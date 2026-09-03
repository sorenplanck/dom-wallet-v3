import QRCode from "qrcode";
import QrScanner from "qr-scanner";
import { listen } from "@tauri-apps/api/event";
import { nativeBridge } from "./bridge.js";
import {
  chainSourcePresentation,
  chainSourceTlsWarning,
  formatDomFromNoms,
  liveStatusProjection,
  miningPresentation,
  nodeStatusText,
  remoteTipAlertPresentation,
  restoreReadinessPresentation,
  restoreScanPresentation,
  synchronizationPresentation,
} from "./status.js";

// Prefilled suggestion for the remote chain source URL. Deployment builds may
// replace this constant; the authoritative value always comes from
// chain_source_get once the user saved a configuration.
const DEFAULT_REMOTE_NODE_URL = "https://rpc.dom-mainnet.example";

const invoke = async (command, args = {}) => {
  const bridge = await nativeBridge.initialize();
  if (!Array.isArray(bridge.command_names) || !bridge.command_names.includes(command)) {
    throw new Error("Unsupported desktop command.");
  }
  return nativeBridge.invoke(command, args);
};
const byId = (id) => document.getElementById(id);
const status = byId("status");
const toast = byId("toast");
let pending = false;
let toastTimer;
let refreshTimer;
let scanner;
let qrFrames = [];
let qrIndex = 0;
let qrAnimationTimer;
let phrasePending = false;
let latestSynchronizationPresentation;
let latestEmbeddedNodeStatus;
let restoreScanTimer;
let remoteTipAlertMessage;
const seenAutomaticCancellations = new Set();

export const clearPasswords = (form) => form?.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; });
export const redactedError = (error) => error?.message && !/password|mnemonic|seed|secret|key|token|credential|:\/\//i.test(error.message)
  ? error.message
  : error?.code ? `Operation rejected (${error.code}).` : "Operation rejected by the native wallet boundary.";
const show = (message, failed = false) => {
  status.textContent = message;
  toast.textContent = message;
  toast.classList.toggle("err", failed);
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 5000);
};
const run = async (action) => {
  if (pending) return undefined;
  pending = true;
  const buttons = [...document.querySelectorAll("button")];
  const disabledState = buttons.map((button) => button.disabled);
  buttons.forEach((button) => { button.disabled = true; });
  try { return await action(); } finally {
    pending = false;
    buttons.forEach((button, index) => { button.disabled = disabledState[index]; });
  }
};
const redactJson = (target, value) => { target.textContent = JSON.stringify(value, null, 2); };
const integerNoms = (value, optional = false) => {
  if (optional && value === "") return null;
  if (!/^[0-9]+$/.test(String(value))) throw new Error("Use an integer number of noms.");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error("Amount exceeds the safe desktop boundary.");
  return parsed;
};
const clearSecretForms = () => {
  document.querySelectorAll('textarea[name="mnemonic"], #transaction-text, #receive-transaction-text').forEach((node) => { node.value = ""; });
  document.querySelectorAll("form").forEach(clearPasswords);
  byId("recovery-phrase").textContent = "";
  byId("recovery-confirmed").checked = false;
  phrasePending = false;
};

export function selectScreen(name) {
  clearSecretForms();
  document.querySelectorAll("#app .screen").forEach((screen) => { screen.hidden = screen.id !== name; });
  document.querySelectorAll(".nav [data-screen]").forEach((button) => button.classList.toggle("active", button.dataset.screen === name));
}
document.querySelectorAll("[data-screen]").forEach((button) => button.addEventListener("click", () => {
  selectScreen(button.dataset.screen);
  if (button.dataset.screen === "mining") refreshMining().catch((error) => show(redactedError(error), true));
  if (button.dataset.screen === "swap") refreshSwap().catch((error) => show(redactedError(error), true));
  if (button.dataset.screen === "node") refreshNode().catch((error) => show(redactedError(error), true));
  if (button.dataset.screen === "history") run(renderHistory).catch((error) => show(redactedError(error), true));
  if (button.dataset.screen === "dashboard" || button.dataset.screen === "diagnostics") refreshSummary().catch((error) => show(redactedError(error), true));
  if (button.dataset.screen === "diagnostics") refreshUpdates().catch((error) => show(redactedError(error), true));
}));
document.querySelectorAll("[data-gate-panel]").forEach((button) => button.addEventListener("click", () => {
  clearSecretForms();
  const panel = button.dataset.gatePanel;
  document.querySelectorAll(".gate-panel").forEach((node) => { node.hidden = node.id !== panel; });
  if (panel === "restore-form") {
    refreshOnboardingNode().catch((error) => show(redactedError(error), true));
    invoke("wallet_restore_staging_list").then((names) => {
      byId("restore-staging-note").textContent = names.length
        ? `Interrupted restores available: ${names.join(", ")}. Submit matching details to resume, or authenticate and abort.`
        : "No interrupted restore staging was discovered.";
    }).catch((error) => show(redactedError(error), true));
  }
  if (panel === "open-form") refreshWalletList().catch((error) => show(redactedError(error), true));
  if (panel === "chain-source-form") refreshChainSource().catch((error) => show(redactedError(error), true));
}));
const refreshWalletList = async () => {
  const names = await invoke("wallet_list");
  const select = byId("open-wallet-select");
  select.replaceChildren(...names.map((name) => {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    return option;
  }));
  byId("open-wallet-empty").hidden = names.length > 0;
  return names;
};
const enterApp = () => { byId("gate").classList.add("hidden"); byId("app").classList.remove("hidden"); selectScreen("dashboard"); };
const enterGate = () => { byId("app").classList.add("hidden"); byId("gate").classList.remove("hidden"); clearSecretForms(); };

const renderOnboardingNode = (node) => {
  const presentation = restoreReadinessPresentation(node);
  byId("onboarding-node-badge").textContent = presentation.badge;
  byId("onboarding-node-message").textContent = presentation.message;
  byId("onboarding-node-progress").value = presentation.progress;
  byId("onboarding-node-local").textContent = presentation.localHeight;
  byId("onboarding-node-peer").textContent = presentation.peerHeight ?? "—";
  byId("onboarding-node-peers").textContent = presentation.connectedPeers;
  byId("restore-submit").disabled = !presentation.submitEnabled;
  byId("restore-readiness-note").textContent = presentation.badge === "READY"
    ? "The Mainnet node is synchronized. Restore scans the canonical chain immediately."
    : "Restore is always available. The wallet scans the chain in the background while the node synchronizes.";
  return presentation;
};
const refreshOnboardingNode = async () => {
  const node = await invoke("embedded_node_status");
  latestEmbeddedNodeStatus = node;
  renderOnboardingNode(node);
  return node;
};

const renderRemoteTipAlert = (presentation) => {
  if (presentation.active) remoteTipAlertMessage = presentation.message;
  for (const id of ["remote-tip-alert", "gate-remote-tip-alert"]) {
    const node = byId(id);
    node.hidden = remoteTipAlertMessage == null;
    node.textContent = remoteTipAlertMessage ?? "";
  }
};

const stopRestoreScanPolling = () => { clearTimeout(restoreScanTimer); restoreScanTimer = undefined; };
const pollRestoreScan = async () => {
  restoreScanTimer = undefined;
  try {
    const synchronization = await invoke("wallet_sync_status");
    renderRemoteTipAlert(remoteTipAlertPresentation(synchronization));
    const scan = restoreScanPresentation(synchronization);
    if (!scan.active) {
      byId("restore-progress-message").textContent = "Restore scan completed. Unlock the wallet to continue.";
      byId("restore-progress-bar").value = 100;
      show("Restore scan completed. Unlock the wallet to continue.");
      return;
    }
    byId("restore-progress-message").textContent = scan.message;
    byId("restore-progress-bar").value = scan.progress;
    byId("restore-progress-balance").textContent = scan.partialBalanceText;
  } catch {
    // Transient status failures never stop the background scan presentation.
  }
  restoreScanTimer = setTimeout(pollRestoreScan, 2000);
};
const beginRestoreScanPolling = () => {
  stopRestoreScanPolling();
  document.querySelectorAll(".gate-panel").forEach((node) => { node.hidden = node.id !== "restore-progress"; });
  byId("restore-progress-message").textContent = "Restored — preparing the chain scan…";
  byId("restore-progress-bar").value = 0;
  byId("restore-progress-balance").textContent = "Partial balance: unavailable";
  pollRestoreScan();
};

const updateChainSourceTlsWarning = () => {
  const form = byId("chain-source-form");
  const remote = new FormData(form).get("source") === "REMOTE";
  byId("chain-source-remote-fields").hidden = !remote;
  byId("chain-source-tls-warning").hidden = !(remote && chainSourceTlsWarning(byId("chain-source-url").value));
};
const renderChainSource = (value) => {
  const presentation = chainSourcePresentation(value);
  const form = byId("chain-source-form");
  for (const radio of form.querySelectorAll('input[name="source"]')) {
    radio.checked = radio.value === presentation.source;
  }
  const url = byId("chain-source-url");
  if (url.value.trim() === "") url.value = presentation.baseUrl ?? DEFAULT_REMOTE_NODE_URL;
  byId("chain-source-token-note").hidden = !presentation.hasBearerToken;
  byId("chain-source-current").textContent = presentation.message;
  byId("settings-chain-source").textContent = presentation.message;
  byId("settings-chain-source-warning").hidden = !presentation.tlsWarning;
  updateChainSourceTlsWarning();
  return presentation;
};
const refreshChainSource = async () => renderChainSource(await invoke("chain_source_get"));
byId("chain-source-form").addEventListener("change", updateChainSourceTlsWarning);
byId("chain-source-url").addEventListener("input", updateChainSourceTlsWarning);
byId("chain-source-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  const source = data.get("source") === "REMOTE" ? "REMOTE" : "EMBEDDED";
  const baseUrl = String(data.get("base_url") ?? "").trim();
  const bearerToken = String(data.get("bearer_token") ?? "");
  try {
    if (source === "REMOTE" && baseUrl === "") throw new Error("Enter the remote node URL first.");
    const result = await run(() => invoke("chain_source_set", {
      source,
      base_url: source === "REMOTE" ? baseUrl : null,
      bearer_token: source === "REMOTE" && bearerToken !== "" ? bearerToken : null,
    }));
    clearPasswords(form);
    const presentation = renderChainSource(result);
    show(presentation.source === "REMOTE"
      ? "Chain source saved: remote node (fast)."
      : "Chain source saved: local full node.");
  } catch (error) { clearPasswords(form); show(redactedError(error), true); }
});

const clearPhrase = () => {
  byId("recovery-phrase").textContent = "";
  byId("recovery-confirmed").checked = false;
  byId("recovery-complete").disabled = true;
  byId("recovery-ceremony").hidden = true;
  clearPasswords(byId("recovery-ceremony"));
  phrasePending = false;
};
const beginPhrase = (mnemonic) => {
  document.querySelectorAll(".gate-panel").forEach((node) => { node.hidden = node.id !== "recovery-ceremony"; });
  byId("recovery-phrase").textContent = mnemonic;
  phrasePending = true;
};
byId("recovery-confirmed").addEventListener("change", (event) => { byId("recovery-complete").disabled = !event.target.checked; });
byId("recovery-complete").addEventListener("click", async () => {
  if (!phrasePending || !byId("recovery-confirmed").checked) return;
  const password = byId("recovery-confirm-password").value;
  try { await run(() => invoke("wallet_recovery_phrase_confirm", { password })); clearPhrase(); show("Recovery phrase confirmed. Unlock wallet to continue."); }
  catch (error) { clearPasswords(byId("recovery-ceremony")); show(redactedError(error), true); }
});
byId("recovery-abandon").addEventListener("click", () => { clearPhrase(); show("Recovery ceremony closed."); });

byId("create-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try {
    const created = await run(() => invoke("wallet_create_recoverable", { name: data.get("name"), password: data.get("password") }));
    clearPasswords(form); beginPhrase(created.mnemonic); created.mnemonic = ""; show("Write down and confirm the recovery phrase.");
  } catch (error) { clearPasswords(form); show(redactedError(error), true); }
});
byId("restore-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try {
    show("Restoring the wallet from the recovery phrase…");
    const result = await run(() => invoke("wallet_restore_from_mnemonic", { name: data.get("name"), password: data.get("password"), mnemonic: data.get("mnemonic") }));
    form.querySelector('textarea[name="mnemonic"]').value = ""; clearPasswords(form);
    if (result?.scanning === true) {
      beginRestoreScanPolling();
      show("Wallet restored. The chain scan continues in the background.");
    } else {
      show("Wallet restored.");
    }
  } catch (error) { form.querySelector('textarea[name="mnemonic"]').value = ""; clearPasswords(form); show(redactedError(error), true); }
});
byId("restore-abort").addEventListener("click", async () => {
  const form = byId("restore-form");
  const data = new FormData(form);
  if (!window.confirm("Authenticate and remove this interrupted restore stage?")) return;
  try {
    await run(() => invoke("wallet_restore_abort", {
      name: data.get("name"),
      password: data.get("password"),
    }));
    form.querySelector('textarea[name="mnemonic"]').value = "";
    clearPasswords(form);
    byId("restore-staging-note").textContent = "Interrupted restore staging removed.";
    show("Interrupted restore aborted.");
  } catch (error) {
    clearPasswords(form);
    show(redactedError(error), true);
  }
});
byId("onboarding-node-retry").addEventListener("click", () => {
  run(() => invoke("embedded_node_start"))
    .then(() => refreshOnboardingNode())
    .catch((error) => show(redactedError(error), true));
});
byId("open-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { await run(() => invoke("wallet_open_named", { name: new FormData(form).get("name") })); show("Mainnet wallet opened in locked state."); }
  catch (error) { show(redactedError(error), true); }
});
byId("wallet-recover-from-disk").addEventListener("click", async () => {
  const name = byId("open-wallet-select").value;
  try {
    await run(() => invoke("wallet_recover_from_disk", { name }));
    show("Wallet service reconstructed from the managed on-disk wallet.");
  } catch (error) {
    show(redactedError(error), true);
  }
});
byId("gate-close-wallet").addEventListener("click", () => run(async () => {
  clearPhrase();
  await invoke("wallet_close");
  await refreshWalletList();
  show("Wallet closed. Choose another managed wallet.");
}).catch((error) => show(redactedError(error), true)));
byId("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  const password = new FormData(form).get("password");
  try {
    await run(() => invoke("wallet_unlock", { password }));
    try {
      const ceremony = await invoke("wallet_recovery_phrase_resume", { password });
      await invoke("wallet_lock");
      clearPasswords(form);
      enterGate();
      beginPhrase(ceremony.mnemonic);
      ceremony.mnemonic = "";
      show("Recovery phrase confirmation is still required.");
      return;
    } catch (error) {
      if (error?.code !== "RECOVERY_PHRASE_ALREADY_CONFIRMED") {
        await invoke("wallet_lock").catch(() => {});
        throw error;
      }
    }
    clearPasswords(form);
    enterApp();
    await refreshSummary();
    show("Wallet unlocked.");
    try {
      const open = await invoke("swap_sessions_open");
      await renderSwapSessions(open);
      if (open.sessions.length) {
        const clock = open.sessions[open.sessions.length - 1]?.refund_unlock_unix;
        show(`${open.sessions.length} swap${open.sessions.length === 1 ? "" : "s"} in progress — resumed from durable state.${clock != null ? ` Your refund unlocks at ${swapUnlockClock(clock)}.` : ""}`);
      }
    } catch { /* the swap surface may be unavailable while the node warms up */ }
  } catch (error) { clearPasswords(form); show(redactedError(error), true); }
});

const refreshSummary = async () => {
  const [summaryResult, nodeResult, networkResult, peersResult, synchronizationResult] = await Promise.allSettled([
    invoke("wallet_summary"), invoke("embedded_node_status"), invoke("node_network_status"),
    invoke("node_peer_status"), invoke("wallet_sync_status")
  ]);
  if (summaryResult.status !== "fulfilled") throw summaryResult.reason;
  const summary = summaryResult.value;
  if (nodeResult.status === "fulfilled") latestEmbeddedNodeStatus = nodeResult.value;
  const node = nodeResult.status === "fulfilled"
    ? nodeResult.value
    : latestEmbeddedNodeStatus
      ? {
          ...latestEmbeddedNodeStatus,
          lifecycle: "STALE",
          ready: false,
          status_message: "Node status is stale; retry the embedded node.",
          error_code: "NODE_STATUS_STALE",
        }
      : undefined;
  const network = networkResult.status === "fulfilled" ? networkResult.value : undefined;
  const peers = peersResult.status === "fulfilled" ? peersResult.value : undefined;
  const synchronization = synchronizationResult.status === "fulfilled"
    ? synchronizationResult.value
    : undefined;
  const liveStatus = liveStatusProjection(summary, node, network, peers, synchronization);
  if (liveStatus.synchronizationState) {
    latestSynchronizationPresentation = liveStatus.synchronizationState;
  } else if (liveStatus.canonicalHeight == null) {
    latestSynchronizationPresentation = undefined;
  }
  const balanceLabels = {
    confirmed: "Confirmed",
    immature: "Immature",
    pending_incoming: "Pending incoming",
    pending_outgoing: "Pending outgoing",
    locked: "Locked",
    spendable: "Spendable",
  };
  byId("balance-total").firstChild.textContent = `${formatDomFromNoms(summary.balance.total ?? 0).replace(/ DOM$/, "")} `;
  byId("balance-cards").replaceChildren(...Object.entries(balanceLabels).map(([key, label]) => {
    const value = summary.balance[key];
    const card = document.createElement("div");
    card.className = "card";
    card.textContent = Number.isSafeInteger(value) && value >= 0
      ? `${label}: ${value} noms · ${formatDomFromNoms(value)}`
      : `${label}: unavailable`;
    return card;
  }));
  byId("network-identity").textContent = `${summary.network} · ${liveStatus.badgeState}`;
  byId("connection-status").textContent = liveStatus.connectedPeers == null
    ? "Peer status unavailable"
    : liveStatus.connectedPeers > 0
      ? `Connected to ${liveStatus.connectedPeers} peer${liveStatus.connectedPeers === 1 ? "" : "s"}`
      : "No peers found";
  byId("canonical-height").textContent = liveStatus.canonicalHeight ?? "—";
  byId("cursor-height").textContent = liveStatus.cursorHeight ?? "Not initialized";
  byId("sync-status").textContent = liveStatus.message;
  const restoreScan = restoreScanPresentation(synchronization);
  if (restoreScan.active) byId("sync-status").textContent = restoreScan.message;
  renderRemoteTipAlert(remoteTipAlertPresentation(synchronization));
  byId("settings-chain-id").textContent = liveStatus.chainId ?? "—";
  byId("settings-genesis").textContent = liveStatus.genesisHash ?? "—";
  if (liveStatus.dataDirectory) byId("settings-node-data").textContent = liveStatus.dataDirectory;
  byId("settings-peer-count").textContent = liveStatus.connectedPeers ?? "—";
  byId("settings-bootstrap").textContent = liveStatus.bootstrapPhase ?? "UNAVAILABLE";
  byId("settings-heights").textContent = `${liveStatus.cursorHeight ?? "—"} / ${liveStatus.canonicalHeight ?? "—"}`;
};
const refreshNode = async () => {
  const value = await invoke("embedded_node_status");
  latestEmbeddedNodeStatus = value;
  byId("node-status").textContent = nodeStatusText(value);
  return value;
};
const refreshUpdates = async () => {
  const [build, updates] = await Promise.all([invoke("get_build_info"), invoke("update_status")]);
  byId("update-wallet-version").textContent = build.wallet_version;
  byId("update-wallet-revision").textContent = build.wallet_revision;
  byId("update-wallet-state").textContent = updates.wallet.state;
  byId("update-wallet-available").textContent = updates.wallet.available_version ?? "None";
  byId("update-wallet-last-check").textContent = updates.wallet.last_check_unix_seconds
    ? new Date(updates.wallet.last_check_unix_seconds * 1000).toLocaleString()
    : "Never";
  byId("update-channel").textContent = updates.channel;
  byId("automatic-updates").checked = updates.automatic_updates;
  byId("update-mode").textContent = updates.automatic_updates && updates.signature_key_configured
    ? "Enabled · Stable"
    : updates.automatic_updates
      ? "Scheduled · signing unavailable"
      : "Unavailable · fail closed";
  byId("update-signing-state").textContent = updates.signature_key_configured ? "Configured" : "Unavailable — updates fail closed";
  const error = updates.wallet.sanitized_error;
  byId("update-error").textContent = error ?? "No updater error.";
};
const formatHashrate = (value) => {
  if (value == null) return "—";
  const hashrate = Number(value);
  if (!Number.isFinite(hashrate) || hashrate < 0) return "—";
  const [divisor, unit] = hashrate >= 1_000_000
    ? [1_000_000, "MH/s"]
    : hashrate >= 1_000
      ? [1_000, "kH/s"]
      : [1, "H/s"];
  return `${(hashrate / divisor).toLocaleString("en-US", { maximumFractionDigits: 2 })} ${unit}`;
};
const renderMining = (value, node) => {
  const presentation = miningPresentation(value, node);
  byId("mining-status").textContent = presentation.status;
  byId("mining-enabled").checked = value.enabled;
  byId("mining-threads").value = value.cpu_threads;
  byId("mining-threads").disabled = !value.enabled || value.running;
  byId("mining-address").value = value.mining_address;
  byId("mining-hashrate").textContent = formatHashrate(value.hashrate_hps);
  byId("mining-network-hashrate").textContent = formatHashrate(value.network_hashrate_hps);
  byId("mining-height").textContent = value.current_height;
  byId("mining-peers").textContent = value.connected_peers;
  byId("mining-accepted").textContent = value.accepted_blocks;
  byId("mining-rejected").textContent = value.rejected_work;
  byId("mining-template-refreshes").textContent = value.template_refreshes;
  byId("mining-candidate").textContent = value.last_block_candidate_time ? new Date(value.last_block_candidate_time * 1000).toLocaleString() : "Never";
  byId("mining-last-height").textContent = value.last_accepted_block_height ?? "—";
  byId("mining-uptime").textContent = `${value.uptime_seconds}s`;
  const estimatedCost = Number(value.estimated_production_cost_usd_per_dom);
  const estimatedLow = Number(value.estimated_production_cost_low_usd_per_dom);
  const estimatedHigh = Number(value.estimated_production_cost_high_usd_per_dom);
  const hasEstimatedRange = [estimatedCost, estimatedLow, estimatedHigh]
    .every((entry) => Number.isFinite(entry) && entry > 0);
  byId("mining-estimated-value").textContent = hasEstimatedRange
    ? `~US$ ${estimatedCost.toPrecision(3)} / DOM (range US$ ${estimatedLow.toPrecision(3)}–${estimatedHigh.toPrecision(3)})`
    : "—";
  byId("mining-warning").hidden = presentation.warning == null;
  byId("mining-warning").textContent = presentation.warning ?? "";
  byId("mining-start").disabled = !presentation.canStart;
  // The worker is also alive while it waits out a synchronization dip, so Stop
  // must stay available — otherwise mining could only be stopped in the exact
  // moments it happened to be hashing.
  byId("mining-stop").disabled = !value.running
    && value.status !== "ERROR"
    && value.status !== "WAITING_FOR_SYNCHRONIZATION";
};
const renderMiningUnavailable = (node) => {
  byId("mining-status").textContent = node?.lifecycle === "SYNCHRONIZING"
    ? "SYNCHRONIZING"
    : "NODE NOT READY";
  byId("mining-enabled").checked = false;
  byId("mining-enabled").disabled = true;
  byId("mining-threads").value = "";
  byId("mining-threads").disabled = true;
  byId("mining-address").value = "";
  for (const id of [
    "mining-hashrate", "mining-network-hashrate", "mining-height", "mining-peers", "mining-accepted",
    "mining-rejected", "mining-template-refreshes", "mining-candidate",
    "mining-last-height", "mining-uptime", "mining-estimated-value",
  ]) byId(id).textContent = "—";
  byId("mining-warning").hidden = false;
  byId("mining-warning").textContent = node?.status_message ?? "The embedded node is unavailable.";
  byId("mining-start").disabled = true;
  byId("mining-stop").disabled = true;
};
// ── Swap tab ────────────────────────────────────────────────────────────────
// The flow commands fail closed until the interop daemon channel lands; this
// UI surfaces that honestly instead of fabricating quotes or sessions.
const SWAP_DAEMON_MESSAGE = "The interop daemon is not connected";
const swapDaemonBanner = () => byId("swap-daemon-banner");
const markSwapDaemon = (offline) => { swapDaemonBanner().hidden = !offline; };
const swapFeeSummary = () => byId("swap-fee-summary");
const renderSwapFee = (quote) => {
  const legs = quote.external_legs === 0 ? "DOM only" : quote.external_legs === 1 ? "one external leg" : "two external legs";
  const payment = swapAssetByCode(quote.payment_asset);
  const paymentLabel = payment?.label ?? quote.payment_asset;
  if (quote.fee_noms == null) {
    swapFeeSummary().textContent = `Protocol fee ${quote.fee_percent}% (${legs}): ${quote.fee_message} Fee payment currency: ${paymentLabel}.`;
    return;
  }
  const dom = (quote.fee_noms / 100000000).toLocaleString("en-US", { maximumFractionDigits: 8 });
  const usd = quote.fee_usd_estimated != null
    ? ` (~US$ ${Number(quote.fee_usd_estimated).toPrecision(3)}, ${quote.depc_basket_version} estimate)`
    : "";
  let paid;
  if (payment?.ticker === "DOM") {
    paid = `paid in DOM`;
  } else if (payment?.ticker === "USDT") {
    paid = quote.fee_payment_estimated != null
      ? `payable as ~${Number(quote.fee_payment_estimated).toPrecision(3)} ${paymentLabel} at the ${quote.depc_basket_version} production-cost reference`
      : `payable in ${paymentLabel} once the node can supply the production-cost reference`;
  } else {
    paid = `payable in ${paymentLabel}, fixed at the rate implied by the quote you accept`;
  }
  swapFeeSummary().textContent = `Protocol fee ${quote.fee_percent}% (${legs}): ${quote.fee_noms} noms (${dom} DOM), ${paid}${usd}.`;
};
// The pickers are built from the curated registry, never from hard-coded
// tickers: a bare "USDT" hides which network settles it, and that is how
// funds reach a chain nobody can spend them from.
let swapAssets = [];
const swapAssetByCode = (code) => swapAssets.find((asset) => asset.code === code);
const swapBaseUnitDisplayName = (asset) => ({
  nom: "noms",
  satoshi: "satoshis",
  lamport: "lamports",
  "micro-USDT": "micro-USDT",
  piconero: "piconero",
})[asset?.base_unit_name] ?? "base units";
const renderSwapUnitPlaceholders = () => {
  const from = swapAssetByCode(byId("swap-from").value);
  const to = swapAssetByCode(byId("swap-to").value);
  byId("swap-amount").placeholder = `Amount in ${swapBaseUnitDisplayName(from)}`;
  byId("swap-minimum-output").placeholder = `Minimum received in ${swapBaseUnitDisplayName(to)}`;
};
const renderSwapReceivingLeg = () => {
  const chosen = swapAssetByCode(byId("swap-to").value);
  const note = byId("swap-receiving-leg");
  if (!chosen) { note.hidden = true; return; }
  note.textContent = chosen.is_dom
    ? "You receive DOM into this wallet."
    : `You receive ${chosen.ticker} on ${chosen.network}, into your ${chosen.receiving_leg} leg address. Paying it to any other network would put it beyond this wallet's reach.`;
  note.hidden = false;
};
const populateSwapAssets = async () => {
  const assets = await invoke("swap_asset_registry");
  if (!Array.isArray(assets) || assets.length === 0) return;
  swapAssets = assets;
  for (const [id, preferred] of [["swap-from", "DOM"], ["swap-to", "USDT.ETH"], ["swap-fee-asset", "DOM"]]) {
    const select = byId(id);
    const previous = select.value;
    select.replaceChildren(...assets.map((asset) => {
      const option = document.createElement("option");
      option.value = asset.code;
      option.textContent = asset.label;
      return option;
    }));
    const wanted = assets.some((asset) => asset.code === previous) ? previous : preferred;
    if (assets.some((asset) => asset.code === wanted)) select.value = wanted;
  }
  renderSwapUnitPlaceholders();
  renderSwapReceivingLeg();
};
byId("swap-from").addEventListener("change", renderSwapUnitPlaceholders);
byId("swap-to").addEventListener("change", () => {
  renderSwapUnitPlaceholders();
  renderSwapReceivingLeg();
});

const previewSwapFee = async () => {
  const data = new FormData(byId("swap-intent-form"));
  const amount = integerNoms(data.get("amount"));
  const quote = await run(() => invoke("swap_fee_quote", { amount, fromAsset: byId("swap-from").value, toAsset: byId("swap-to").value, paymentAsset: byId("swap-fee-asset").value }));
  if (quote) renderSwapFee(quote);
};
// Resume is a read of committed state: every open session survives restart
// because the backend persists each transition before acting on it.
let activeSwapSession = null;
const swapUnlockClock = (unix) => new Date(unix * 1000).toLocaleString();
const renderSwapDeposit = async (session) => {
  const panel = byId("swap-deposit-panel");
  const deposit = session?.deposit;
  panel.hidden = !deposit;
  if (!deposit) return;
  byId("swap-deposit-address").textContent = deposit.address;
  byId("swap-deposit-bounds").textContent = `min ${deposit.minimum_base_units} — max ${deposit.maximum_base_units} (base units)`;
  byId("swap-deposit-confirmations").textContent = `${deposit.observed_confirmations} / ${deposit.required_confirmations}`;
  byId("swap-deposit-warning").hidden = !deposit.insufficient_after_fees;
  await QRCode.toCanvas(byId("swap-deposit-qr"), deposit.address, { errorCorrectionLevel: "M", margin: 2, width: 220 });
};
const renderSwapSessions = async (dto) => {
  markSwapDaemon(!dto.daemon_connected);
  const sessions = dto.sessions ?? [];
  activeSwapSession = sessions.length ? sessions[sessions.length - 1] : null;
  const banner = byId("swap-resume-banner");
  if (sessions.length) {
    banner.textContent = `${sessions.length} swap${sessions.length === 1 ? "" : "s"} in progress — resumed from durable state.`;
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
  const clock = byId("swap-refund-clock");
  if (activeSwapSession?.refund_unlock_unix != null) {
    clock.textContent = `If anything fails, your refund unlocks at ${swapUnlockClock(activeSwapSession.refund_unlock_unix)}.`;
    clock.hidden = false;
  } else {
    clock.hidden = true;
  }
  const status = byId("swap-session-status");
  if (activeSwapSession) {
    const s = activeSwapSession;
    status.textContent = `${s.from_asset} → ${s.to_asset} · ${s.amount_base_units} base units · state ${s.state}` + (s.last_error ? ` · ${s.last_error}` : "");
  } else {
    status.textContent = "No active swap session.";
  }
  byId("swap-session-cancel").disabled = !activeSwapSession;
  byId("swap-manual-refund").disabled = !activeSwapSession;
  byId("swap-session-details").disabled = !activeSwapSession;
  await renderSwapDeposit(activeSwapSession);
};
const refreshSwap = async () => {
  try {
    await populateSwapAssets();
  } catch { /* the pickers keep whatever the registry last supplied */ }
  try {
    await renderSwapSessions(await invoke("swap_sessions_open"));
  } catch {
    markSwapDaemon(true);
  }
};
byId("swap-fee-preview").addEventListener("click", () => previewSwapFee().catch((error) => {
  swapFeeSummary().textContent = "The fee could not be computed.";
  show(redactedError(error), true);
}));
byId("swap-addresses-refresh").addEventListener("click", async () => {
  try {
    const value = await run(() => invoke("swap_leg_addresses"));
    if (!value) return;
    byId("swap-btc-address").textContent = value.bitcoin_address;
    byId("swap-evm-address").textContent = value.evm_address;
    byId("swap-sol-address").textContent = value.solana_address;
    byId("swap-xmr-address").textContent = value.monero_address;
    // The index is part of the answer: these are the addresses the NEXT
    // session will watch, and a later session will show different ones.
    byId("swap-legs-index").textContent =
      `Derivation index ${value.index}. Each swap takes a fresh index on Bitcoin, EVM and Solana so repeated swaps do not share one address; Monero stays on account 0 because its stealth addresses already do this.`;
    byId("swap-legs-index").hidden = false;
  } catch (error) { show(redactedError(error), true); }
});
byId("swap-intent-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  try {
    await previewSwapFee();
    const result = await run(() => invoke("swap_intent_create", {
      amount: integerNoms(data.get("amount")),
      fromAsset: byId("swap-from").value,
      toAsset: byId("swap-to").value,
      minimumOutput: integerNoms(data.get("minimum_output")),
      feeAsset: byId("swap-fee-asset").value,
    }));
    if (!result) return;
    if (result.published) {
      show("Swap intent published.");
    } else {
      markSwapDaemon(true);
      show(result.message ?? `${SWAP_DAEMON_MESSAGE}; the intent was not published.`, true);
    }
    await refreshSwap();
  } catch (error) {
    markSwapDaemon(true);
    show(`${SWAP_DAEMON_MESSAGE}; the intent was not published. Your draft was saved and can be cancelled for free.`, true);
    await refreshSwap().catch(() => {});
  }
});
byId("swap-session-cancel").addEventListener("click", async () => {
  if (!activeSwapSession) return;
  if (!window.confirm("Cancel this swap session? While nothing is locked, cancellation is free.")) return;
  try { await run(() => invoke("swap_session_cancel", { sessionId: activeSwapSession.id })); show("Swap session cancelled."); await refreshSwap(); }
  catch (error) { show(redactedError(error), true); }
});
byId("swap-manual-refund").addEventListener("click", async () => {
  if (!activeSwapSession) return;
  try { await run(() => invoke("swap_manual_refund", { sessionId: activeSwapSession.id })); show("Refund broadcast requested."); }
  catch (error) { show(redactedError(error), true); }
});
byId("swap-session-details").addEventListener("click", async () => {
  if (!activeSwapSession) return;
  try {
    const detail = await run(() => invoke("swap_session_detail", { sessionId: activeSwapSession.id }));
    if (!detail) return;
    const panel = byId("swap-session-detail");
    redactJson(panel, detail);
    panel.hidden = !panel.hidden;
  } catch (error) { show(redactedError(error), true); }
});
// Display-once recovery hatch: rendered on explicit demand, cleared on hide,
// never logged, never persisted by the frontend.
byId("swap-export-keys").addEventListener("click", async () => {
  if (!window.confirm("Export the private keys of your Bitcoin, EVM, Solana and Monero swap legs? Anyone who sees them can take the funds on those chains. They will be shown once, on screen only.")) return;
  try {
    const keys = await run(() => invoke("swap_leg_keys_export", { acknowledged: true }));
    if (!keys) return;
    const output = byId("swap-export-output");
    // Every index the wallet ever allocated, not just the live one: funds
    // stranded on an earlier index have to remain reachable.
    const rows = [["Warning", keys.warning]];
    for (const set of keys.indices) {
      rows.push([`Bitcoin ${set.bitcoin_derivation_path}`, set.bitcoin_address]);
      rows.push([`Bitcoin secret (hex) · index ${set.index}`, set.bitcoin_secret_hex]);
      rows.push([`EVM ${set.evm_derivation_path}`, set.evm_address]);
      rows.push([`EVM secret (hex) · index ${set.index}`, set.evm_secret_hex]);
      rows.push([`Solana ${set.solana_derivation_path}`, set.solana_address]);
      rows.push([`Solana secret (hex) · index ${set.index}`, set.solana_secret_hex]);
    }
    rows.push([`Monero ${keys.monero_derivation_path}`, keys.monero_address]);
    rows.push(["Monero spend secret (hex)", keys.monero_spend_secret_hex]);
    rows.push(["Monero view secret (hex)", keys.monero_view_secret_hex]);
    output.replaceChildren(...rows.map(([label, value]) => {
      const row = document.createElement("div");
      const name = document.createElement("span"); name.textContent = label;
      const code = document.createElement("code"); code.textContent = value;
      row.append(name, code); return row;
    }));
    output.hidden = false;
    byId("swap-export-clear").hidden = false;
  } catch (error) { show(redactedError(error), true); }
});
// The seed-only recovery path: public addresses to check on each chain
// when the wallet file is gone. No secret is involved, so it needs no
// acknowledgment ceremony.
byId("swap-scan-plan").addEventListener("click", async () => {
  try {
    const plan = await run(() => invoke("swap_leg_scan_plan"));
    if (!plan) return;
    const output = byId("swap-scan-output");
    const rows = [[
      "How to use this",
      `${plan.note} Scanned through index ${plan.scan_through_index} (gap limit ${plan.gap_limit}).`,
    ]];
    for (const entry of plan.entries) {
      const mark = entry.recorded ? "used" : "gap margin";
      rows.push([`Index ${entry.index} · ${mark} · Bitcoin`, entry.bitcoin_address]);
      rows.push([`Index ${entry.index} · ${mark} · EVM`, entry.evm_address]);
      rows.push([`Index ${entry.index} · ${mark} · Solana`, entry.solana_address]);
    }
    rows.push(["Monero (account 0)", plan.monero_address]);
    output.replaceChildren(...rows.map(([label, value]) => {
      const row = document.createElement("div");
      const name = document.createElement("span"); name.textContent = label;
      const code = document.createElement("code"); code.textContent = value;
      row.append(name, code); return row;
    }));
    output.hidden = false;
  } catch (error) { show(redactedError(error), true); }
});
byId("swap-export-clear").addEventListener("click", () => {
  const output = byId("swap-export-output");
  output.replaceChildren();
  output.hidden = true;
  byId("swap-export-clear").hidden = true;
  const scan = byId("swap-scan-output");
  scan.replaceChildren();
  scan.hidden = true;
});
byId("swap-identity-show").addEventListener("click", async () => {
  try {
    const identity = await run(() => invoke("swap_initiator_identity"));
    if (!identity) return;
    const output = byId("swap-identity-output");
    output.replaceChildren(...[
      ["Initiator public key", identity.public_key_hex],
      ["Derivation domain", identity.derivation_domain],
      ["Roster role", identity.role],
    ].map(([label, value]) => {
      const row = document.createElement("div");
      const name = document.createElement("span"); name.textContent = label;
      const code = document.createElement("code"); code.textContent = value;
      row.append(name, code); return row;
    }));
    output.hidden = false;
  } catch (error) { show(redactedError(error), true); }
});
byId("swap-descriptor-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const verdict = byId("swap-descriptor-verdict");
  try {
    const status = await run(() => invoke("swap_network_descriptor_check", {
      descriptorJson: byId("swap-descriptor-json").value,
    }));
    if (!status) return;
    verdict.textContent = status.valid
      ? `${status.message} Solvers: ${status.solvers}. Assets: ${status.assets.join(", ")}.`
      : status.message;
    verdict.hidden = false;
  } catch (error) {
    verdict.textContent = "The descriptor could not be checked.";
    verdict.hidden = false;
    show(redactedError(error), true);
  }
});
byId("swap-quotes-refresh").addEventListener("click", async () => {
  try { await run(() => invoke("swap_quotes_list")); }
  catch { markSwapDaemon(true); byId("swap-quotes-list").textContent = `${SWAP_DAEMON_MESSAGE}; no quotes were fetched.`; }
});
byId("swap-history-refresh").addEventListener("click", async () => {
  try {
    const history = await run(() => invoke("swap_history"));
    if (!history) return;
    const list = byId("swap-history-list");
    if (!history.length) { list.textContent = "No swaps recorded."; return; }
    list.replaceChildren(...history.map((session) => {
      const row = document.createElement("article");
      row.className = "history-item";
      row.textContent = `${session.from_asset} → ${session.to_asset} · ${session.amount_base_units} base units · ${session.state}`;
      return row;
    }));
  } catch (error) { byId("swap-history-list").textContent = "History is unavailable."; show(redactedError(error), true); }
});

const refreshMining = async () => {
  const [nodeResult, miningResult] = await Promise.allSettled([
    invoke("embedded_node_status"),
    invoke("mining_status"),
  ]);
  let node = nodeResult.status === "fulfilled" ? nodeResult.value : undefined;
  const mining = miningResult.status === "fulfilled" ? miningResult.value : undefined;
  if (latestSynchronizationPresentation?.badgeState === "SYNCHRONIZING") {
    node = {
      ...node,
      lifecycle: "SYNCHRONIZING",
      ready: false,
      status_message: latestSynchronizationPresentation.message,
    };
  }
  if (!mining) {
    renderMiningUnavailable(node);
    return;
  }
  byId("mining-enabled").disabled = false;
  renderMining(mining, node);
};
byId("mining-enabled").addEventListener("change", async (event) => {
  try {
    const config = await invoke("mining_config_get");
    const threads = Number(byId("mining-threads").value) || config.recommended_cpu_threads;
    await run(() => invoke("mining_config_set", { enabled: event.target.checked, cpuThreads: threads }));
    await refreshMining();
  } catch (error) { event.target.checked = false; show(redactedError(error), true); }
});
byId("mining-threads").addEventListener("change", async (event) => {
  try { await run(() => invoke("mining_config_set", { enabled: byId("mining-enabled").checked, cpuThreads: Number(event.target.value) })); await refreshMining(); }
  catch (error) { show(redactedError(error), true); }
});
byId("mining-start").addEventListener("click", async () => {
  const [current, node] = await Promise.all([invoke("mining_status"), invoke("embedded_node_status")]);
  if (!miningPresentation(current, node).canStart) {
    show(node.status_message ?? "The node is not ready for mining.", true);
    return;
  }
  const message = current.current_height === 0
    ? "Starting mining may produce the first post-genesis Mainnet block. Continue?"
    : "Start local CPU mining on DOM Mainnet?";
  if (!window.confirm(message)) return;
  try { renderMining(await run(() => invoke("mining_start", { confirmed: true })), node); }
  catch (error) { show(redactedError(error), true); }
});
byId("mining-stop").addEventListener("click", async () => {
  try {
    const value = await run(() => invoke("mining_stop"));
    renderMining(value, await invoke("embedded_node_status"));
  }
  catch (error) { show(redactedError(error), true); }
});
byId("sync").addEventListener("click", () => run(async () => { await invoke("wallet_sync_start"); await refreshSummary(); }).catch((error) => show(redactedError(error), true)));
byId("node-sync").addEventListener("click", () => run(async () => {
  await invoke("wallet_sync_start");
  await Promise.all([refreshNode(), refreshSummary()]);
}).catch((error) => show(redactedError(error), true)));
byId("node-refresh").addEventListener("click", () => run(refreshNode).catch((error) => show(redactedError(error), true)));
byId("node-start").addEventListener("click", () => run(async () => {
  await invoke("embedded_node_start");
  await Promise.allSettled([refreshNode(), refreshSummary(), refreshMining()]);
  show("Embedded node started.");
}).catch((error) => show(redactedError(error), true)));
byId("node-stop").addEventListener("click", () => run(async () => {
  await invoke("embedded_node_stop");
  await Promise.allSettled([refreshNode(), refreshSummary()]);
  show("Embedded node stopped. The wallet remains open.");
}).catch((error) => show(redactedError(error), true)));
for (const [id, command] of [["pause", "wallet_sync_pause"], ["resume", "wallet_sync_resume"], ["retry", "wallet_sync_retry"]]) {
  byId(id).addEventListener("click", () => run(async () => {
    await invoke(command);
    await refreshSummary();
  }).catch((error) => show(redactedError(error), true)));
}
byId("rescan").addEventListener("click", () => {
  if (window.confirm("Rescan from canonical Mainnet genesis?")) {
    run(async () => {
      await invoke("wallet_rescan");
      await refreshSummary();
    }).catch((error) => show(redactedError(error), true));
  }
});
byId("diagnostics-refresh").addEventListener("click", () => run(async () => { await refreshSummary(); redactJson(byId("diagnostics-output"), await invoke("diagnostics_redacted")); }).catch((error) => show(redactedError(error), true)));
byId("updates-check").addEventListener("click", () => run(async () => {
  const updates = await invoke("check_updates_now");
  await refreshUpdates();
  const error = updates.wallet.sanitized_error;
  show(error ? `Update check failed closed (${error}).` : "Signed Wallet update check completed. Nothing was downloaded or installed.", Boolean(error));
}).catch((error) => show(redactedError(error), true)));
byId("updates-download").addEventListener("click", () => run(async () => {
  const updates = await invoke("download_update_now");
  await refreshUpdates();
  const error = updates.wallet.sanitized_error;
  show(error ? `Update download failed closed (${error}).` : "Signed Wallet update downloaded and verified. Apply remains explicit.", Boolean(error));
}).catch((error) => show(redactedError(error), true)));
byId("updates-apply").addEventListener("click", () => {
  if (!window.confirm("Apply the already downloaded and verified Wallet update, close the wallet, and restart now?")) return;
  run(() => invoke("apply_update_now", { confirmed: true }))
    .catch((error) => show(redactedError(error), true));
});
byId("automatic-updates").addEventListener("change", (event) => run(async () => {
  await invoke("automatic_updates_set", { enabled: event.target.checked });
  await refreshUpdates();
}).catch((error) => show(redactedError(error), true)));
byId("lock").addEventListener("click", () => run(async () => { await stopScanner(); await invoke("wallet_lock"); enterGate(); }).catch((error) => show(redactedError(error), true)));
byId("close").addEventListener("click", () => run(async () => { await stopScanner(); await invoke("wallet_close"); enterGate(); }).catch((error) => show(redactedError(error), true)));

byId("backup-export-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try { const result = await run(() => invoke("wallet_backup_export", { destination: data.get("destination"), backupPassword: data.get("backup_password") })); show(`Encrypted backup created: ${result.destination_name}.`); }
  catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); }
});
byId("backup-import-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  if (!window.confirm("Close the current wallet and import this backup into a new folder?")) {
    clearPasswords(form);
    return;
  }
  try {
    await run(async () => {
      await invoke("wallet_close");
      await invoke("wallet_backup_import", {
        name: data.get("name"),
        backupPath: data.get("backup_path"),
        backupPassword: data.get("backup_password"),
        password: data.get("password"),
      });
    });
    enterGate();
    show("Encrypted backup imported in locked state.");
  } catch (error) {
    enterGate();
    show(redactedError(error), true);
  } finally { clearPasswords(form); }
});

// Display conversion only: 1 DOM = 100,000,000 noms (consensus COIN_UNIT).
// Fee arithmetic itself stays in Core; the frontend only presents it.
const NOMS_PER_DOM = 100000000;
const domText = (noms) => `${noms} noms (${(noms / NOMS_PER_DOM).toLocaleString("en-US", { maximumFractionDigits: 8 })} DOM)`;
const feeSummary = byId("send-fee-summary");
const renderFeeSummary = (amountNoms, feeNoms) => {
  feeSummary.textContent = `Amount ${domText(amountNoms)} · Network fee ${domText(feeNoms)} · Total ${domText(amountNoms + feeNoms)}`;
};
const output = byId("transaction-output");
const slateId = byId("transaction-slate-id");
const slateText = byId("transaction-text");
const renderTransaction = (value) => { redactJson(output, value); if (value?.slate_id) slateId.value = value.slate_id; if (value?.transaction?.slate_id) slateId.value = value.transaction.slate_id; if (value?.text) slateText.value = value.text; };
const requiredId = () => { if (!/^[0-9a-f-]{36}$/i.test(slateId.value.trim())) throw new Error("Enter a valid payment identifier."); return slateId.value.trim(); };
const requiredSlate = () => { const text = slateText.value.trim(); if (!text.startsWith("DOMSLATE4.")) throw new Error("A canonical DOMSLATE4 transport is required."); return text; };
byId("transaction-create").addEventListener("submit", async (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  try {
    const amount = integerNoms(data.get("amount"));
    const requestedFee = integerNoms(data.get("requested_fee"), true);
    let estimate;
    try {
      estimate = await run(() => invoke("transaction_fee_estimate", { amount, selectedInputCount: 1, changeOutput: true }));
    } catch (error) {
      feeSummary.textContent = "The network fee is unavailable; the payment was not created.";
      show(`Network fee unavailable: ${redactedError(error)}`, true);
      return;
    }
    const feeNoms = requestedFee ?? estimate.minimum_fee;
    renderFeeSummary(amount, feeNoms);
    if (!window.confirm(`Send ${domText(amount)} with a network fee of ${domText(feeNoms)}? Total ${domText(amount + feeNoms)}.`)) return;
    const network = await run(() => invoke("node_network_status"));
    const expiry = data.get("expires_at_height") === "" ? network.canonical_height + 1440 : integerNoms(data.get("expires_at_height"));
    const result = await run(() => invoke("transaction_send_create", { amount, requestedFee, expiresAtHeight: expiry }));
    renderTransaction(result); show("Recoverable Slate v4 request created.");
  } catch (error) { show(redactedError(error), true); }
});
byId("transaction-estimate").addEventListener("click", async () => {
  const data = new FormData(byId("transaction-create"));
  try {
    const amount = integerNoms(data.get("amount"));
    const estimate = await run(() => invoke("transaction_fee_estimate", { amount, selectedInputCount: 1, changeOutput: true }));
    renderFeeSummary(amount, estimate.minimum_fee);
    renderTransaction(estimate);
  } catch (error) {
    feeSummary.textContent = "The network fee is unavailable.";
    show(redactedError(error), true);
  }
});
const tx = (id, command, args = () => ({ slateId: requiredId() })) => byId(id).addEventListener("click", async () => {
  try { renderTransaction(await run(() => invoke(command, args()))); show(`${command.replaceAll("_", " ")} completed.`); }
  catch (error) { show(redactedError(error), true); }
});
tx("request-export", "slate_request_export", () => ({ slateId: requiredId() }));
tx("response-import", "slate_response_import", () => ({ text: requiredSlate() }));
tx("transaction-finalize", "transaction_finalize");
tx("transaction-submit", "transaction_submit");
tx("transaction-retry", "transaction_retry_submission");
tx("transaction-reconcile", "transaction_reconcile_submission");
tx("transaction-cancel", "slate_cancel", () => {
  const confirmed = window.confirm("Cancel this payment manually? If a finalized transaction exists, the counterparty may still broadcast it; releasing the input can create a double-spend risk. Otherwise, the entire reserved input becomes available again.");
  if (!confirmed) throw new Error("Cancellation was not confirmed.");
  return { slateId: requiredId(), confirmExported: true };
});

const receiveText = byId("receive-transaction-text");
const receiveId = byId("receive-transaction-slate-id");
const renderReceiver = (value) => {
  redactJson(byId("receive-output"), value);
  if (value?.slate_id) receiveId.value = value.slate_id;
  if (value?.text) receiveText.value = value.text;
};
const requiredReceiveId = () => { if (!/^[0-9a-f-]{36}$/i.test(receiveId.value.trim())) throw new Error("Import a valid Slate v4 request first."); return receiveId.value.trim(); };
const requiredReceiveSlate = () => { const text = receiveText.value.trim(); if (!text.startsWith("DOMSLATE4.")) throw new Error("A canonical DOMSLATE4 request is required."); return text; };
byId("request-import").addEventListener("click", async () => {
  try { const result = await run(() => invoke("slate_request_import", { text: requiredReceiveSlate() })); renderReceiver(result); show("Slate v4 request validated for Mainnet."); }
  catch (error) { show(redactedError(error), true); }
});
byId("response-create").addEventListener("click", async () => {
  try { renderReceiver(await run(() => invoke("slate_response_create", { slateId: requiredReceiveId() }))); show("Receiver participant response created."); }
  catch (error) { show(redactedError(error), true); }
});
byId("response-export").addEventListener("click", async () => {
  try { renderReceiver(await run(() => invoke("slate_response_export", { slateId: requiredReceiveId() }))); show("Slate v4 receiver response exported."); }
  catch (error) { show(redactedError(error), true); }
});

const renderHistory = async () => {
  const [transactions, summary] = await Promise.all([invoke("transaction_list"), invoke("wallet_summary")]);
  const pendingStates = new Set([
    "INPUTS_RESERVED", "REQUEST_EXPORTED", "RESPONSE_IMPORTED", "FINALIZED",
    "SUBMITTING", "SUBMITTED", "ACCEPTED_NOT_RELAYED", "IN_MEMPOOL",
    "REORGED", "RETRANSMIT_REQUIRED", "RECONCILIATION_REQUIRED", "FAILED",
  ]);
  const nodes = transactions.map((transaction) => {
    const node = document.createElement("article");
    node.className = "history-item";
    const title = document.createElement("strong");
    title.textContent = `${transaction.state} · ${transaction.amount} noms`;
    const identifier = document.createElement("code");
    identifier.textContent = transaction.slate_id ?? transaction.id;
    const details = document.createElement("p");
    details.className = "muted";
    const blockAge = transaction.created_at_height == null || summary.tip_height == null
      ? "unknown block age"
      : `${Math.max(0, summary.tip_height - transaction.created_at_height)} blocks old`;
    const timeAge = transaction.created_at_unix_seconds == null
      ? "unknown time age"
      : `${Math.max(0, Math.floor(Date.now() / 1000) - transaction.created_at_unix_seconds)} seconds old`;
    details.textContent = `${blockAge} · ${timeAge}`;
    node.append(title, identifier, details);
    if (transaction.awaiting_broadcast_confirmation) {
      const waiting = document.createElement("p");
      waiting.className = "warning";
      waiting.textContent = `Awaiting broadcast/confirmation · envelope expiry height ${transaction.expires_at_height}. This finalized transaction is never cancelled automatically.`;
      node.append(waiting);
    }
    if (transaction.cancellation_reason === "EXPIRED_BEFORE_FINALIZATION") {
      const automatic = document.createElement("p");
      automatic.className = "automatic-cancellation-event";
      automatic.textContent = `Automatically cancelled at height ${transaction.cancelled_at_height}: the envelope expired before finalization, so the reserved input was released.`;
      node.append(automatic);
      const key = transaction.slate_id ?? transaction.id;
      if (!seenAutomaticCancellations.has(key)) {
        seenAutomaticCancellations.add(key);
        show("An expired, unfinalized payment was cancelled automatically and its input is available again.");
      }
    }
    if (pendingStates.has(transaction.state) && transaction.manual_cancel_allowed) {
      const cancel = document.createElement("button");
      cancel.className = "btn ghost transaction-cancel-pending";
      cancel.type = "button";
      cancel.textContent = transaction.manual_cancel_warning
        ? "Cancel manually (double-spend risk)"
        : "Cancel and release input";
      cancel.addEventListener("click", async () => {
        const message = transaction.manual_cancel_warning
          ? "A finalized transaction is persisted and the counterparty may still broadcast it. Cancelling releases the input and can create a double spend. Cancel at your own risk?"
          : "Cancel this pending payment? The entire reserved input will return to your confirmed, available balance. A wallet rescan will not reserve it again.";
        const confirmed = window.confirm(message);
        if (!confirmed) return;
        try {
          await run(() => invoke("slate_cancel", { slateId: transaction.slate_id, confirmExported: true }));
          await Promise.all([renderHistory(), refreshSummary()]);
          show("Payment cancelled. The reserved input is available again.");
        } catch (error) {
          show(redactedError(error), true);
        }
      });
      node.append(cancel);
    }
    return node;
  });
  if (!nodes.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No transactions recorded.";
    nodes.push(empty);
  }
  byId("history-output").replaceChildren(...nodes);
  renderTransaction(transactions);
};
byId("history-refresh").addEventListener("click", () => run(renderHistory).catch((error) => show(redactedError(error), true)));
byId("transaction-list").addEventListener("click", () => run(renderHistory).catch((error) => show(redactedError(error), true)));

const canvas = byId("slate-qr-canvas");
const qrMeta = byId("slate-qr-meta");
const video = byId("slate-qr-video");
const drawQr = async () => { if (!qrFrames.length) return; await QRCode.toCanvas(canvas, qrFrames[qrIndex], { errorCorrectionLevel: "M", margin: 2, width: 360 }); qrMeta.textContent = `Frame ${qrIndex + 1} of ${qrFrames.length}`; };
const stopQrAnimation = () => {
  clearInterval(qrAnimationTimer);
  qrAnimationTimer = undefined;
};
const exportQr = async (slateId, response) => { const result = await run(() => invoke("slate_qr_encode", { slateId, response })); qrFrames = result.frames; qrIndex = 0; await drawQr(); };
const stopScanner = async () => { if (scanner) { scanner.stop(); scanner.destroy(); scanner = undefined; } video.srcObject = null; try { await invoke("slate_qr_reassembly_clear"); } catch { /* lifecycle may already be closed */ } };
byId("request-qr").addEventListener("click", () => exportQr(requiredId(), false).catch((error) => show(redactedError(error), true)));
byId("receive-response-qr").addEventListener("click", async () => {
  try {
    const result = await run(() => invoke("slate_qr_encode", {
      slateId: requiredReceiveId(),
      response: true,
    }));
    qrFrames = result.frames;
    qrIndex = 0;
    await QRCode.toCanvas(byId("receive-qr-canvas"), qrFrames[0], { errorCorrectionLevel: "M", margin: 2, width: 360 });
    byId("receive-qr-meta").textContent = `Receiver response frame 1 of ${qrFrames.length}`;
  } catch (error) {
    show(redactedError(error), true);
  }
});
byId("receive-qr-next").addEventListener("click", async () => {
  if (!qrFrames.length) return;
  qrIndex = (qrIndex + 1) % qrFrames.length;
  await QRCode.toCanvas(byId("receive-qr-canvas"), qrFrames[qrIndex], { errorCorrectionLevel: "M", margin: 2, width: 360 });
  byId("receive-qr-meta").textContent = `Receiver response frame ${qrIndex + 1} of ${qrFrames.length}`;
});
byId("qr-next").addEventListener("click", () => { if (qrFrames.length) { qrIndex = (qrIndex + 1) % qrFrames.length; drawQr(); } });
byId("qr-previous").addEventListener("click", () => { if (qrFrames.length) { qrIndex = (qrIndex + qrFrames.length - 1) % qrFrames.length; drawQr(); } });
byId("qr-clear").addEventListener("click", () => { stopQrAnimation(); qrFrames = []; canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height); qrMeta.textContent = "No QR export shown."; });
byId("qr-cancel").addEventListener("click", () => stopScanner());
byId("qr-scan").addEventListener("click", async () => {
  await stopScanner();
  scanner = new QrScanner(video, async (scan) => { const decoded = await invoke("slate_qr_decode_frame", { frame: scan.data }); if (decoded.complete_text) { slateText.value = decoded.complete_text; await stopScanner(); } }, { preferredCamera: "environment", returnDetailedScanResult: true });
  try { await scanner.start(); } catch (error) { await stopScanner(); show(redactedError(error), true); }
});
byId("qr-animate").addEventListener("click", () => {
  stopQrAnimation();
  if (qrFrames.length <= 1) {
    show("This QR export contains one frame.");
    return;
  }
  qrAnimationTimer = setInterval(() => {
    qrIndex = (qrIndex + 1) % qrFrames.length;
    drawQr().catch((error) => { stopQrAnimation(); show(redactedError(error), true); });
  }, 800);
  show(`Animating ${qrFrames.length} authenticated QR frames.`);
});
byId("qr-pause").addEventListener("click", () => { stopQrAnimation(); show("QR presentation paused."); });

document.documentElement.dataset.nativeBridge = nativeBridge.state;
nativeBridge.initialize()
  .then(() => {
    document.documentElement.dataset.nativeBridge = nativeBridge.state;
    refreshChainSource().catch(() => { /* configuration is loaded on demand in the panel */ });
    return Promise.all([invoke("application_status"), refreshOnboardingNode()]);
  })
  .then(([result]) => show(`Application state: ${result.state}.`))
  .catch((error) => {
    document.documentElement.dataset.nativeBridge = nativeBridge.state;
    show(redactedError(error), true);
  });
const refresh = async () => {
  const gateVisible = !byId("gate").classList.contains("hidden");
  const tasks = gateVisible
    ? [refreshOnboardingNode()]
    : [refreshSummary(), refreshNode(), refreshMining()];
  if (!gateVisible && !byId("diagnostics").hidden) tasks.push(refreshUpdates());
  if (!gateVisible && !byId("history").hidden) tasks.push(renderHistory());
  await Promise.allSettled(tasks);
  refreshTimer = setTimeout(refresh, gateVisible ? 5000 : 15000);
};
refreshTimer = setTimeout(refresh, 15000);
listen("swap-session-update", () => { refreshSwap().catch(() => {}); }).catch(() => { /* events unavailable outside the shell */ });
window.addEventListener("beforeunload", () => { clearTimeout(refreshTimer); stopRestoreScanPolling(); stopQrAnimation(); clearPhrase(); clearSecretForms(); stopScanner(); }, { once: true });
