import QRCode from "qrcode";
import QrScanner from "qr-scanner";
import { nativeBridge } from "./bridge.js";

export const COMMANDS = Object.freeze([
  "native_bridge_status", "application_status", "wallet_create_recoverable", "wallet_restore_from_mnemonic",
  "wallet_backup_export", "wallet_backup_import", "wallet_recovery_phrase_confirm",
  "wallet_open", "wallet_unlock", "wallet_lock", "wallet_close", "wallet_summary",
  "account_list", "account_summary", "embedded_node_start", "embedded_node_status",
  "node_network_status", "node_peer_status", "wallet_sync_status", "wallet_sync_start",
  "wallet_sync_pause", "wallet_sync_resume", "wallet_sync_retry", "wallet_rescan",
  "mining_status", "mining_config_get", "mining_config_set", "mining_start", "mining_stop",
  "wallet_address_validate", "synchronization_start", "synchronization_pause",
  "synchronization_resume", "synchronization_retry", "synchronization_rescan",
  "diagnostics_redacted", "application_shutdown", "transaction_fee_estimate",
  "transaction_send_create", "slate_request_export", "slate_request_import",
  "slate_response_create", "slate_response_export", "slate_response_import",
  "slate_summary_redacted", "transaction_finalize", "transaction_submit",
  "transaction_retry_submission", "transaction_reconcile_submission", "transaction_cancel",
  "transaction_list", "transaction_detail_redacted", "slate_qr_encode",
  "slate_qr_decode_frame", "slate_qr_reassembly_status", "slate_qr_reassembly_clear"
]);

const invoke = (command, args = {}) => {
  if (!COMMANDS.includes(command)) return Promise.reject(new Error("Unsupported desktop command."));
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
let phrasePending = false;

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
  document.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  try { return await action(); } finally {
    pending = false;
    document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
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
};

export function selectScreen(name) {
  clearSecretForms();
  document.querySelectorAll("#app .screen").forEach((screen) => { screen.hidden = screen.id !== name; });
  document.querySelectorAll(".nav [data-screen]").forEach((button) => button.classList.toggle("active", button.dataset.screen === name));
}
document.querySelectorAll("[data-screen]").forEach((button) => button.addEventListener("click", () => {
  selectScreen(button.dataset.screen);
  if (button.dataset.screen === "mining") refreshMining().catch((error) => show(redactedError(error), true));
  if (button.dataset.screen === "dashboard" || button.dataset.screen === "diagnostics") refreshSummary().catch((error) => show(redactedError(error), true));
}));
document.querySelectorAll("[data-gate-panel]").forEach((button) => button.addEventListener("click", () => {
  clearSecretForms();
  const panel = button.dataset.gatePanel;
  document.querySelectorAll(".gate-panel").forEach((node) => { node.hidden = node.id !== panel; });
}));
const enterApp = () => { byId("gate").classList.add("hidden"); byId("app").classList.remove("hidden"); selectScreen("dashboard"); };
const enterGate = () => { byId("app").classList.add("hidden"); byId("gate").classList.remove("hidden"); clearSecretForms(); };

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
    const created = await run(() => invoke("wallet_create_recoverable", { path: data.get("path"), password: data.get("password") }));
    clearPasswords(form); beginPhrase(created.mnemonic); show("Write down and confirm the recovery phrase.");
  } catch (error) { clearPasswords(form); show(redactedError(error), true); }
});
byId("restore-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try {
    show("Restore: initializing Mainnet node.");
    const result = await run(() => invoke("wallet_restore_from_mnemonic", { path: data.get("path"), password: data.get("password"), mnemonic: data.get("mnemonic") }));
    form.querySelector('textarea[name="mnemonic"]').value = ""; clearPasswords(form);
    show(`Restore completed: ${result.owned_output_count} owned outputs, ${result.confirmed_balance} confirmed noms.`);
  } catch (error) { form.querySelector('textarea[name="mnemonic"]').value = ""; clearPasswords(form); show(redactedError(error), true); }
});
byId("open-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { await run(() => invoke("wallet_open", { path: new FormData(form).get("path") })); show("Mainnet wallet opened in locked state."); }
  catch (error) { show(redactedError(error), true); }
});
byId("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { await run(() => invoke("wallet_unlock", { password: new FormData(form).get("password") })); clearPasswords(form); enterApp(); await refreshSummary(); show("Wallet unlocked."); }
  catch (error) { clearPasswords(form); show(redactedError(error), true); }
});

const refreshSummary = async () => {
  const [summary, network, peers, synchronization] = await Promise.all([
    invoke("wallet_summary"), invoke("node_network_status"), invoke("node_peer_status"), invoke("wallet_sync_status")
  ]);
  byId("network-identity").textContent = `${summary.network} · ${summary.state}`;
  byId("balance-total").firstChild.textContent = `${summary.balance.total ?? 0} `;
  byId("balance-cards").replaceChildren(...Object.entries(summary.balance).map(([key, value]) => {
    const card = document.createElement("div"); card.className = "card"; card.textContent = `${key}: ${value} noms`; return card;
  }));
  byId("connection-status").textContent = peers.total_connected_peers > 0
    ? `Connected to ${peers.total_connected_peers} peer${peers.total_connected_peers === 1 ? "" : "s"}`
    : "No peers found";
  byId("canonical-height").textContent = network.canonical_height;
  byId("cursor-height").textContent = synchronization.cursor_height ?? "Not initialized";
  byId("sync-status").textContent = synchronization.synchronized
    ? `Wallet synchronized at height ${synchronization.cursor_height}`
    : synchronization.last_error ?? "Not synchronized";
  byId("settings-chain-id").textContent = network.chain_id;
  byId("settings-genesis").textContent = network.genesis_hash;
  byId("settings-node-data").textContent = network.data_directory;
  byId("settings-peer-count").textContent = peers.total_connected_peers;
  byId("settings-bootstrap").textContent = peers.bootstrap_phase;
  byId("settings-heights").textContent = `${synchronization.cursor_height ?? "—"} / ${network.canonical_height}`;
};
const refreshNode = async () => redactJson(byId("node-status"), await invoke("embedded_node_status"));
const renderMining = (value) => {
  byId("mining-status").textContent = value.status;
  byId("mining-enabled").checked = value.enabled;
  byId("mining-threads").value = value.cpu_threads;
  byId("mining-threads").disabled = !value.enabled || value.running;
  byId("mining-address").value = value.mining_address;
  byId("mining-hashrate").textContent = `${value.hashrate_hps.toFixed(1)} H/s`;
  byId("mining-height").textContent = value.current_height;
  byId("mining-peers").textContent = value.connected_peers;
  byId("mining-accepted").textContent = value.accepted_blocks;
  byId("mining-rejected").textContent = value.rejected_work;
  byId("mining-candidate").textContent = value.last_block_candidate_time ? new Date(value.last_block_candidate_time * 1000).toLocaleString() : "Never";
  byId("mining-last-height").textContent = value.last_accepted_block_height ?? "—";
  byId("mining-uptime").textContent = `${value.uptime_seconds}s`;
  byId("mining-warning").hidden = value.current_height !== 0;
  byId("mining-start").disabled = !value.enabled || value.running;
  byId("mining-stop").disabled = !value.running && value.status !== "ERROR";
};
const refreshMining = async () => renderMining(await invoke("mining_status"));
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
  const current = await invoke("mining_status");
  const message = current.current_height === 0
    ? "Starting mining may produce the first post-genesis Mainnet block. Continue?"
    : "Start local CPU mining on DOM Mainnet?";
  if (!window.confirm(message)) return;
  try { renderMining(await run(() => invoke("mining_start", { confirmed: true }))); }
  catch (error) { show(redactedError(error), true); }
});
byId("mining-stop").addEventListener("click", async () => {
  try { renderMining(await run(() => invoke("mining_stop"))); }
  catch (error) { show(redactedError(error), true); }
});
byId("sync").addEventListener("click", () => run(async () => { await invoke("wallet_sync_start"); await refreshSummary(); }).catch((error) => show(redactedError(error), true)));
byId("node-sync").addEventListener("click", () => run(async () => { await invoke("wallet_sync_start"); await refreshNode(); }).catch((error) => show(redactedError(error), true)));
byId("node-refresh").addEventListener("click", () => run(refreshNode).catch((error) => show(redactedError(error), true)));
for (const [id, command] of [["pause", "wallet_sync_pause"], ["resume", "wallet_sync_resume"], ["retry", "wallet_sync_retry"]]) {
  byId(id).addEventListener("click", () => run(() => invoke(command)).catch((error) => show(redactedError(error), true)));
}
byId("rescan").addEventListener("click", () => { if (window.confirm("Rescan from canonical Mainnet genesis?")) run(() => invoke("wallet_rescan")).catch((error) => show(redactedError(error), true)); });
byId("diagnostics-refresh").addEventListener("click", () => run(async () => { await refreshSummary(); redactJson(byId("diagnostics-output"), await invoke("diagnostics_redacted")); }).catch((error) => show(redactedError(error), true)));
byId("lock").addEventListener("click", () => run(async () => { await stopScanner(); await invoke("wallet_lock"); enterGate(); }).catch((error) => show(redactedError(error), true)));
byId("close").addEventListener("click", () => run(async () => { await stopScanner(); await invoke("wallet_close"); enterGate(); }).catch((error) => show(redactedError(error), true)));

byId("backup-export-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try { const result = await run(() => invoke("wallet_backup_export", { destination: data.get("destination"), backupPassword: data.get("backup_password") })); show(`Encrypted backup created: ${result.destination_name}.`); }
  catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); }
});
byId("backup-import-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try { await run(() => invoke("wallet_backup_import", { destination: data.get("destination"), backupPath: data.get("backup_path"), backupPassword: data.get("backup_password"), password: data.get("password") })); enterGate(); show("Encrypted backup imported in locked state."); }
  catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); }
});

const output = byId("transaction-output");
const slateId = byId("transaction-slate-id");
const slateText = byId("transaction-text");
const renderTransaction = (value) => { redactJson(output, value); if (value?.slate_id) slateId.value = value.slate_id; if (value?.transaction?.slate_id) slateId.value = value.transaction.slate_id; if (value?.text) slateText.value = value.text; };
const requiredId = () => { if (!/^[0-9a-f-]{36}$/i.test(slateId.value.trim())) throw new Error("Enter a valid payment identifier."); return slateId.value.trim(); };
const requiredSlate = () => { const text = slateText.value.trim(); if (!text.startsWith("DOMSLATE4.")) throw new Error("A canonical DOMSLATE4 transport is required."); return text; };
byId("transaction-create").addEventListener("submit", async (event) => {
  event.preventDefault(); const data = new FormData(event.currentTarget);
  try {
    const network = await run(() => invoke("node_network_status"));
    const expiry = data.get("expires_at_height") === "" ? network.canonical_height + 1440 : integerNoms(data.get("expires_at_height"));
    const result = await run(() => invoke("transaction_send_create", { amount: integerNoms(data.get("amount")), requestedFee: integerNoms(data.get("requested_fee"), true), expiresAtHeight: expiry }));
    renderTransaction(result); show("Recoverable Slate v4 request created.");
  } catch (error) { show(redactedError(error), true); }
});
byId("transaction-estimate").addEventListener("click", async () => {
  const data = new FormData(byId("transaction-create"));
  try { renderTransaction(await run(() => invoke("transaction_fee_estimate", { amount: integerNoms(data.get("amount")), selectedInputCount: 1, changeOutput: true }))); }
  catch (error) { show(redactedError(error), true); }
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
tx("transaction-cancel", "transaction_cancel", () => ({ slateId: requiredId(), confirmExported: window.confirm("Cancel this payment and retain its consumed recovery coordinate?") }));

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
  const transactions = await invoke("transaction_list");
  const nodes = transactions.map((transaction) => { const node = document.createElement("article"); node.className = "history-item"; node.textContent = `${transaction.state} · ${transaction.amount} noms · ${transaction.slate_id}`; return node; });
  byId("history-output").replaceChildren(...nodes);
  renderTransaction(transactions);
};
byId("history-refresh").addEventListener("click", () => run(renderHistory).catch((error) => show(redactedError(error), true)));
byId("transaction-list").addEventListener("click", () => run(renderHistory).catch((error) => show(redactedError(error), true)));

const canvas = byId("slate-qr-canvas");
const qrMeta = byId("slate-qr-meta");
const video = byId("slate-qr-video");
const drawQr = async () => { if (!qrFrames.length) return; await QRCode.toCanvas(canvas, qrFrames[qrIndex], { errorCorrectionLevel: "M", margin: 2, width: 360 }); qrMeta.textContent = `Frame ${qrIndex + 1} of ${qrFrames.length}`; };
const exportQr = async (response) => { const result = await run(() => invoke("slate_qr_encode", { slateId: requiredId(), response })); qrFrames = result.frames; qrIndex = 0; await drawQr(); };
const stopScanner = async () => { if (scanner) { scanner.stop(); scanner.destroy(); scanner = undefined; } video.srcObject = null; try { await invoke("slate_qr_reassembly_clear"); } catch { /* lifecycle may already be closed */ } };
byId("request-qr").addEventListener("click", () => exportQr(false).catch((error) => show(redactedError(error), true)));
byId("response-qr").addEventListener("click", () => exportQr(true).catch((error) => show(redactedError(error), true)));
byId("qr-next").addEventListener("click", () => { if (qrFrames.length) { qrIndex = (qrIndex + 1) % qrFrames.length; drawQr(); } });
byId("qr-previous").addEventListener("click", () => { if (qrFrames.length) { qrIndex = (qrIndex + qrFrames.length - 1) % qrFrames.length; drawQr(); } });
byId("qr-clear").addEventListener("click", () => { qrFrames = []; canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height); qrMeta.textContent = "No QR export shown."; });
byId("qr-cancel").addEventListener("click", () => stopScanner());
byId("qr-scan").addEventListener("click", async () => {
  await stopScanner();
  scanner = new QrScanner(video, async (scan) => { const decoded = await invoke("slate_qr_decode_frame", { frame: scan.data }); if (decoded.complete_text) { slateText.value = decoded.complete_text; await stopScanner(); } }, { preferredCamera: "environment", returnDetailedScanResult: true });
  try { await scanner.start(); } catch (error) { await stopScanner(); show(redactedError(error), true); }
});
byId("qr-animate").addEventListener("click", () => show("Single canonical QR frame requires no animation."));
byId("qr-pause").addEventListener("click", () => show("QR presentation paused."));

document.documentElement.dataset.nativeBridge = nativeBridge.state;
nativeBridge.initialize()
  .then(() => {
    document.documentElement.dataset.nativeBridge = nativeBridge.state;
    return invoke("application_status");
  })
  .then((result) => show(`Application state: ${result.state}.`))
  .catch((error) => {
    document.documentElement.dataset.nativeBridge = nativeBridge.state;
    show(redactedError(error), true);
  });
const refresh = async () => { try { await refreshNode(); await refreshMining(); } catch { /* wallet or node may not be open */ } refreshTimer = setTimeout(refresh, 15000); };
refreshTimer = setTimeout(refresh, 15000);
window.addEventListener("beforeunload", () => { clearTimeout(refreshTimer); clearPhrase(); clearSecretForms(); stopScanner(); }, { once: true });
