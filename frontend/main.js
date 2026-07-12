// The packaged application has exactly one transport: Tauri invoke. There is
// intentionally no production mock, balance calculator, or browser storage.
export const COMMANDS = Object.freeze([
  "application_status", "wallet_create", "wallet_open", "wallet_unlock", "wallet_lock",
  "wallet_close", "wallet_summary", "account_list", "account_summary",
  "node_configuration_get_redacted", "node_configuration_set", "node_probe",
  "synchronization_start", "synchronization_pause", "synchronization_resume",
  "synchronization_retry", "synchronization_rescan", "diagnostics_redacted", "application_shutdown"
  , "transaction_fee_estimate", "transaction_send_create", "slate_request_export",
  "slate_request_import", "slate_response_create", "slate_response_export",
  "slate_response_import", "slate_summary_redacted", "transaction_finalize",
  "transaction_submit", "transaction_retry_submission", "transaction_cancel",
  "transaction_list", "transaction_detail_redacted"
]);

const productionInvoke = (command, args = {}) => {
  if (!COMMANDS.includes(command)) return Promise.reject(new Error("Unsupported desktop command."));
  const bridge = window.__TAURI__?.core?.invoke;
  if (!bridge) return Promise.reject(new Error("Native desktop command bridge is unavailable."));
  return bridge(command, args);
};

const status = document.querySelector("#status");
const identity = document.querySelector("#network-identity");
const cards = document.querySelector("#balance-cards");
const syncStatus = document.querySelector("#sync-status");
let pending = false;
let refreshTimer = null;
let refreshActive = false;
const STATUS_REFRESH_MS = 15_000;

const show = (message, failure = false) => { status.textContent = message; status.style.borderColor = failure ? "var(--danger)" : "var(--bronze)"; };
export const clearPasswords = (form) => form.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; });
const amount = (value) => `${value ?? 0} DOM atomic units`;
export const redactedError = (error) => {
  const text = String(error?.message ?? "Operation failed");
  return /password|secret|key|token|credential|bearer|:\/\//i.test(text) ? "The desktop operation failed." : text;
};

export function selectScreen(name) { document.querySelectorAll(".screen").forEach((screen) => { screen.hidden = screen.id !== name; }); }
document.querySelectorAll("[data-screen]").forEach((button) => button.addEventListener("click", () => selectScreen(button.dataset.screen)));

const withPending = async (action) => {
  if (pending) return;
  pending = true;
  document.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  try { return await action(); } finally { pending = false; document.querySelectorAll("button").forEach((button) => { button.disabled = false; }); }
};

export const renderState = (value) => {
  const supported = new Set(["CLOSED", "LOCKED", "UNLOCKING", "UNLOCKED", "DISCONNECTED", "CONNECTING", "VERIFYING_IDENTITY", "CONNECTED", "SYNCHRONIZING", "SYNCED", "PAUSED", "RESCANNING", "DEGRADED", "BACKING_OFF", "WRONG_NETWORK", "AUTHENTICATION_FAILED", "INCOMPATIBLE_PROTOCOL", "STORAGE_ERROR", "FATAL_CONFIGURATION_ERROR", "ERROR"]);
  return supported.has(value) ? value : "Unsupported desktop state";
};

async function refreshSummary() {
  if (refreshActive) return;
  refreshActive = true;
  try {
    const summary = await productionInvoke("wallet_summary");
    if (!summary?.balance || !summary?.state) throw new Error("Invalid wallet summary response.");
    identity.textContent = `${summary.network} · wallet ${summary.wallet_id}`;
    cards.replaceChildren(...Object.entries(summary.balance).map(([name, value]) => { const node = document.createElement("div"); node.className = "card"; node.textContent = `${name}: ${amount(value)}`; return node; }));
    syncStatus.textContent = `Cursor ${summary.cursor_height ?? "not activated"}; state ${renderState(summary.state)}.`;
  } finally { refreshActive = false; }
}

const decodeHex32 = (value) => {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("Chain and genesis values must be 64 lowercase hexadecimal characters.");
  return Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
};

document.querySelector("#create-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; try { await withPending(() => productionInvoke("wallet_create", { path: new FormData(form).get("path"), password: new FormData(form).get("password"), identity: { network: new FormData(form).get("network"), chain_id: decodeHex32(new FormData(form).get("chain_id")), genesis_id: decodeHex32(new FormData(form).get("genesis_id")) } })); show("Wallet created. Unlock it to use protected capabilities."); } catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); } });
document.querySelector("#open-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; try { await withPending(() => productionInvoke("wallet_open", { path: new FormData(form).get("path") })); show("Wallet opened in locked state."); } catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); } });
document.querySelector("#unlock-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; try { await withPending(async () => { await productionInvoke("wallet_unlock", { password: new FormData(form).get("password") }); await refreshSummary(); }); show("Wallet unlocked."); selectScreen("dashboard"); } catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); } });
document.querySelector("#lock").addEventListener("click", () => withPending(async () => { await productionInvoke("wallet_lock"); show("Wallet locked; protected capabilities were revoked."); } ).catch((error) => show(redactedError(error), true)));
document.querySelector("#sync").addEventListener("click", () => withPending(async () => { await productionInvoke("synchronization_start"); await refreshSummary(); show("Synchronization request completed."); }).catch((error) => show(redactedError(error), true)));

productionInvoke("application_status").then((app) => show(`Application state: ${renderState(app.state)}.`)).catch((error) => show(redactedError(error), true));
export const stopStatusRefresh = () => { if (refreshTimer) clearTimeout(refreshTimer); refreshTimer = null; };
const scheduleStatusRefresh = () => {
  stopStatusRefresh();
  const tick = async () => {
    if (refreshActive) return;
    refreshActive = true;
    try {
      const app = await productionInvoke("application_status");
      const state = renderState(app?.state);
      show(`Application state: ${state}.`, state === "Unsupported desktop state");
      if (!new Set(["CLOSED", "FATAL_CONFIGURATION_ERROR", "Unsupported desktop state"]).has(state)) refreshTimer = setTimeout(tick, STATUS_REFRESH_MS);
    } catch (error) { show(redactedError(error), true); } finally { refreshActive = false; }
  };
  refreshTimer = setTimeout(tick, STATUS_REFRESH_MS);
};
scheduleStatusRefresh();
window.addEventListener("beforeunload", stopStatusRefresh, { once: true });
const diagnostics = document.querySelector("#diagnostics-output");
const nodeStatus = document.querySelector("#node-status");
const nodeForm = document.querySelector("#node-form");
const numeric = (value) => { const parsed = Number(value); if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error("Invalid numeric configuration value."); return parsed; };
const configurationFromForm = (form) => {
  const value = new FormData(form);
  const credential = value.get("credential_reference");
  return { endpoint_url: value.get("endpoint_url"), expected_identity: { network: value.get("network"), chain_id: decodeHex32(value.get("chain_id")), genesis_id: decodeHex32(value.get("genesis_id")) }, source_identity: "configured-dom-node", api_compatibility_version: 1, connect_timeout_ms: numeric(value.get("connect_timeout_ms")), request_timeout_ms: numeric(value.get("request_timeout_ms")), poll_interval_ms: numeric(value.get("poll_interval_ms")), retry_ceiling: numeric(value.get("retry_ceiling")), max_backoff_ms: numeric(value.get("max_backoff_ms")), stable_success_threshold: 3, tls_required: value.get("tls_required") === "on", credential_reference: credential || null };
};
const redactedJson = (target, value) => { target.textContent = JSON.stringify(value, null, 2); };
document.querySelector("#config-load").addEventListener("click", () => withPending(async () => { const value = await productionInvoke("node_configuration_get_redacted"); redactedJson(nodeStatus, value); }).catch((error) => show(redactedError(error), true)));
nodeForm.addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; if (!window.confirm("Replace the active node configuration?")) return; try { await withPending(() => productionInvoke("node_configuration_set", { configuration: configurationFromForm(form) })); show("Redacted node configuration updated."); } catch (error) { show(redactedError(error), true); } finally { clearPasswords(form); } });
document.querySelector("#probe").addEventListener("click", () => withPending(async () => { const result = await productionInvoke("node_probe", { configuration: configurationFromForm(nodeForm) }); redactedJson(nodeStatus, result); }).catch((error) => show(redactedError(error), true)));
document.querySelector("#pause").addEventListener("click", () => withPending(() => productionInvoke("synchronization_pause")).catch((error) => show(redactedError(error), true)));
document.querySelector("#resume").addEventListener("click", () => withPending(() => productionInvoke("synchronization_resume")).catch((error) => show(redactedError(error), true)));
document.querySelector("#retry").addEventListener("click", () => withPending(() => productionInvoke("synchronization_retry")).catch((error) => show(redactedError(error), true)));
document.querySelector("#rescan").addEventListener("click", () => { if (window.confirm("Full rescan reconstructs the wallet from canonical chain evidence. Continue?")) withPending(() => productionInvoke("synchronization_rescan")).catch((error) => show(redactedError(error), true)); });
document.querySelector("#close").addEventListener("click", () => withPending(async () => { await productionInvoke("wallet_close"); stopStatusRefresh(); selectScreen("onboarding"); show("Wallet closed."); }).catch((error) => show(redactedError(error), true)));
document.querySelector("#diagnostics-refresh").addEventListener("click", () => withPending(async () => redactedJson(diagnostics, await productionInvoke("diagnostics_redacted"))).catch((error) => show(redactedError(error), true)));

// Manual slate exchange is intentionally explicit: text stays in the DOM only
// until an import settles and is never copied into browser storage.
const transactionOutput = document.querySelector("#transaction-output");
const transactionSlateId = document.querySelector("#transaction-slate-id");
const transactionText = document.querySelector("#transaction-text");
const renderTransaction = (value) => { redactedJson(transactionOutput, value); if (value?.slate_id) transactionSlateId.value = value.slate_id; };
const requiredSlateId = () => { const value = transactionSlateId.value.trim(); if (!/^[0-9a-f-]{36}$/i.test(value)) throw new Error("Enter a valid slate identifier."); return value; };
const clearSlateText = () => { transactionText.value = ""; };
document.querySelector("#transaction-create").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const data = new FormData(form);
  try {
    const created = await withPending(() => productionInvoke("transaction_send_create", { amount: Number(data.get("amount")), requestedFee: data.get("requested_fee") ? Number(data.get("requested_fee")) : null }));
    renderTransaction(created); show("Send transaction reserved. Export the request only after review.");
  } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#transaction-estimate").addEventListener("click", async () => {
  const form = document.querySelector("#transaction-create"); const data = new FormData(form);
  try { redactedJson(transactionOutput, await withPending(() => productionInvoke("transaction_fee_estimate", { amount: Number(data.get("amount")), selectedInputCount: 1, changeOutput: true }))); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#request-export").addEventListener("click", async () => {
  if (!window.confirm("Export this manual slate request? It contains public transaction data.")) return;
  try { const result = await withPending(() => productionInvoke("slate_request_export", { slateId: requiredSlateId() })); transactionText.value = result.text; renderTransaction(result); show("Canonical request exported."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#request-import").addEventListener("click", async () => {
  const text = transactionText.value;
  try { renderTransaction(await withPending(() => productionInvoke("slate_request_import", { text }))); show("Request imported. Review it before preparing a response."); } catch (error) { show(redactedError(error), true); } finally { clearSlateText(); }
});
document.querySelector("#response-create").addEventListener("click", async () => {
  if (!window.confirm("Create the recipient output and response for this request?")) return;
  try { renderTransaction(await withPending(() => productionInvoke("slate_response_create", { slateId: requiredSlateId() }))); show("Recipient response prepared."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#response-export").addEventListener("click", async () => {
  if (!window.confirm("Export this recipient response?")) return;
  try { const result = await withPending(() => productionInvoke("slate_response_export", { slateId: requiredSlateId() })); transactionText.value = result.text; renderTransaction(result); show("Canonical response exported."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#response-import").addEventListener("click", async () => {
  const text = transactionText.value;
  try { renderTransaction(await withPending(() => productionInvoke("slate_response_import", { text }))); show("Response imported."); } catch (error) { show(redactedError(error), true); } finally { clearSlateText(); }
});
document.querySelector("#transaction-finalize").addEventListener("click", async () => {
  if (!window.confirm("Finalize this DOM transaction?")) return;
  try { renderTransaction(await withPending(() => productionInvoke("transaction_finalize", { slateId: requiredSlateId() }))); show("Transaction finalized and stored."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#transaction-submit").addEventListener("click", async () => {
  if (!window.confirm("Submit the immutable finalized transaction to the configured node?")) return;
  try { renderTransaction(await withPending(() => productionInvoke("transaction_submit", { slateId: requiredSlateId() }))); show("Submission result recorded."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#transaction-retry").addEventListener("click", async () => {
  if (!window.confirm("Retry submission using the same finalized bytes?")) return;
  try { renderTransaction(await withPending(() => productionInvoke("transaction_retry_submission", { slateId: requiredSlateId() }))); show("Submission retry recorded."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#transaction-cancel").addEventListener("click", async () => {
  if (!window.confirm("Cancel this pre-submission transaction and release only safe reservations?")) return;
  try { renderTransaction(await withPending(() => productionInvoke("transaction_cancel", { slateId: requiredSlateId(), confirmExported: true }))); show("Transaction cancellation recorded."); } catch (error) { show(redactedError(error), true); }
});
document.querySelector("#transaction-list").addEventListener("click", async () => {
  try { redactedJson(transactionOutput, await withPending(() => productionInvoke("transaction_list"))); } catch (error) { show(redactedError(error), true); }
});
export { productionInvoke, refreshSummary };
