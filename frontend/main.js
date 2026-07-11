const invoke = (command, args = {}) => {
  const bridge = window.__TAURI__?.core?.invoke;
  if (!bridge) return Promise.reject(new Error("Desktop command bridge is unavailable in this static preview."));
  return bridge(command, args);
};

const status = document.querySelector("#status");
const identity = document.querySelector("#network-identity");
const cards = document.querySelector("#balance-cards");
const syncStatus = document.querySelector("#sync-status");
const show = (message, failure = false) => { status.textContent = message; status.style.borderColor = failure ? "var(--danger)" : "var(--bronze)"; };
const clearPasswords = (form) => form.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ""; });
const amount = (value) => `${value ?? 0} DOM atomic units`;
const redactedError = (error) => String(error?.message ?? "Operation failed").replace(/password|secret|key/gi, "redacted");

function selectScreen(name) { document.querySelectorAll(".screen").forEach((screen) => { screen.hidden = screen.id !== name; }); }
document.querySelectorAll("[data-screen]").forEach((button) => button.addEventListener("click", () => selectScreen(button.dataset.screen)));

async function refreshSummary() {
  const summary = await invoke("wallet_summary");
  identity.textContent = `${summary.network} · wallet ${summary.wallet_id}`;
  cards.replaceChildren(...Object.entries(summary.balance).map(([name, value]) => { const node = document.createElement("div"); node.className = "card"; node.innerHTML = `<strong>${name}</strong>${amount(value)}`; return node; }));
  syncStatus.textContent = `Cursor ${summary.cursor_height ?? "not activated"}; state ${summary.state}.`;
}

const decodeHex32 = (value) => {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new Error("Chain and genesis values must be 64 lowercase hexadecimal characters.");
  return Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
};

document.querySelector("#create-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; try { const values = Object.fromEntries(new FormData(form)); await invoke("wallet_create", { path: values.path, password: values.password, identity: { network: values.network, chain_id: decodeHex32(values.chain_id), genesis_id: decodeHex32(values.genesis_id) } }); clearPasswords(form); show("Wallet created. Unlock it to use protected capabilities."); selectScreen("onboarding"); } catch (error) { clearPasswords(form); show(redactedError(error), true); } });
document.querySelector("#open-form").addEventListener("submit", async (event) => { event.preventDefault(); try { await invoke("wallet_open", Object.fromEntries(new FormData(event.currentTarget))); show("Wallet opened in locked state."); } catch (error) { show(redactedError(error), true); } });
document.querySelector("#unlock-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = event.currentTarget; try { await invoke("wallet_unlock", Object.fromEntries(new FormData(form))); clearPasswords(form); await refreshSummary(); show("Wallet unlocked."); selectScreen("dashboard"); } catch (error) { clearPasswords(form); show(redactedError(error), true); } });
document.querySelector("#lock").addEventListener("click", async () => { try { await invoke("wallet_lock"); show("Wallet locked; protected capabilities were revoked."); } catch (error) { show(redactedError(error), true); } });
document.querySelector("#sync").addEventListener("click", async () => { try { await invoke("synchronization_start"); await refreshSummary(); show("Synchronization request completed."); } catch (error) { show(redactedError(error), true); } });
document.querySelector("#probe").addEventListener("click", async () => { try { const result = await invoke("node_probe"); document.querySelector("#node-status").textContent = JSON.stringify(result); } catch (error) { show(redactedError(error), true); } });
invoke("application_status").then((app) => show(`Application state: ${app.state}.`)).catch((error) => show(redactedError(error), true));

export { clearPasswords, redactedError, selectScreen };
