import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const source = async (name) => readFile(new URL(name, root), "utf8");

test("the swap screen exists with the four design panels and the fee minute", async () => {
  const html = await source("index.html");
  assert.equal(html.includes('data-screen-contract="swap"'), true, "missing swap screen contract");
  assert.equal(html.includes('data-screen="swap"'), true, "missing swap nav entry");
  for (const id of [
    "swap-intent-form", "swap-fee-asset", "swap-fee-summary",
    "swap-quotes-list", "swap-session-status", "swap-history-list",
    "swap-btc-address", "swap-evm-address", "swap-daemon-banner",
  ]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing swap element ${id}`);
  }
  // The fee minute offers exactly the adjudicated payment assets.
  for (const asset of ["DOM", "BTC", "USDT"]) {
    assert.equal(html.includes(`<option value="${asset}">`), true, `missing payment asset ${asset}`);
  }
  // The protection floor from the design's intent screen is present.
  assert.equal(html.includes('name="minimum_output"'), true, "missing minimum received field");
});

test("the swap flow fails closed without the interop daemon and fabricates nothing", async () => {
  const js = await source("main.js");
  assert.equal(js.includes("The interop daemon is not connected"), true, "missing honest daemon message");
  assert.equal(js.includes("the intent was not published"), true, "a failed intent must say it was not published");
  // No fabricated quotes, sessions or balances anywhere in the swap logic.
  for (const forbidden of ["fakeQuote", "mockQuote", "sampleQuotes", "placeholderSession"]) {
    assert.equal(js.includes(forbidden), false, `fabricated swap state: ${forbidden}`);
  }
  // Fee arithmetic lives in Rust: the frontend only formats the DTO.
  assert.equal(js.includes("swap_fee_quote"), true, "fee must come from the command");
  assert.equal(js.includes("SWAP_FEE_BPS"), false, "fee constant must not leak into the frontend");
  assert.equal(js.includes("* 10 / 10000") || js.includes("*10/10000"), false, "no bps arithmetic in the frontend");
});

test("leg addresses come from the wallet's own derivation command", async () => {
  const js = await source("main.js");
  assert.equal(js.includes('invoke("swap_leg_addresses")'), true, "addresses must come from the derivation command");
  const html = await source("index.html");
  assert.equal(html.includes("m/86'/0'"), true, "the taproot path is stated to the user");
  assert.equal(html.includes("m/44'/60'"), true, "the EVM path is stated to the user");
});

test("every swap session is resumable and the UI reads only committed state", async () => {
  const js = await source("main.js");
  const html = await source("index.html");
  // Resume is enumeration of the durable store, surfaced without being asked.
  assert.equal(js.includes('invoke("swap_sessions_open")'), true, "resume must read the durable store");
  assert.equal(js.includes("resumed from durable state"), true, "the resume banner must say where sessions come from");
  assert.equal(html.includes('id="swap-resume-banner"'), true, "missing resume banner");
  // The refund clock is always visible once armed (design I5).
  assert.equal(html.includes('id="swap-refund-clock"'), true, "missing refund clock");
  assert.equal(js.toLowerCase().includes("your refund unlocks at"), true, "missing refund unlock message");
});

test("the deposit panel guides with QR, quoted bounds and an honest shortfall warning", async () => {
  const html = await source("index.html");
  for (const id of [
    "swap-deposit-panel", "swap-deposit-qr", "swap-deposit-address",
    "swap-deposit-bounds", "swap-deposit-confirmations", "swap-deposit-warning",
  ]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing deposit element ${id}`);
  }
  assert.equal(
    html.includes("does not cover the minimum after network fees"),
    true,
    "the shortfall warning must account for network fees explicitly",
  );
  const js = await source("main.js");
  // Confirmations are observations relayed by the backend, never invented.
  assert.equal(js.includes("observed_confirmations"), true, "confirmations must come from the DTO");
});

test("manual refund and free cancellation exist as explicit fallbacks", async () => {
  const html = await source("index.html");
  const js = await source("main.js");
  assert.equal(html.includes('id="swap-manual-refund"'), true, "missing manual refund button");
  assert.equal(html.includes('id="swap-session-cancel"'), true, "missing cancel button");
  assert.equal(html.includes('id="swap-session-detail"'), true, "missing raw details panel");
  assert.equal(js.includes('invoke("swap_manual_refund"'), true, "refund must go through the gated command");
  assert.equal(js.includes('invoke("swap_session_cancel"'), true, "cancel must go through the command");
});

test("the recovery hatch is display-once, acknowledged and never logged", async () => {
  const html = await source("index.html");
  const js = await source("main.js");
  for (const id of ["swap-export-keys", "swap-export-clear", "swap-export-output"]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing hatch element ${id}`);
  }
  assert.equal(js.includes('invoke("swap_leg_keys_export", { acknowledged: true })'), true, "export must acknowledge explicitly");
  const exportBlock = js.slice(js.indexOf("swap-export-keys"), js.indexOf('swap-export-clear")'));
  assert.equal(exportBlock.includes("window.confirm"), true, "export must ask before revealing");
  assert.equal(exportBlock.includes("console.log"), false, "keys must never reach the console");
  assert.equal(js.includes("replaceChildren()"), true, "hiding the keys must clear the DOM");
});

test("all four external legs are first-class: BTC, EVM, XMR and SOL", async () => {
  const html = await source("index.html");
  // The intent selects offer every leg family plus the DOM itself.
  for (const asset of ["DOM", "BTC", "USDT", "XMR", "SOL"]) {
    assert.equal(html.includes(`<option value="${asset}">`), true, `missing ${asset} option`);
  }
  // Leg addresses state every derivation path and render every chain.
  for (const path of ["m/86'/0'", "m/44'/60'", "m/44'/501'", "m/44'/128'"]) {
    assert.equal(html.includes(path), true, `the ${path} path is stated to the user`);
  }
  for (const id of ["swap-btc-address", "swap-evm-address", "swap-sol-address", "swap-xmr-address"]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing leg address element ${id}`);
  }
  const js = await source("main.js");
  assert.equal(js.includes("solana_address"), true, "the Solana address must be rendered");
  assert.equal(js.includes("monero_address"), true, "the Monero address must be rendered");
  // The recovery hatch covers all four legs, Monero with both secrets.
  for (const field of ["solana_secret_hex", "monero_spend_secret_hex", "monero_view_secret_hex"]) {
    assert.equal(js.includes(field), true, `hatch must render ${field}`);
  }
});

test("the swap network card exposes identity and descriptor validation, never a fake connection", async () => {
  const html = await source("index.html");
  for (const id of ["swap-identity-show", "swap-identity-output", "swap-descriptor-form", "swap-descriptor-json", "swap-descriptor-verdict"]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing swap network element ${id}`);
  }
  assert.equal(html.includes("Nothing connects until an endpoint exists"), true, "the card must state the disconnected truth");
  const js = await source("main.js");
  assert.equal(js.includes('invoke("swap_initiator_identity")'), true, "identity must come from the command");
  assert.equal(js.includes('invoke("swap_network_descriptor_check"'), true, "validation must go through the command");
});

test("leg addresses rotate per swap and the hatch reaches every index used", async () => {
  const html = await source("index.html");
  const js = await source("main.js");
  // The index is stated to the user, not hidden behind the address.
  assert.equal(html.includes('id="swap-legs-index"'), true, "missing derivation index line");
  assert.equal(js.includes("Derivation index"), true, "the index must be named on screen");
  // The hatch iterates the recorded index sets; exporting only one index
  // would strand funds left on an earlier one.
  assert.equal(js.includes("keys.indices"), true, "the hatch must export every recorded index");
  assert.equal(js.includes("set.bitcoin_secret_hex"), true, "per-index bitcoin secret");
  assert.equal(js.includes("set.solana_secret_hex"), true, "per-index solana secret");
  // Monero keeps a single account on purpose — stealth addresses already
  // give each payment its own destination.
  assert.equal(js.includes("keys.monero_spend_secret_hex"), true, "monero stays single-account");
  // The seed-only recovery path exists and carries no secret.
  assert.equal(html.includes('id="swap-scan-plan"'), true, "missing scan plan button");
  assert.equal(html.includes('id="swap-scan-output"'), true, "missing scan plan output");
  assert.equal(js.includes('invoke("swap_leg_scan_plan")'), true, "scan plan must come from the command");
  assert.equal(js.includes("gap margin"), true, "gap-limit entries must be marked as such");
  const scanBlock = js.slice(js.indexOf('swap-scan-plan"'), js.indexOf('swap-export-clear")'));
  assert.equal(/secret/i.test(scanBlock), false, "the scan plan must never render a secret");
});
