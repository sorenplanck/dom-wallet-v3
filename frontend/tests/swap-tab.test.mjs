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
