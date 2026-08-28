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
