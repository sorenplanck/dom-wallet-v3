import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const source = async (name) => readFile(new URL(name, root), "utf8");

test("mining screen distinguishes local and observed network hashrate", async () => {
  const [html, js] = await Promise.all([source("index.html"), source("main.js")]);
  assert.equal(html.includes('id="mining-hashrate"'), true, "missing local hashrate element");
  assert.equal(html.includes("Your hashrate"), true, "local hashrate must be labeled explicitly");
  assert.equal(html.includes('id="mining-network-hashrate"'), true, "missing network hashrate element");
  assert.equal(html.includes("Network hashrate"), true, "network hashrate must be labeled explicitly");
  assert.equal(js.includes('formatHashrate(value.hashrate_hps)'), true, "local renderer must use the local field");
  assert.equal(js.includes('formatHashrate(value.network_hashrate_hps)'), true, "network renderer must use the network field");
  for (const unit of ["H/s", "kH/s", "MH/s"]) {
    assert.equal(js.includes(`"${unit}"`), true, `missing readable ${unit} unit`);
  }
});

test("mining screen shows the DEPC range with a fail-closed placeholder", async () => {
  const [html, js] = await Promise.all([source("index.html"), source("main.js")]);
  assert.equal(html.includes('id="mining-estimated-value"'), true, "missing estimated value element");
  assert.equal(html.includes("Estimated production cost"), true, "missing estimated cost label");
  assert.equal(js.includes("value.estimated_production_cost_usd_per_dom"), true, "missing central estimate");
  assert.equal(js.includes("value.estimated_production_cost_low_usd_per_dom"), true, "missing low estimate");
  assert.equal(js.includes("value.estimated_production_cost_high_usd_per_dom"), true, "missing high estimate");
  assert.equal(js.includes("hasEstimatedRange"), true, "renderer must require the complete range");
  assert.equal(js.includes(': "—";'), true, "missing data must render a dash, never a fabricated number");
  // The value arrives computed from the Rust boundary. No DEPC constant,
  // basket cost or emission arithmetic may live in the frontend.
  for (const forbidden of ["0.07404071", "0.04231930", "0.09535797", "3.12e-9", "23760", "23_760"]) {
    assert.equal(js.includes(forbidden), false, `DEPC constant leaked into the frontend: ${forbidden}`);
  }
});

test("send flow presents the Core fee projection and fails closed without it", async () => {
  const [html, js] = await Promise.all([source("index.html"), source("main.js")]);
  assert.equal(html.includes('id="send-fee-summary"'), true, "missing fee summary element");
  assert.equal(js.includes('invoke("transaction_fee_estimate"'), true, "send flow must request the Core projection");
  assert.equal(js.includes("Network fee unavailable"), true, "missing projection must surface a reason");
  assert.equal(js.includes("the payment was not created"), true, "missing projection must abort the payment");
  assert.equal(js.includes("estimate.minimum_fee"), true, "the displayed fee must come from the Core projection");
  // Presentation only: the frontend must not recompute fee policy.
  for (const forbidden of ["fee_rate", "weight *", "* weight", "minimum_relay", "minimum_mempool"]) {
    assert.equal(js.includes(forbidden), false, `fee-policy arithmetic leaked into the frontend: ${forbidden}`);
  }
});

test("the estimated value never reaches transaction construction", async () => {
  const js = await source("main.js");
  const sendSection = js.slice(js.indexOf('byId("transaction-create")'));
  assert.equal(sendSection.includes("estimated_production_cost_usd_per_dom"), false, "DEPC is a mining-screen reference and must not touch the send flow");
});
