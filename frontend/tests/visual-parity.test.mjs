import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const source = async (name) => readFile(new URL(name, root), "utf8");

test("DOM visual shell preserves all thirteen Wallet journeys", async () => {
  const html = await source("index.html");
  for (const screen of ["access", "welcome", "create", "restore", "locate", "unlock", "dashboard", "send", "receive", "history", "node", "backup", "settings"]) {
    assert.equal(html.includes(`data-screen-contract="${screen}"`), true, `missing ${screen}`);
  }
  assert.equal(html.includes("remote HTTP endpoint"), false);
  assert.equal(html.includes("Embedded node settings"), true);
});

test("production protocol and secret boundaries are explicit", async () => {
  const [html, js] = await Promise.all([source("index.html"), source("main.js")]);
  for (const command of ["embedded_node_start", "wallet_address_validate", "transaction_reconcile_submission"]) assert.equal(js.includes(`"${command}"`), true);
  assert.equal(js.includes("DOMSLATE4."), true);
  assert.equal(js.includes("integerNoms"), true);
  assert.equal(html.includes("recovery-confirm-password"), true);
  assert.equal(html.includes("endpoint_url"), false);
});

test("DOM visual tokens preserve the validated dark bronze desktop geometry", async () => {
  const css = await source("styles.css");
  for (const token of ["--bg-0:#0c0807", "--bronze-3:#c89a63", "width:220px", "max-width:880px", "width:120px", "border-radius:var(--radius)"]) {
    assert.equal(css.includes(token), true, `missing visual token ${token}`);
  }
  assert.equal(css.includes("@media (max-width:700px)"), true);
  assert.equal(css.includes(":focus-visible"), true);
});

test("presentation adapter does not create browser persistence or a second lifecycle", async () => {
  const js = await source("main.js");
  for (const forbidden of ["localStorage", "sessionStorage", "indexedDB", "fetch(", "eval(", "new Function"]) assert.equal(js.includes(forbidden), false);
  assert.equal(js.includes("window.__TAURI__?.core?.invoke"), true);
  assert.equal(js.includes("enterApp"), true);
  assert.equal(js.includes("enterGate"), true);
});
