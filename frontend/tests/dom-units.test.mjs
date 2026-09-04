import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { formatDomFromNoms, nomsFromDom } from "../status.js";

test("DOM text converts to exact integer noms without floating point", () => {
  assert.equal(nomsFromDom("1"), 100000000);
  assert.equal(nomsFromDom("10"), 1000000000);
  assert.notEqual(nomsFromDom("10"), 10);
  assert.equal(nomsFromDom("0.001"), 100000);
  assert.equal(nomsFromDom("0.00000001"), 1);
  assert.equal(nomsFromDom(" 1.5 "), 150000000);
  assert.equal(nomsFromDom("0.07"), 7000000);
  assert.equal(nomsFromDom("4.35"), 435000000);
  assert.equal(nomsFromDom("0.29"), 29000000);
  assert.equal(nomsFromDom("1.005"), 100500000);
  assert.equal(formatDomFromNoms(100000), "0.00100000 DOM");
});

test("invalid or unsafe DOM text is rejected", () => {
  for (const value of ["0.000000001", "0", "-1", "1.2.3", "abc", "", "1e8", "1,5"]) {
    assert.throws(() => nomsFromDom(value));
  }
});

test("monetary controls and command boundaries use DOM text", async () => {
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
  ]);

  assert.equal(html.includes("in noms"), false);
  assert.equal((html.match(/inputmode="decimal"/g) ?? []).length, 4);
  assert.equal(js.includes("integerNoms"), false);
  assert.equal(js.includes('integerHeight(data.get("amount"))'), false);
  assert.equal(js.includes('integerHeight(data.get("requested_fee"))'), false);
  assert.equal(js.includes('integerHeight(data.get("minimum_output"))'), false);
  assert.equal(js.includes("noms ("), false);
  assert.equal(js.includes("ATTENTION: this spends more than 10% of your spendable balance."), true);
});
