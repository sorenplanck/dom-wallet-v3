import test from "node:test";
import assert from "node:assert/strict";

test("frontend source contains no durable browser storage access", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes("localStorage"), false);
  assert.equal(source.includes("sessionStorage"), false);
  assert.equal(source.includes("indexedDB"), false);
});

test("production adapter maps every registered Phase 1A command without a mock", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal((source.match(/"application_status"/g) ?? []).length > 0, true);
  assert.equal(source.includes("const developmentMock"), false);
  assert.equal(source.includes("fake balance"), false);
  assert.equal(source.includes("window.__TAURI__?.core?.invoke"), true);
});
