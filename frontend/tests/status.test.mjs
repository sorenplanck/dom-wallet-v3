import test from "node:test";
import assert from "node:assert/strict";

test("frontend source contains no durable browser storage access", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes("localStorage"), false);
  assert.equal(source.includes("sessionStorage"), false);
});
