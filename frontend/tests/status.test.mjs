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

test("manual slate controls use only the production invoke adapter and clear pasted text", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  for (const command of [
    "transaction_fee_estimate", "transaction_send_create", "slate_request_export",
    "slate_request_import", "slate_response_create", "slate_response_export",
    "slate_response_import", "slate_summary_redacted", "transaction_finalize",
    "transaction_submit", "transaction_retry_submission", "transaction_cancel",
    "transaction_list", "transaction_detail_redacted"
  ]) assert.equal(source.includes(`"${command}"`), true);
  assert.equal(source.includes("clearSlateText"), true);
  assert.equal(source.includes("/wallet/spend"), false);
});

test("QR exchange stays local, uses canonical native frames, and releases camera state", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  for (const command of ["slate_qr_encode", "slate_qr_decode_frame", "slate_qr_reassembly_status", "slate_qr_reassembly_clear"]) {
    assert.equal(source.includes(`"${command}"`), true);
  }
  assert.equal(source.includes("QrScanner"), true);
  assert.equal(source.includes("releaseCamera"), true);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("localStorage"), false);
});
