import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../main.js", import.meta.url), "utf8");
const declaration = source.match(/export const redactedError = \(error\) => \{[\s\S]*?\n\};/);
assert.ok(declaration, "main.js must export the error presentation boundary");
const redactedError = Function(
  `${declaration[0].replace("export const", "const")}\nreturn redactedError;`,
)();

test("redacted errors append the typed code to a safe message", () => {
  assert.equal(
    redactedError({ message: "Wallet state changed; retrying.", code: "WALLET_STORAGE_GENERATION_CONFLICT" }),
    "Wallet state changed; retrying. (WALLET_STORAGE_GENERATION_CONFLICT)",
  );
  assert.equal(redactedError({ message: "Wallet is locked." }), "Wallet is locked.");
});

test("redacted errors keep the complete secret filter", () => {
  for (const secret of [
    "password",
    "mnemonic",
    "seed",
    "secret",
    "key",
    "token",
    "credential",
    "https://private.example",
  ]) {
    const rendered = redactedError({
      message: `Do not expose ${secret}`,
      code: "SAFE_TYPED_CODE",
    });
    assert.equal(rendered, "Operation rejected (SAFE_TYPED_CODE).");
    assert.equal(rendered.includes(secret), false);
  }
});
