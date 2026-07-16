import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("release workflow provides pinned experimental dry-run packaging", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/release-wallet.yml", import.meta.url), "utf8");
  for (const required of [
    "wallet-v*", "workflow_dispatch", "publish_release", "default: false",
    "ubuntu-24.04", "windows-2022", "macos-14", "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc", "aarch64-apple-darwin", "appimage,deb,rpm",
    "nsis,msi", "dmg,app", "npm test --prefix frontend", "cargo metadata --locked",
    "--locked", "cargo audit", "cargo deny check", "actionlint_1.7.7_linux_amd64.tar.gz",
    "SHA256SUMS", "needs: [validate, package]", "contents: write",
    "git rev-parse \"${GITHUB_REF}^{commit}\"", "DOM initially has no monetary value",
    "Do not use real funds", "experimental software", "Installers are unsigned",
    "--prerelease", "DOM Wallet V3 ${GITHUB_REF_NAME#wallet-v} Experimental",
    "24-word BIP-39 phrase", "Confirmed Recovery Capsule v1 funds are recoverable",
    "backup remains additional", "No independent security audit is claimed",
    "release-upload/SHA256SUMS.txt",
    "target/${{ matrix.target }}/release/bundle",
    "Install Linux validation dependencies",
  ]) assert.equal(workflow.includes(required), true, `missing ${required}`);

  const actionRefs = [...workflow.matchAll(/uses:\s+[^@\s]+@([^\s]+)/g)].map((match) => match[1]);
  assert.ok(actionRefs.length >= 10);
  assert.equal(actionRefs.every((ref) => /^[0-9a-f]{40}$/.test(ref)), true);
  assert.equal(workflow.includes("github.event_name == 'push' && startsWith(github.ref, 'refs/tags/wallet-v')"), true);
  assert.equal(workflow.includes("release: published"), false);
  assert.equal(workflow.includes("release: created"), false);
  assert.equal(workflow.includes("/home/"), false);
  assert.equal(workflow.includes("dom-wallet-v1"), false);
  assert.equal(workflow.includes("dom-wallet-v2"), false);
});

test("Tauri resolves the frontend build from the workspace root", async () => {
  const config = JSON.parse(await readFile(new URL("../../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.equal(config.build.beforeBuildCommand, "npm --prefix frontend run build");
  assert.equal(config.build.frontendDist, "../frontend/dist");
  assert.deepEqual(config.bundle.icon, ["../frontend/assets/dom-coin.png"]);
});
