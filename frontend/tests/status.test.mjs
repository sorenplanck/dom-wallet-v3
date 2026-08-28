import test from "node:test";
import assert from "node:assert/strict";
import {
  formatDomFromNoms,
  liveStatusProjection,
  miningPresentation,
  nodeStatusText,
  restoreReadinessPresentation,
  synchronizationPresentation,
} from "../status.js";

test("frontend source contains no durable browser storage access", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes("localStorage"), false);
  assert.equal(source.includes("sessionStorage"), false);
  assert.equal(source.includes("indexedDB"), false);
});

test("dashboard refreshes live IBD progress every fifteen seconds", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes('invoke("embedded_node_status")'), true);
  assert.equal(source.includes("liveStatusProjection(summary, node, network, peers, synchronization)"), true);
  assert.equal(source.includes("let latestEmbeddedNodeStatus;"), true);
  assert.equal(source.includes(": latestEmbeddedNodeStatus;"), true);
  assert.equal(source.includes(": [refreshSummary(), refreshNode(), refreshMining()]"), true);
  assert.equal(source.includes("? [refreshOnboardingNode()]"), true);
  assert.equal(source.includes("await Promise.allSettled(tasks)"), true);
  assert.equal(source.includes("setTimeout(refresh, gateVisible ? 5000 : 15000)"), true);
});

test("dashboard badge cannot report READY while a peer is ahead", () => {
  const result = synchronizationPresentation(
    { canonical_height: 1_008 },
    { highest_known_peer_height: 6_684 },
    { synchronized: false, cursor_height: 1_008, last_error: null },
  );
  assert.deepEqual(result, {
    badgeState: "SYNCHRONIZING",
    message: "Synchronizing 1008 / 6684 (15%)",
    localHeight: 1_008,
    peerHeight: 6_684,
    progress: 15,
  });
});

test("dashboard reports READY only when canonical height and cursor are synchronized", () => {
  const result = synchronizationPresentation(
    { canonical_height: 6_684 },
    { highest_known_peer_height: 6_684 },
    { synchronized: true, cursor_height: 6_684, last_error: null },
  );
  assert.equal(result.badgeState, "READY");
  assert.equal(result.message, "Wallet synchronized at height 6684");
});

test("dashboard exposes a synchronization error instead of READY", () => {
  const result = synchronizationPresentation(
    { canonical_height: 20 },
    { highest_known_peer_height: 20 },
    { synchronized: false, cursor_height: 19, last_error: "CURSOR_HASH_MISMATCH" },
  );
  assert.equal(result.badgeState, "ATTENTION");
  assert.equal(result.message, "CURSOR_HASH_MISMATCH");
});

test("dashboard preserves live node identity when peer or wallet status is transiently unavailable", () => {
  const result = liveStatusProjection(
    { cursor_height: 0 },
    {
      canonical_tip_height: 1,
      connected_peers: 1,
      highest_known_peer_height: 6_706,
      chain_id: "chain",
      genesis_hash: "genesis",
      bootstrap_phase: "CONNECTED",
    },
    undefined,
    undefined,
    undefined,
  );
  assert.equal(result.chainId, "chain");
  assert.equal(result.genesisHash, "genesis");
  assert.equal(result.canonicalHeight, 1);
  assert.equal(result.connectedPeers, 1);
  assert.equal(result.badgeState, "SYNCHRONIZING");
  assert.equal(result.message, "Synchronizing 1 / 6706 (0%)");
});

test("mining controls remain disabled until the real node is ready", () => {
  const result = miningPresentation(
    { status: "READY", enabled: true, running: false, current_height: 0 },
    { lifecycle: "SYNCHRONIZING", ready: false, status_message: "Synchronizing 0 / 6684 (0%)" },
  );
  assert.deepEqual(result, {
    status: "SYNCHRONIZING",
    canStart: false,
    warning: "Synchronizing 0 / 6684 (0%)",
  });
});

test("node status text exposes live heights and progress", () => {
  const text = nodeStatusText({
    status_message: "Synchronizing 1008 / 6684 (15%)",
    lifecycle: "SYNCHRONIZING",
    network: "MAINNET",
    canonical_tip_height: 1_008,
    highest_known_peer_height: 6_684,
    synchronization_progress_percent: 15,
    connected_peers: 1,
    bootstrap_phase: "CONNECTED",
    canonical_tip_hash: "abcd",
    error_code: null,
  });
  assert.match(text, /Local height: 1008/);
  assert.match(text, /Highest peer height: 6684/);
  assert.match(text, /Synchronization: 15%/);
  assert.doesNotMatch(text, /CORE_NOT_READY/);
});

test("onboarding restore gate exposes live Mainnet synchronization and unlocks only at tip", () => {
  assert.deepEqual(
    restoreReadinessPresentation({
      network: "MAINNET",
      lifecycle: "READY",
      ready: true,
      canonical_tip_height: 5_241,
      highest_known_peer_height: 0,
      connected_peers: 0,
    }),
    {
      ready: false,
      badge: "DISCOVERING",
      message: "Discovering Mainnet peers at local height 5241.",
      localHeight: 5_241,
      peerHeight: null,
      connectedPeers: 0,
      progress: 0,
    },
  );

  const syncing = restoreReadinessPresentation({
    network: "MAINNET",
    lifecycle: "SYNCHRONIZING",
    ready: false,
    canonical_tip_height: 5_241,
    highest_known_peer_height: 8_009,
    connected_peers: 2,
  });
  assert.equal(syncing.ready, false);
  assert.equal(syncing.badge, "SYNCHRONIZING");
  assert.equal(syncing.message, "Synchronizing 5241 / 8009 (65%).");

  const ready = restoreReadinessPresentation({
    network: "MAINNET",
    lifecycle: "READY",
    ready: true,
    canonical_tip_height: 8_009,
    highest_known_peer_height: 8_009,
    connected_peers: 2,
  });
  assert.equal(ready.ready, true);
  assert.equal(ready.badge, "READY");
  assert.equal(ready.progress, 100);
});

test("DOM balances use the canonical 100,000,000 noms denomination", () => {
  assert.equal(formatDomFromNoms(0), "0.00000000 DOM");
  assert.equal(formatDomFromNoms(100_000_000), "1.00000000 DOM");
  assert.equal(formatDomFromNoms(3_300_000_000), "33.00000000 DOM");
  assert.equal(formatDomFromNoms(Number.MAX_SAFE_INTEGER + 1), "Unavailable");
});

test("settings expose separate fail-closed Wallet and node update states", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
  ]);
  for (const marker of [
    "update-wallet-state",
    "update-node-state",
    "update-peer-state",
    "update-signing-state",
    "Check node now",
  ]) assert.equal(html.includes(marker), true);
  assert.equal(js.includes('"Scheduled · signing unavailable"'), true);
  for (const command of [
    '"get_build_info"',
    '"update_status"',
    '"check_updates_now"',
    '"check_node_now"',
  ]) assert.equal(js.includes(command), true);
  assert.equal(js.includes("localStorage"), false);
  assert.equal(js.includes("sessionStorage"), false);
});

test("production adapter maps each recovery and backup command without a mock", async () => {
  const { readFile } = await import("node:fs/promises");
  const [source, bridge] = await Promise.all([
    readFile(new URL("../main.js", import.meta.url), "utf8"),
    readFile(new URL("../bridge.js", import.meta.url), "utf8"),
  ]);
  assert.equal((source.match(/"application_status"/g) ?? []).length > 0, true);
  assert.equal(source.includes("const developmentMock"), false);
  assert.equal(source.includes("fake balance"), false);
  assert.equal(source.includes("window.__TAURI__"), false);
  assert.equal(bridge.includes('@tauri-apps/api/core'), true);
  assert.equal(bridge.includes("window.__TAURI__"), false);
  for (const command of [
    "wallet_create_recoverable", "wallet_recovery_phrase_confirm",
    "wallet_restore_from_mnemonic", "wallet_backup_export", "wallet_backup_import"
  ]) assert.equal(source.includes(`"${command}"`), true);
});

test("recovery and backup inputs are transient and use no browser persistence", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8")
  ]);
  for (const id of [
    "restore-form", "restore-submit", "onboarding-node-message", "onboarding-node-progress",
    "backup-export-form", "backup-import-form", "recovery-ceremony"
  ]) assert.equal(html.includes(`id="${id}"`), true);
  assert.equal(html.includes('name="mnemonic"'), true);
  assert.equal(js.includes("clearPhrase"), true);
  assert.equal(js.includes("textarea[name=\"mnemonic\"]"), true);
  assert.equal(js.includes('byId("restore-submit").disabled = !presentation.ready'), true);
  assert.equal(js.includes('invoke("embedded_node_status")'), true);
  assert.equal(js.includes("localStorage"), false);
});

test("manual slate controls use only the production invoke adapter and clear pasted text", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  for (const command of [
    "transaction_fee_estimate", "transaction_send_create", "slate_request_export",
    "slate_request_import", "slate_response_create", "slate_response_export",
    "slate_response_import", "slate_summary_redacted", "transaction_finalize",
    "transaction_submit", "transaction_retry_submission", "transaction_reconcile_submission", "transaction_cancel",
    "transaction_list", "transaction_detail_redacted"
  ]) assert.equal(source.includes(`"${command}"`), true);
  assert.equal(source.includes("clearSecretForms"), true);
  assert.equal(source.includes("/wallet/spend"), false);
});

test("QR exchange stays local, uses canonical native frames, and releases camera state", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  for (const command of ["slate_qr_encode", "slate_qr_decode_frame", "slate_qr_reassembly_status", "slate_qr_reassembly_clear"]) {
    assert.equal(source.includes(`"${command}"`), true);
  }
  assert.equal(source.includes("QrScanner"), true);
  assert.equal(source.includes("stopScanner"), true);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("localStorage"), false);
});
