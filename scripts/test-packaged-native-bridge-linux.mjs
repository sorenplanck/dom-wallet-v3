#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";

const binary = process.argv[2] ? resolve(process.argv[2]) : undefined;
if (!binary) throw new Error("usage: test-packaged-native-bridge-linux.mjs <packaged-binary>");
if (!process.env.DISPLAY) throw new Error("DISPLAY is required (use xvfb-run in CI)");

const port = 9515 + (process.pid % 1000);
const endpoint = `http://127.0.0.1:${port}`;
const profile = await mkdtemp(`${tmpdir()}/dom-wallet-bridge-e2e-`);
if (process.env.PACKAGED_NODE_FIXTURE) {
  await cp(
    resolve(process.env.PACKAGED_NODE_FIXTURE),
    `${profile}/data/org.domprotocol.wallet.v3/mainnet/node`,
    { recursive: true },
  );
}
const driverPath = process.env.WEBKIT_WEBDRIVER
  ? `${dirname(process.env.WEBKIT_WEBDRIVER)}:${process.env.PATH}`
  : process.env.PATH;
const driver = spawn(process.env.TAURI_DRIVER ?? "tauri-driver", [`--port=${port}`, `--native-port=${port + 1}`], {
  env: {
    ...process.env,
    HOME: profile,
    XDG_CONFIG_HOME: `${profile}/config`,
    XDG_DATA_HOME: `${profile}/data`,
    XDG_CACHE_HOME: `${profile}/cache`,
    TAURI_WEBVIEW_AUTOMATION: "true",
    RUST_BACKTRACE: "1",
    RUST_LOG: "info",
    PATH: driverPath,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let driverOutput = "";
driver.stdout.on("data", (chunk) => { driverOutput += chunk; });
driver.stderr.on("data", (chunk) => { driverOutput += chunk; });

const request = async (path, body, options = {}) => {
  const response = await fetch(`${endpoint}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    ...options,
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`WebDriver ${response.status}: ${JSON.stringify(result)}`);
  return result.value;
};

const waitForDriver = async () => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (driver.exitCode !== null) throw new Error(`tauri-driver exited early: ${driverOutput}`);
    try { await request("/status"); return; } catch { await new Promise((done) => setTimeout(done, 100)); }
  }
  throw new Error(`WebKitWebDriver did not start: ${driverOutput}`);
};

let sessionId;
try {
  await waitForDriver();
  const created = await request("/session", {
    capabilities: { alwaysMatch: { "tauri:options": { application: binary } } },
  });
  sessionId = created.sessionId ?? created.capabilities?.sessionId;
  if (!sessionId) {
    const sessions = await request("/sessions");
    sessionId = sessions?.at(-1)?.id;
  }
  assert.ok(sessionId, "WebDriver session was not created");

  const execute = (script, args = []) => request(`/session/${sessionId}/execute/sync`, { script, args });
  const screenshotDirectory = process.env.PACKAGED_SCREENSHOT_DIR
    ? resolve(process.env.PACKAGED_SCREENSHOT_DIR)
    : undefined;
  const screenshot = async (name) => {
    if (!screenshotDirectory) return;
    await mkdir(screenshotDirectory, { recursive: true });
    const encoded = await request(`/session/${sessionId}/screenshot`);
    await writeFile(`${screenshotDirectory}/${name}.png`, Buffer.from(encoded, "base64"));
  };
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const ready = await execute("return document.readyState === 'complete' && document.documentElement.dataset.nativeBridge === 'READY'").catch(() => false);
    if (ready) break;
    if (attempt === 199) throw new Error("packaged bridge did not reach READY");
    await new Promise((done) => setTimeout(done, 100));
  }

  const runtime = await execute(`return {
    title: document.title,
    status: document.getElementById("status")?.textContent,
    bridgeState: document.documentElement.dataset.nativeBridge,
    globalTauri: typeof window.__TAURI__,
    internals: typeof window.__TAURI_INTERNALS__
  }`);
  assert.equal(runtime.bridgeState, "READY");
  assert.equal(runtime.globalTauri, "undefined");
  assert.equal(runtime.internals, "object");
  assert.match(runtime.status, /^Application state:/);
  assert.doesNotMatch(runtime.status, /Native desktop command bridge is unavailable/i);
  await screenshot("initial-bridge-ready");

  const probe = await execute("return window.__TAURI_INTERNALS__.invoke('native_bridge_status')");
  assert.deepEqual(probe, { bridge: "ready", app_version: "0.2.0" });

  const nativeResult = async (command, args) => execute(`
    return window.__TAURI_INTERNALS__.invoke(arguments[0], arguments[1])
      .then((value) => ({ reachedNative: true, ok: true, value }))
      .catch((error) => ({ reachedNative: true, ok: false, error }));
  `, [command, args]);
  const actions = {
    create: await nativeResult("wallet_create_recoverable", { path: "", password: "" }),
    restore: await nativeResult("wallet_restore_from_mnemonic", { path: "", password: "", mnemonic: "" }),
    locate: await nativeResult("wallet_open", { path: `${profile}/missing-wallet` }),
    unlock: await nativeResult("wallet_unlock", { password: "" }),
  };
  for (const [name, result] of Object.entries(actions)) {
    assert.equal(result.reachedNative, true, `${name} did not reach native IPC`);
    assert.equal(result.ok, false, `${name} unexpectedly accepted invalid test input`);
    assert.notEqual(result.error, undefined, `${name} did not return a native domain error`);
    assert.doesNotMatch(JSON.stringify(result.error), /Native desktop command bridge is unavailable/i);
  }

  const unlockResponse = await execute(`
    const form = document.getElementById("unlock-form");
    form.querySelector('input[name="password"]').value = "invalid-test-only";
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const value = document.getElementById("status").textContent;
        if (!value.startsWith("Application state:")) return resolve(value);
        if (attempts++ > 100) return reject(new Error("unlock UI did not receive a native response"));
        setTimeout(poll, 50);
      };
      poll();
    });
  `);
  assert.doesNotMatch(unlockResponse, /Native desktop command bridge is unavailable/i);
  await screenshot("unlock-native-response");

  const panels = await execute(`
    const result = {};
    for (const [name, panel] of [["create", "create-form"], ["restore", "restore-form"], ["locate", "open-form"]]) {
      document.querySelector('[data-gate-panel="' + panel + '"]').click();
      result[name] = !document.getElementById(panel).hidden;
    }
    return result;
  `);
  assert.deepEqual(panels, { create: true, restore: true, locate: true });

  const walletPath = `${profile}/wallet`;
  const testPassword = "packaged-mainnet-test-only";
  await execute(`
    document.querySelector('[data-gate-panel="create-form"]').click();
    const form = document.getElementById("create-form");
    form.querySelector('input[name="path"]').value = arguments[0];
    form.querySelector('input[name="password"]').value = arguments[1];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const ceremony = document.getElementById("recovery-ceremony");
        if (!ceremony.hidden && document.getElementById("recovery-phrase").textContent.trim()) return resolve(true);
        if (attempts++ > 1_000) return reject(new Error("wallet creation did not reach recovery confirmation"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [walletPath, testPassword]);

  await execute(`
    const confirmed = document.getElementById("recovery-confirmed");
    confirmed.checked = true;
    confirmed.dispatchEvent(new Event("change", { bubbles: true }));
    document.getElementById("recovery-confirm-password").value = arguments[0];
    document.getElementById("recovery-complete").click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const value = document.getElementById("status").textContent;
        if (/Recovery phrase confirmed/i.test(value)) return resolve(value);
        if (attempts++ > 300) return reject(new Error("recovery confirmation did not complete"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [testPassword]);
  const phraseCleared = await execute("return document.getElementById('recovery-phrase').textContent === ''");
  assert.equal(phraseCleared, true, "recovery phrase remained in the DOM after confirmation");

  await execute(`
    const form = document.getElementById("unlock-form");
    form.querySelector('input[name="password"]').value = arguments[0];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        if (!document.getElementById("app").classList.contains("hidden")) return resolve(true);
        if (attempts++ > 300) return reject(new Error("packaged wallet did not unlock"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [testPassword]);

  const productSurface = await execute(`return {
    networkSelectors: document.querySelectorAll('[name="network"], [name="chain"], [name="node_data"], [name="listen_address"], [name="remote_endpoint"], [name="server_address"], [name="seed"], [name="port"], [name="backend"]').length,
    miningPage: Boolean(document.querySelector('[data-screen="mining"]') && document.getElementById("mining")),
    senderAddressFields: document.querySelectorAll('[name="sender_address"], #sender-address').length,
    receiverAddressFields: document.querySelectorAll('[name="receiver_address"], #receiver-address').length,
    slateV4: document.getElementById("transactions").textContent.includes("Slate v4"),
    settingsMainnet: document.getElementById("diagnostics").textContent.includes("Mainnet")
  }`);
  assert.deepEqual(productSurface, {
    networkSelectors: 0,
    miningPage: true,
    senderAddressFields: 0,
    receiverAddressFields: 0,
    slateV4: true,
    settingsMainnet: true,
  });

  let peerStatus;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const result = await nativeResult("node_peer_status", {});
    if (!result.ok) throw new Error("packaged peer diagnostics failed");
    peerStatus = result.value;
    if (peerStatus.total_connected_peers > 0) break;
    await new Promise((done) => setTimeout(done, 500));
  }
  assert.ok(peerStatus.total_connected_peers > 0, "packaged node did not register a Mainnet peer");

  const networkStatus = await nativeResult("node_network_status", {});
  if (!networkStatus.ok) throw new Error("packaged network diagnostics failed");
  assert.equal(networkStatus.value.network, "MAINNET");
  assert.ok(
    Number.isSafeInteger(networkStatus.value.canonical_height)
      && networkStatus.value.canonical_height >= 0,
    "packaged node returned an invalid Mainnet tip",
  );
  let syncStatus;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const syncStart = await nativeResult("wallet_sync_start", {});
    if (!syncStart.ok && syncStart.error?.code !== "EMBEDDED_NODE_NOT_READY") {
      throw new Error(`packaged missing-cursor synchronization failed: ${JSON.stringify(syncStart.error)}`);
    }
    syncStatus = await nativeResult("wallet_sync_status", {});
    if (!syncStatus.ok) throw new Error("packaged synchronization diagnostics failed");
    if (syncStatus.value.synchronized) break;
    await new Promise((done) => setTimeout(done, 500));
  }
  assert.ok(syncStatus, "packaged synchronization status was not observed");
  assert.equal(syncStatus.value.synchronized, true);
  assert.equal(syncStatus.value.cursor_height, syncStatus.value.canonical_height);
  assert.equal(syncStatus.value.state, "READY");
  assert.equal(syncStatus.value.last_error, null);

  const miningConfig = await nativeResult("mining_config_get", {});
  if (!miningConfig.ok) throw new Error("packaged mining configuration failed");
  const enabledMining = await nativeResult("mining_config_set", {
    enabled: true,
    cpuThreads: miningConfig.value.cpu_threads,
  });
  if (!enabledMining.ok) throw new Error("packaged mining controls remained blocked by the cursor");
  const miningStatus = await nativeResult("mining_status", {});
  if (!miningStatus.ok) throw new Error("packaged mining diagnostics failed");
  assert.equal(miningStatus.value.status, "READY");
  assert.equal(miningStatus.value.enabled, true);
  assert.equal(miningStatus.value.running, false);
  assert.equal(miningStatus.value.hash_attempts, 0);
  assert.equal(miningStatus.value.accepted_blocks, 0);
  const unconfirmedStart = await nativeResult("mining_start", { confirmed: false });
  assert.equal(unconfirmedStart.ok, false);
  assert.equal(unconfirmedStart.error.code, "MINING_CONFIRMATION_REQUIRED");
  const stoppedMining = await nativeResult("mining_stop", {});
  if (!stoppedMining.ok) throw new Error("packaged mining stop control failed");
  assert.equal(stoppedMining.value.running, false);
  assert.equal(stoppedMining.value.hash_attempts, 0);
  // Shutdown closes the native webview, so WebDriver may correctly lose the
  // session before it can deliver the command reply.
  await nativeResult("application_shutdown", {}).catch(() => undefined);

  process.stdout.write(`${JSON.stringify({
    packagedBinary: basename(binary),
    bridge: probe,
    runtime,
    actions: Object.fromEntries(Object.entries(actions).map(([name, value]) => [name, value.reachedNative])),
    productSurface,
    mainnet: {
      connectedPeers: peerStatus.total_connected_peers,
      bootstrapPhase: peerStatus.bootstrap_phase,
      canonicalHeight: syncStatus.value.canonical_height,
      cursorHeight: syncStatus.value.cursor_height,
      synchronized: syncStatus.value.synchronized,
      applicationState: syncStatus.value.state,
      lastError: syncStatus.value.last_error,
    },
    mining: {
      status: miningStatus.value.status,
      running: miningStatus.value.running,
      hashAttempts: miningStatus.value.hash_attempts,
      acceptedBlocks: miningStatus.value.accepted_blocks,
    },
  }, null, 2)}\n`);
} finally {
  if (sessionId) await request(`/session/${sessionId}`, undefined, { method: "DELETE" }).catch(() => {});
  driver.kill("SIGTERM");
  await Promise.race([
    new Promise((done) => driver.once("exit", done)),
    new Promise((done) => setTimeout(done, 2_000)),
  ]);
  if (driver.exitCode === null) {
    driver.kill("SIGKILL");
    await new Promise((done) => driver.once("exit", done));
  }
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
