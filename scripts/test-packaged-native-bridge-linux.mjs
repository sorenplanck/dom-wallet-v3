#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";

const binary = process.argv[2] ? resolve(process.argv[2]) : undefined;
if (!binary) throw new Error("usage: test-packaged-native-bridge-linux.mjs <packaged-binary>");
if (!process.env.DISPLAY) throw new Error("DISPLAY is required (use xvfb-run in CI)");

const port = 9515 + (process.pid % 1000);
const endpoint = `http://127.0.0.1:${port}`;
const profile = await mkdtemp(`${tmpdir()}/dom-wallet-bridge-e2e-`);
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
  assert.deepEqual(probe, { bridge: "ready", app_version: "0.1.1" });

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

  process.stdout.write(`${JSON.stringify({
    packagedBinary: basename(binary),
    bridge: probe,
    runtime,
    actions: Object.fromEntries(Object.entries(actions).map(([name, value]) => [name, value.reachedNative])),
  }, null, 2)}\n`);
} finally {
  if (sessionId) await request(`/session/${sessionId}`, undefined, { method: "DELETE" }).catch(() => {});
  driver.kill("SIGTERM");
  await new Promise((done) => setTimeout(done, 250));
  if (!driver.killed) driver.kill("SIGKILL");
  await rm(profile, { recursive: true, force: true });
}
