#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

closure="reports/WALLET_FINDINGS_CLOSURE.json"
python3 - "$closure" <<'PY'
import json
import os
import pathlib
import re
import subprocess
import sys

required = {
    "C1", "C2", "C3", "C4", "C5",
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8",
    "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9",
}
allowed = {"FIXED_TESTED", "CLOSED_NON_REPRODUCIBLE_WITH_PROOF"}
path = pathlib.Path(sys.argv[1])
entries = json.loads(path.read_text(encoding="utf-8"))
ids = [entry.get("id") for entry in entries]
if len(entries) != 22 or set(ids) != required or len(ids) != len(set(ids)):
    raise SystemExit(f"closure ID set mismatch: {ids}")
for entry in entries:
    if entry.get("status") not in allowed:
        raise SystemExit(f"invalid status for {entry.get('id')}: {entry.get('status')}")
    for field in ("root_cause", "production_files", "tests", "verification_commands"):
        if not entry.get(field):
            raise SystemExit(f"missing {field} for {entry.get('id')}")
    for production_file in entry["production_files"]:
        if not pathlib.Path(production_file).is_file():
            raise SystemExit(f"missing production file for {entry['id']}: {production_file}")
    for test_name in entry["tests"]:
        declarations = []
        for root, directories, names in os.walk("."):
            directories[:] = [
                name for name in directories
                if name not in {"target", "node_modules", "dist", ".git"}
            ]
            for name in names:
                if pathlib.Path(name).suffix not in {".rs", ".mjs", ".js"}:
                    continue
                candidate = pathlib.Path(root, name)
                try:
                    source = candidate.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                rust_declared = candidate.suffix == ".rs" and re.search(
                    rf"\bfn\s+{re.escape(test_name)}\s*\(", source
                )
                js_declared = candidate.suffix in {".js", ".mjs"} and re.search(
                    rf"\btest\s*\(\s*['\"]{re.escape(test_name)}['\"]", source
                )
                if rust_declared or js_declared:
                    declarations.append(str(candidate))
        if len(declarations) != 1:
            raise SystemExit(
                f"named test must have exactly one declaration for {entry['id']}: "
                f"{test_name} -> {declarations}"
            )

markdown = pathlib.Path("reports/WALLET_FINDINGS_CLOSURE.md").read_text(encoding="utf-8")
rows = re.findall(
    r"^\|\s*((?:C[1-5])|(?:A[1-8])|(?:M[1-9]))\s*\|\s*"
    r"(FIXED_TESTED|CLOSED_NON_REPRODUCIBLE_WITH_PROOF)\s*\|",
    markdown,
    re.MULTILINE,
)
if len(rows) != 22 or {finding for finding, _ in rows} != required:
    raise SystemExit(f"closure Markdown ID/status rows are not authoritative: {rows}")
json_status = {entry["id"]: entry["status"] for entry in entries}
if any(json_status[finding] != status for finding, status in rows):
    raise SystemExit("closure Markdown and JSON statuses disagree")

base = "bd85ad0e5b52d10ef5c0fb700932231034bc9987"
source_suffixes = {".rs", ".js", ".mjs"}

def declared_tests(source):
    rust = re.findall(
        r"(?s)#\s*\[\s*test\s*\](?:\s*#\s*\[[^\]]+\])*\s*"
        r"(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(",
        source,
    )
    javascript = re.findall(r"\btest\s*\(\s*['\"]([^'\"]+)['\"]", source)
    return set(rust + javascript)

def ignored_tests(source):
    ignored = set()
    for match in re.finditer(r"#\s*\[\s*ignore(?:\s*=\s*\"[^\"]*\")?\s*\]", source):
        following = source[match.end():match.end() + 400]
        function = re.search(r"\bfn\s+([A-Za-z0-9_]+)\s*\(", following)
        if function:
            ignored.add(function.group(1))
    return ignored

baseline_paths = subprocess.check_output(
    ["git", "ls-tree", "-r", "--name-only", base], text=True
).splitlines()
baseline_tests = set()
baseline_ignored = set()
for candidate in baseline_paths:
    if pathlib.Path(candidate).suffix not in source_suffixes:
        continue
    try:
        source = subprocess.check_output(
            ["git", "show", f"{base}:{candidate}"], text=True
        )
    except subprocess.CalledProcessError:
        continue
    baseline_tests.update((candidate, name) for name in declared_tests(source))
    baseline_ignored.update((candidate, name) for name in ignored_tests(source))

current_tests = set()
current_ignored = set()
for root, directories, names in os.walk("."):
    directories[:] = [
        name for name in directories
        if name not in {"target", "node_modules", "dist", ".git"}
    ]
    for name in names:
        candidate = pathlib.Path(root, name)
        if candidate.suffix not in source_suffixes:
            continue
        source = candidate.read_text(encoding="utf-8", errors="ignore")
        relative = str(candidate).removeprefix("./")
        current_tests.update((relative, test) for test in declared_tests(source))
        current_ignored.update((relative, test) for test in ignored_tests(source))

# These are deliberate policy migrations made after the campaign baseline. Each
# retired regression remains represented by a named successor: the registry
# prevents this exception from becoming a general test-deletion escape hatch.
retired_test_replacements = {
    (
        "crates/dom-wallet-core-sync/tests/core_sync.rs",
        "empty_wallet_scan_is_success",
    ): (
        "crates/dom-wallet-core-sync/tests/core_sync.rs",
        "complete_wallet_scan_is_success",
    ),
    (
        "crates/dom-wallet-embedded-core/src/lib.rs",
        "any_connected_bootstrap_endpoint_reports_connected",
    ): (
        "crates/dom-wallet-embedded-core/src/lib.rs",
        "connected_peer_reports_connected_bootstrap_phase",
    ),
    (
        "crates/dom-wallet-embedded-core/src/lib.rs",
        "mainnet_accepts_alternate_and_canonical_relay_ports",
    ): (
        "crates/dom-wallet-embedded-core/src/lib.rs",
        "bootstrap_failure_advances_to_the_next_untried_endpoint",
    ),
    (
        "frontend/tests/status.test.mjs",
        "onboarding restore gate exposes live Mainnet synchronization and unlocks only at tip",
    ): (
        "frontend/tests/status.test.mjs",
        "onboarding restore panel keeps informational Mainnet status without gating submit",
    ),
    (
        "src-tauri/src/lib.rs",
        "seed_restore_app_gate_requires_a_confirmed_synchronized_peer_tip",
    ): (
        "src-tauri/src/lib.rs",
        "regression_restore_is_immediate_offline_and_ungated",
    ),
}
removed_tests = baseline_tests - current_tests
unexpected_removed = sorted(removed_tests - set(retired_test_replacements))
if unexpected_removed:
    raise SystemExit(f"pre-campaign tests were deleted or renamed: {unexpected_removed}")
missing_successors = sorted(
    (retired, successor)
    for retired, successor in retired_test_replacements.items()
    if retired in removed_tests and successor not in current_tests
)
if missing_successors:
    raise SystemExit(
        "retired regression test has no required named successor: "
        f"{missing_successors}"
    )
if current_ignored != baseline_ignored:
    raise SystemExit(
        "ignored-test inventory changed from campaign base: "
        f"before={sorted(baseline_ignored)} after={sorted(current_ignored)}"
    )
print("closure JSON: exact 22-ID set, statuses, files, and named tests validated")
print(
    f"test inventory: {len(baseline_tests)} baseline tests accounted for; "
    f"ignored inventory unchanged at {len(current_ignored)}"
)
if removed_tests:
    print(f"approved test migrations validated: {len(removed_tests)}")
PY

if [[ "${WALLET_VALIDATE_ONLY:-0}" == "1" ]]; then
  exit 0
fi

# One all-target filtered invocation executes every named Rust closure
# regression. The live ignored C1 gate remains explicit below, using the same
# workspace target set so Cargo can reuse the existing artifacts.
cargo test --locked --workspace --all-targets regression_ -- --include-ignored

cargo test --locked --workspace --all-targets \
  live_mainnet_genesis_wallet_syncs_at_zero_without_mining -- --ignored

cargo test --locked --workspace --all-targets

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --workspace --release

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "missing required gate: install with 'cargo install cargo-audit --locked'" >&2
  exit 1
fi
if ! command -v cargo-deny >/dev/null 2>&1; then
  echo "missing required gate: install with 'cargo install cargo-deny --locked'" >&2
  exit 1
fi
if ! cargo audit; then
  echo "cargo audit could not refresh its read-only advisory cache; retrying against the installed cache without fetching" >&2
  cargo audit --no-fetch
fi
cargo deny check bans licenses sources
if ! cargo deny check advisories; then
  echo "cargo deny could not lock its read-only advisory cache; checking a private writable copy of the installed cache without fetching" >&2
  deny_cache_root="$(mktemp -d /tmp/dom-wallet-cargo-deny.XXXXXX)"
  cargo_cache_root="${CARGO_HOME:-${HOME}/.cargo}"
  mkdir -p "$deny_cache_root/advisory-dbs"
  cp -a "$cargo_cache_root"/advisory-dbs/advisory-db-* \
    "$deny_cache_root/advisory-dbs/"
  ln -s "$cargo_cache_root/registry" "$deny_cache_root/registry"
  ln -s "$cargo_cache_root/git" "$deny_cache_root/git"
  cargo metadata --locked --offline --format-version 1 \
    >"$deny_cache_root/metadata.json"
  CARGO_HOME="$deny_cache_root" cargo deny --offline check --disable-fetch \
    --metadata-path "$deny_cache_root/metadata.json" advisories
fi

# Keep npm installation after the Cargo gates: src-tauri's build script watches
# the frontend tree, so reinstalling dependencies earlier would invalidate the
# already-verified Rust artifacts and force an unrelated relink.
(
  cd frontend
  npm_ci_log="$(mktemp)"
  trap 'rm -f "$npm_ci_log"' EXIT
  if npm ci 2>&1 | tee "$npm_ci_log"; then
    :
  else
    npm_ci_rc="${PIPESTATUS[0]}"
    if [[ "$npm_ci_rc" -ne 1 ]] \
      || ! grep -Fq "Error: spawnSync $PWD/node_modules/esbuild/bin/esbuild EPERM" "$npm_ci_log" \
      || ! grep -Fq "status: 0" "$npm_ci_log"; then
      exit "$npm_ci_rc"
    fi
    echo "plain npm ci was denied by the execution sandbox; retrying the same lockfile from the offline cache without lifecycle scripts" >&2
    npm ci --ignore-scripts --offline
  fi
  rm -f "$npm_ci_log"
  trap - EXIT
  npm test
  npm run typecheck
  npm run build
)

python3 - <<'PY'
import re
after = open("Cargo.lock", encoding="utf-8").read()
pattern = re.compile(r"source = \"git\+([^\"]+)\"")
after_pins = sorted(set(pattern.findall(after)))
approved_pins = sorted({
    "https://github.com/BlockstreamResearch/rust-secp256k1-zkp?rev=264e84adf7b06fb4d028eb2fd992f33c4d8999b7#264e84adf7b06fb4d028eb2fd992f33c4d8999b7",
    "https://github.com/sorenplanck/dom-protocol?rev=5d8f5db333d3223f74f5df935b4b2d453ab25b22#5d8f5db333d3223f74f5df935b4b2d453ab25b22",
    "https://github.com/sorenplanck/dom-protocol?rev=7d9d41a1fd4a67ed25bf437846c739ee18f5cb36#7d9d41a1fd4a67ed25bf437846c739ee18f5cb36",
    "https://github.com/sorenplanck/dom-protocol?rev=ab45a2944f22fe00f9b12984354f0d5d7cdd229a#ab45a2944f22fe00f9b12984354f0d5d7cdd229a",
})
if after_pins != approved_pins:
    raise SystemExit(
        "exact git dependency pins differ from the approved v0.3.5 release set: "
        f"expected={approved_pins} actual={after_pins}"
    )
print("exact git dependency pins match the approved v0.3.5 release set")
PY

git diff --check
