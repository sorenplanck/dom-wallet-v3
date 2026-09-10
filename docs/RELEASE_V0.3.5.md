# DOM Wallet V3 v0.3.5

- Release date: 2026-09-10
- Tag: `wallet-v0.3.5`
- Source branch: `main-v0.4`
- DOM Core and embedded node revision: `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`

## Highlights

- Accepts payment and fee input in DOM with exact decimal-to-integer conversion,
  while retaining noms as the internal consensus and command representation.
- Warns before a payment spends more than ten percent of the known spendable
  balance and presents user-facing balances and confirmations in DOM.
- Retries optimistic wallet-generation conflicts during canonical scanning,
  reloads the active state, reapplies the scan batch, and reports a closed
  persistence stage if the bounded retry budget is exhausted.
- Exposes typed, retryable storage-generation conflicts and preserves the error
  code in the frontend without leaking secret-bearing messages.
- Preserves raw Minisign text for `dom_manifest.artifacts[].signature` while
  retaining the base64 representation required by Tauri under `platforms.*`.
- Updates the embedded DOM core and node to revision `7d9d41a`, including the
  P2P hotfix that mirrors the negotiated prologue version in Hello messages so
  deployed v2 and v3 peers can interoperate.
- Carries blinding secrets through the protocol adapter using zeroizing
  containers and retains authenticated mempool and restore regression coverage.

## Compatibility and limits

- DOM Mainnet identity remains fixed to chain ID
  `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`.
- Consensus dependencies and the embedded node use the single reviewed
  revision `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`.
- The separately managed sidecar update channel remains independent and still
  requires its own signed `sidecar-manifest.json` and `node-latest.json`.
- Swap execution remains fail-closed unless a compatible interop daemon is
  configured and reachable.
- The application and network remain experimental. DOM initially has no
  monetary value. Do not use real funds.
- Installers are not Authenticode-signed or Apple-notarized and may trigger
  operating-system warnings. Release checksums and Minisign signatures remain
  authoritative for artifact verification.

## Required publication evidence

- The source commit is clean, pushed to `main-v0.4`, and reports `0.3.5` in the
  Rust workspace, frontend package, Tauri configuration, native bridge tests,
  and release documentation.
- Workspace tests, frontend tests/build, Rust formatting, Clippy, targeted
  release tests, dependency audit, and dependency policy checks pass.
- The GitHub validation workflow produces Linux, Windows, and macOS artifacts
  and their SHA-256 manifests from the exact source commit.
- Updater artifacts and the canonical DOM manifest are signed offline with the
  pinned Minisign release key and verified before `latest.json` is uploaded.
- `platforms.*.signature` contains base64-encoded Minisign files and
  `dom_manifest.artifacts[].signature` contains raw Minisign text.
- The GitHub Release is attached to `wallet-v0.3.5`, is neither a draft nor a
  prerelease, and becomes the repository's latest release only after every
  referenced artifact and signature is present.
