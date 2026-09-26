# DOM Wallet V3 v0.3.7

- Tag: `wallet-v0.3.7`
- Source branch: `main-v0.4`
- DOM Core and embedded node revision: `38dd70536f088a467f2b7175978c5a6ebb4e5bd4`

## Highlights

- Wallet state envelope v2 stores ciphertext compactly so wallets with large
  output histories continue committing synchronization pages beyond the former
  16 MiB v1 envelope boundary.
- Existing v1 state remains readable and migrates lazily through the crash-safe
  generation protocol, retaining one pre-migration snapshot.
- Persistent storage-limit and I/O failures are reported explicitly and stop
  deterministic retry loops until the user requests another synchronization.
- The UI reports wallet synchronization failures separately from node errors.
- Signed Wallet updates download automatically and install when no critical
  Slate or protected runtime activity is in progress. A verified update waits
  in staging and retries later when the safe point is unavailable.
- The compatibility feed retains identical raw Minisign text in both signature
  positions so installed 0.3.4 and 0.3.5 wallets can accept the transition.

## Compatibility and safety

- No consensus, block, transaction or P2P change. The wallet continues using
  DOM Core revision `38dd705` and prologue versions `[3, 2]`.
- A released v1-only application cannot read state after it has been migrated
  and committed as v2. Preserve a copy of the complete wallet data directory
  before upgrading if rollback to an old application is required.
- Users on 0.3.4, 0.3.5 or 0.3.6 must perform this transition once through the
  existing manual update controls or installer. Later releases can use the
  automatic installation logic included here.
- The network and application remain experimental. Do not use real funds.
- Installers are not Authenticode-signed or Apple-notarized. Minisign signatures
  and the release checksums authenticate updater artifacts.

## Publication requirements

- The release commit reports `0.3.7` in the Rust workspace, frontend package,
  Tauri configuration and native bridge tests.
- CI packages the exact immutable revision for Linux, Windows and macOS without
  access to the release private key.
- The three updater artifacts and the canonical manifest are signed offline
  with Minisign key ID `74197A95CA309CF0` and verified before promotion.
- The complete release, including `latest.json`, remains a GitHub draft until
  every remote asset matches the locally approved bytes.
- Packaged canaries cover manual 0.3.6 -> 0.3.7 transition and automatic update
  behavior from a build containing the new scheduler.
