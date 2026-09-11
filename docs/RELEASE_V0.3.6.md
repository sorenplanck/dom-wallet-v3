# DOM Wallet V3 v0.3.6

- Tag: `wallet-v0.3.6`
- Source branch: `main-v0.4`
- DOM Core and embedded node revision: `38dd70536f088a467f2b7175978c5a6ebb4e5bd4`

## Highlights

- The embedded DOM node can accept inbound peers by default, using persisted
  port selection, UPnP/NAT-PMP mapping and advertised-address confirmation.
- Private mode restores the loopback-only, outbound-peer configuration.
- The Node screen reports reachability, mapping outcome, advertised port and
  inbound peer count.
- Bootstrap retains pinned hub IP fallbacks if DNS seed lookup fails.
- Windows elevated installs can create a path-scoped Defender Firewall rule;
  default per-user installs retain the standard Windows firewall prompt.

## Compatibility and safety

- No consensus change. The wallet uses DOM Core revision `38dd705` and
  prologue versions `[3, 2]`.
- The network and application remain experimental. Do not use real funds.
- Installers are not Authenticode-signed or Apple-notarized. Verify release
  checksums and Minisign signatures before installation.

## Publication requirements

- The release commit reports `0.3.6` in the Rust workspace, frontend package,
  Tauri configuration and native bridge tests.
- CI validates the tag and packages unsigned artifacts for Linux, Windows and
  macOS. The offline Minisign key signs updater artifacts and the generated
  canonical manifest before `latest.json` is published.
- Before publishing the automatic-update feed, complete the documented mesh
  canary and self-connection checks in `docs/RELEASE_V0.4.0.md`.
