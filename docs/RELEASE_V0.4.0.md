# DOM Wallet V3 v0.4.0

- Release date: TBD (after the manual canary, see below)
- Tag: `wallet-v0.4.0`
- Source branch: `main-v0.4`
- DOM Core and embedded node revision: `38dd70536f088a467f2b7175978c5a6ebb4e5bd4`

## Highlights

- The wallet now accepts inbound connections from the DOM network
  automatically: the embedded node listens on all interfaces (IPv4), asks the
  router for a port mapping via UPnP/NAT-PMP, and announces the confirmed
  address, so wallets connect to each other instead of leaning only on the two
  hubs. No configuration is required.
- Stable P2P port: 33369 preferred, 33370-33379 as a deterministic fallback,
  then an ephemeral port; the chosen port is persisted beside the node data
  and reused across restarts so the dial-back-confirmed address survives.
- Private mode: a persisted preference, "Accept connections from the DOM
  network (recommended)", enabled by default. Disabling it restores the exact
  v0.3.5 behavior (loopback listener, outbound-only leaf). Changes apply when
  the embedded node restarts.
- Reachability on screen: the Node status screen shows the port-mapping
  outcome (`none`/`upnp`/`natpmp`/`cgnat_detected`), the announced port, the
  local listen port and the inbound peer count.
- Inbound peer limit raised from 4 to 16 so the mesh can close.
- Bootstrap fallback by IP: after every DNS seed fails, the wallet now seeds
  the pinned hub endpoints (66.42.127.141:33369, 64.177.121.62:33369)
  directly, removing DNS as a single point of failure.
- Embedded DOM core and node updated to revision `38dd705`, whose delta over
  `7d9d41a` is exclusively P2P (`dom-node/src/node.rs`,
  `dom-wire/src/handshake.rs`): the prologue fallback now also reaches
  inbound connections and DNS-named seeds, which becomes mandatory once other
  nodes dial into the wallet.
- Elevated Windows installations create a Defender Firewall rule keyed to
  the executable path (removed on uninstall). The default installation is
  per-user without elevation, where the rule cannot be created: Windows
  shows its standard firewall dialog once instead.

## Privacy note

Accepting connections makes it visible to any network peer that this IP runs
a DOM node. This is the same trade-off every reachable Bitcoin or BitTorrent
node makes. Users who prefer not to expose this can disable
"Accept connections from the DOM network" on the Node status screen; the
wallet then behaves exactly like v0.3.5.

## Firewall notes by operating system

- **Windows:** the bundle's effective NSIS installMode is `currentUser`
  (Tauri's default; the wallet does not override it), so the DEFAULT
  installation runs without elevation and CANNOT create the machine
  firewall rule - Windows shows its standard permission dialog once on
  first listen; allowing it enables inbound connections, denying it leaves
  the wallet outbound-only (everything else keeps working). When the
  installer IS run elevated, it creates a Defender Firewall rule keyed to
  the application executable, valid for ALL network profiles
  (domain/private/public), and the uninstaller removes it. The mode stays
  `currentUser` on purpose: switching to `perMachine` would break the
  silent self-update path.
- **macOS:** the application firewall is off by default. If enabled, macOS
  asks once whether to allow inbound connections for the app.
- **Linux:** no dialog in the default configuration. `ufw`/`firewalld` users
  must allow the P2P port (33369 by default) manually for inbound
  reachability; the wallet works as an outbound-only leaf otherwise.

## Compatibility and limits

- No protocol change: v0.4.0 speaks prologue versions `[3, 2]`, the hubs run
  `38dd705`, and v0.3.5 wallets keep working as outbound-only leaves during
  and after the rollout.
- IPv4 only in this release. IPv6 (`[::]`) is deferred until the hubs have
  AAAA records and the dual-stack bind fallback cannot lose IPv4.
- Reachability requires a router that answers UPnP or NAT-PMP; carriers using
  CGNAT are detected and reported, and those wallets remain outbound-only.
- The RPC and metrics endpoints of the embedded node remain disabled; the
  only exposed surface is the Noise-authenticated P2P port.
- DOM Mainnet identity remains fixed to chain ID
  `f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b`.
- Consensus is untouched: the `7d9d41a` -> `38dd705` delta contains no
  consensus files, and the compact-target byte order remains the consensus
  convention.
- The application and network remain experimental. DOM initially has no
  monetary value. Do not use real funds.
- Installers are not Authenticode-signed or Apple-notarized and may trigger
  operating-system warnings. Release checksums and Minisign signatures remain
  authoritative for artifact verification.

## Required publication evidence

- The source commit is clean, pushed to `main-v0.4`, and reports `0.4.0` in
  the Rust workspace, frontend package, Tauri configuration, native bridge
  tests, and release documentation.
- Workspace tests, frontend tests/build, Rust formatting, Clippy, targeted
  release tests, dependency audit, and dependency policy checks pass.
- `Cargo.lock` resolves every node crate to the single revision `38dd705`
  (`no_duplicate_dom_protocol_revisions` guards this) and contains no
  `7d9d41a` entry.
- **Manual canary before `latest.json` (mandatory - the updater has no
  percentage rollout):** install the signed artifacts on three machines (two
  different home networks, one behind CGNAT); pass V1-V7 and V10 of the mesh
  spec - reachable status in the UI, hub dial-back confirmed, two wallets
  connected to each other, stable port across three restarts, CGNAT detected
  cleanly, private mode verified, firewall behavior recorded. On a REACHABLE
  wallet, additionally check its peer list for its own public IP and its logs
  for reconnection loops to itself (the core has no Noise-identity
  self-connection guard - see docs/issues-draft/): any such instability is a
  RELEASE BLOCKER until the core is fixed. Then watch the hubs for 24 hours
  (equal `dom_best_known_peer_height`, no peer drops) before publishing
  `latest.json`.
- Rollback path: there is no remote kill switch. If v0.4.0 misbehaves after
  publication, ship a v0.4.1 with the listener reverted to loopback;
  meanwhile users can enable private mode to restore the previous behavior.
