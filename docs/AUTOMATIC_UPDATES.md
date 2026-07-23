# DOM Wallet V3 signed update architecture

This document describes the stabilization contract. It does not authorize a
release and it does not contain a signing private key.

## Independent channels

The application checks three signed HTTPS feeds, in this order:

1. `mainnet-peers.json` changes only operational bootstrap endpoints.
2. Wallet `latest.json` updates the complete installed application.
3. `node-latest.json` updates only a compatible managed `dom-node` sidecar.

Checks occur after startup readiness, every 60 minutes while the application is
running, after resume, and on explicit user request. A single-flight guard
prevents concurrent checks. Network errors are non-fatal and retain the last
authenticated cache and compiled emergency peers.

Peer-only changes never install a binary. A node-only update never changes the
Wallet version. An incompatible node sets `WALLET_UPDATE_REQUIRED` and waits for
a coordinated Wallet release.

## Trust roots and release inputs

Release builds must embed `DOM_UPDATE_PUBLIC_KEY`. The corresponding private key
must exist only in the protected GitHub release environment:

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`

The client accepts only HTTPS port 443 URLs hosted by the explicit GitHub release
allowlist or an approved DOM domain. TLS is transport protection, not artifact
authorization. Tauri's mandatory Minisign verification is followed by the DOM
manifest signature, SHA-256, byte length, SemVer, channel, expiry, platform,
architecture, network and schema policy.

If the public key is missing or invalid, all three update channels fail closed.
Local development builds therefore remain runnable but cannot install updates.

## Wallet update safe point

The Wallet updater refuses to interrupt critical Slate states. After a signed
artifact is downloaded and verified it:

1. blocks new work;
2. stops mining and drains workers;
3. persists and closes the Wallet;
4. stops the node;
5. invokes the platform installer;
6. restarts the application;
7. leaves the Wallet locked.

If installation fails before replacement, the current application is restarted.
Wallet, chain, cursor, history and configuration directories are never installer
targets.

## Managed node runtime

The intended runtime is outside the protected application installation:

```text
runtime/
├── node-state.json
├── staging/
└── nodes/
    ├── <previous-version>-<revision>/
    └── <active-version>-<revision>/
```

`node-state.json` contains only non-secret version, revision, digest, signature
identity, compatibility and monotonic sequence metadata. Promotion uses a
same-filesystem atomic rename. The active and previous known-good versions are
retained. Runtime paths, ownership, permissions, symlinks/reparse points and
binary digests are validated before execution.

Every node binary replacement requires a process restart:

1. wait for the Slate safe point;
2. stop mining and confirm worker exit;
3. persist Wallet journal and canonical height-plus-hash cursor;
4. call authenticated loopback `POST /shutdown`;
5. confirm the old PID exited and local ports were released;
6. promote staging atomically;
7. start the new node with fixed structured arguments and a protected temporary
   RPC Bearer token;
8. call authenticated `/build-info`;
9. compare the reported revision and identity with the signed manifest;
10. require health `READY`, canonical cursor validation and peer discovery;
11. only then enter `NODE_UPDATE_SUCCEEDED`.

Startup, handshake, identity, storage, READY or crash-loop failure causes an
atomic rollback and a mandatory restart of the previous node. The rejected
revision is suppressed until a higher signed sequence/revision is observed.

## DOM Protocol integration boundary

DOM Protocol `release/mainnet` commit
`28ba3cefc9fbc913f126336482662528c68a7d8c` is the first inspected immutable
control-plane revision that provides:

- Bearer authentication for `/wallet/balance`, `/chain/scan` and `/build-info`;
- `/build-info` containing the build commit;
- loopback-only authenticated `POST /shutdown` returning `202`;
- graceful shutdown through `DomNode::request_shutdown()` and ordered task drain.

The current `/build-info` response is `{"commit":"<sha>"}`. It does not yet
report the complete compatibility identity required by the node-only update
contract. The Wallet therefore records this revision as the control-plane
baseline but does not replace the existing consensus crate pin or activate
production node-only promotion. Promotion remains fail-closed until an immutable
revision also proves node version, network, chain ID, genesis hash, RPC protocol,
P2P protocol and storage schema through authenticated RPC. This avoids importing
unreviewed miner/node changes into the Wallet merely to obtain the RPC routes.

## Recovery

A failed Wallet update never deletes Wallet data. Reinstalling the previous
signed installer is the supported manual recovery path. A failed node update
automatically returns to the previous known-good runtime directory when no
irreversible storage migration occurred. Irreversible migrations are never
eligible for node-only update.

## Release prohibition on stabilization

The `stabilize/wallet-v0.2.0` workflow validates and packages only. It must not
create or move a tag, publish a GitHub Release, or upload a live update manifest.
Production publication requires an authorized immutable tag, protected release
environment, matching versions/revisions and all platform artifacts and
signatures before the release becomes visible as latest.
