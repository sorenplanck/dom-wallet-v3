# Build and Run

Status: IMPLEMENTED_FOUNDATION

The Phase 1A foundation is experimental and unaudited. It supports local wallet lifecycle and deterministic mock synchronization only. It does not implement send, receive, transaction finalization, broadcast, backup export, restore, migration, or a negotiated live DOM-node scan adapter.

## Rust checks

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

## Frontend checks

The frontend has no third-party runtime dependency in Phase 1A.

```bash
cd frontend
npm run typecheck
npm test
npm run build
```

## Desktop shell

```bash
cargo run -p dom-wallet-tauri-shell
```

The shell has a native Tauri v2 entry point and invoke handler. The UI source is bundled from `frontend/`; do not place passwords, root material, nonce material, contexts, or credentials in browser storage or frontend diagnostics.

## Wallet and node behavior

Tests create disposable wallet directories and use synthetic network identities. Real configuration must provide exact authoritative network, chain ID, and genesis ID. The configured endpoint placeholder is intentionally invalid. A non-mutating node probe requires a negotiated DOM adapter; the current adapter returns a typed capability error rather than inventing a response format.
