# Live node lifecycle runbook

The `dom-wallet-live-e2e` binary is opt-in. `cargo test` does not execute it.

Required configuration names are `DOM_LIVE_E2E_RPC_URL`, `DOM_LIVE_E2E_NETWORK`, `DOM_LIVE_E2E_CHAIN_ID`, `DOM_LIVE_E2E_GENESIS_HASH`, `DOM_LIVE_E2E_WALLET_A_DIR`, `DOM_LIVE_E2E_WALLET_A_PASSWORD_FILE`, `DOM_LIVE_E2E_WALLET_B_DIR`, `DOM_LIVE_E2E_WALLET_B_PASSWORD_FILE`, and `DOM_LIVE_E2E_AMOUNT_NOMS`. The runner prints missing names only. It never prints values, passwords, tokens, raw slates, QR content, private contexts, or finalized bytes.

Password files must be regular files and, on Unix, must not grant group or other permissions. Wallet paths and protected files must remain outside the repository.

Run the dry gate first:

```text
cargo run -p dom-wallet-core --bin dom-wallet-live-e2e
```

Mutation requires the exact acknowledgement:

```text
DOM_LIVE_E2E_ENABLE=I_UNDERSTAND_THIS_SUBMITS_A_LIVE_DOM_TRANSACTION
```

With that token, the runner performs node identity preflight, opens and synchronizes both wallets, uses the existing text slate exchange and transaction engine, submits only the persisted finalized bytes, observes mempool evidence when present, waits for scan-based kernel confirmation, reconciles both wallets, closes/reopens both, and resynchronizes. It never starts or configures a miner. A missing block producer results in `SUBMITTED_NOT_YET_CONFIRMED`; no reservation is released and no replacement transaction is created.

`DOM_LIVE_E2E_ALLOW_CREATE_WALLET_B=YES` is the only creation opt-in for Wallet B. Confirmation polling may be bounded through `DOM_LIVE_E2E_CONFIRMATION_TIMEOUT_SECS` and `DOM_LIVE_E2E_POLL_INTERVAL_SECS`.
