# Implementation Phase 1B-A — transaction engine

Input commit: `f5cd77bc87b1ff90409b76d1c305038a80f8e231`
Protocol reference commit: `f10667d86196daf4599eff6074a7abf73b6ed55a`

## Verdict

`IMPLEMENTATION_PHASE1B_A_TRANSACTION_ENGINE_COMPLETE`

Phase 1A lifecycle, encrypted state, identity, synchronization, rescan,
kernel confirmation, Tauri foundation, and production frontend adapter remain
preserved. Phase 1B-A adds a manual, restart-safe DOM transaction path; it
does not claim live VPS or mining-confirmation evidence.

## Implemented boundary

`crates/dom-wallet-protocol` isolates immutable DOM protocol dependencies at
the exact required Git revision. Its authoritative source symbols are
`dom_slate::build_send`, `dom_slate::respond_receive`,
`dom_slate::finalize`, `dom_slate::sender_phase_slate`,
`dom_serialization::{DomSerialize, DomDeserialize, Reader, Writer}`,
`dom_consensus::{validate_transaction_structure, validate_balance_equation}`,
`dom_crypto::bp2_verify`, DOM transaction `weight`, and
`dom_core::MIN_RELAY_FEE_RATE`.

The core persists private sender context before request export and recipient
output/context before response export inside the existing encrypted canonical
wallet generation. Inputs are deterministically selected from confirmed,
unreserved descriptors with local encrypted blinding evidence and reserved in
that same commit. A response is bound to the stored request before
finalization. Finalization stores canonical bytes and the 33-byte kernel excess
before submission. Submission is exclusively through the pre-existing
`POST /tx/submit` adapter; `/wallet/spend` is not used.

The durable states include `INPUTS_RESERVED`, `REQUEST_EXPORTED`,
`REQUEST_IMPORTED`, `RESPONSE_PREPARED`, `RESPONSE_EXPORTED`,
`RESPONSE_IMPORTED`, `FINALIZED`, `SUBMITTING`, `SUBMITTED`,
`ACCEPTED_NOT_RELAYED`, `CONFIRMED`, `REORGED`,
`RETRANSMIT_REQUIRED`, `CANCELLED`, and `FAILED`. Repeated exports,
responses, finalization, and retry are idempotent where their stored evidence
matches; conflicts fail closed. Scan kernel evidence remains the confirmation
and rollback authority.

## Manual transport and interface

The experimental text envelope is
`dom-slate-v1:<request|response>:<slate UUID>:<lowercase canonical slate hex>`.
Imports reject malformed, oversized, non-ASCII, wrong-role, noncanonical,
wrong-chain, unsupported, and conflicting replay data. It is not Slatepack.

Tauri registers bounded redacted transaction commands for fee estimate, send
creation, request/response import and export, summary, finalization,
submission/retry, cancellation, list, and redacted detail. The DOM frontend
uses the production invoke adapter, requires confirmations for external
effects, and clears pasted slate text after import. No private context,
blinding, nonce, offset, credential, or seed is serialized into the UI.

## Compatibility and validation evidence

The deterministic adapter test completes Wallet A build → Wallet B receive →
Wallet A finalize with pinned DOM crates, canonical transaction serialization
and strict deserialization, transaction structure/balance validation, range
proof verification, aggregate slate signature validation performed by
`dom_slate::finalize`, chain binding, and protocol weight/fee validation.
Direct local core coverage persists a sender reservation across reopen, creates
a recipient response, finalizes exactly once, and retains a redacted recipient
record. The live chain-view mempool admission boundary is deferred to the next
phase because adding `dom-mempool` would pull node/store infrastructure; no
node, mining, or network test ran here.

Focused commands run in this repository:

```bash
CARGO_TARGET_DIR=/tmp/dom-wallet-v3-phase1b-a-target cargo test -p dom-wallet-protocol authoritative_round_trip_is_canonical -- --nocapture
CARGO_TARGET_DIR=/tmp/dom-wallet-v3-phase1b-a-target cargo test -p dom-wallet-core --no-fail-fast
cd frontend && npm run typecheck && npm test && npm run build
```

Validation passed with `cargo fmt --all --check`, `cargo check --workspace
--all-targets`, scoped `cargo clippy -D warnings`, and `git diff --check`.
Focused wallet tests: 18 passed, 0 failed (6 domain, 2 protocol-adapter, and
10 core). Focused Tauri tests: 6 passed, 0 failed. Frontend tests: 3 passed,
0 failed; frontend typecheck and production build passed.

## Remaining work

`LIVE_VPS_NODE_AND_TWO_WALLET_E2E_WITH_MINING_CONFIRMATION` remains the next
phase. It will supply live mempool admission, propagation, confirmation, and
reorganization operational evidence. Automatic transport, QR codes, Slatepack
relay, backup, restore, migration, and transaction lifecycle screens beyond
the manual exchange remain outside Phase 1B-A.
