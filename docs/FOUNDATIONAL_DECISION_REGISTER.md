# Foundational Decision Register

**Owner:** Soren Planck
**Review date:** 2026-07-11

## Inventory method

The inventory deduplicates substantive decision markers in the Pass 2 report and Specifications 0000 through 0012. The prior advisory count was 14. The repository-derived count is 30 because the Pass 2 prose grouped distinct contracts such as lifecycle expiry, cancellation, retention, credential form, transport policy, limits, recovery order, and test-evidence scope. Each row has one final status.

| ID | Decision and sources | Owner and affected specifications | Status | Contract or exact blocker | Required evidence and tests |
|---|---|---|---|---|---|
| DEC-ROLLBACK-PROTECTION | Anti-rollback; 0001 dependencies, 0004 reopen, 0008 invariants | 0004; 0001,0007,0008,0011,0012 | BLOCKING | Authenticated old-generation replay remains undetected by current evidence. | Platform monotonicity design, rollback tests, restore and reopen vectors. |
| DEC-API-CREDENTIALS | Credential form and revocation; 0001,0010 | 0010; 0001,0007,0012 | BLOCKING | No DOM credential/revocation construction selects a safe remote contract. | Approved credential design, expiry/revocation and denial tests. |
| DEC-ZEROIZATION | Platform zeroization; 0001,0007 | 0007; 0001,0012 | BLOCKING | Supported-platform guarantees are not established. | Platform review and memory-handling tests. |
| DEC-ACCOUNT-POLICY | Account fields and deletion; 0002 | 0002; 0010,0011 | BLOCKING | Account retention and deletion policy requires project approval. | Authorization, retention, and migration tests. |
| DEC-RESERVATION-LIFETIME | Expiry, post-exposure cancellation, retention; 0002,0003 | 0003; 0002,0004,0006,0009 | BLOCKING | DOM wire and approved lifecycle policy do not select one expiry/cancellation contract. | DOM participant evidence and lifecycle/restart tests. |
| DEC-CANONICAL-SERIALIZATION | Canonical encoding; 0002,0004 | 0004; 0002,0008,0011 | BLOCKING | No approved V3 schema encoding exists. | Storage/migration format decision and corruption vectors. |
| DEC-BACKEND-DURABILITY | Backend acknowledgement profile; 0004 | 0004; 0008,0012 | BLOCKING | Current file-envelope publication is evidence only; alternative backend acknowledgement is unselected. | Adapter fault model and crash matrix. |
| DEC-MIGRATION-RETENTION | Source-byte retention; 0004,0011 | 0011; 0004,0008 | BLOCKING | Privacy and recovery retention period is unselected. | Migration governance policy and deletion evidence. |
| DEC-STABLE-VIEW | Stable-view format; 0005 | 0005; 0002,0003,0006,0008,0011,0012 | BLOCKING | Current DOM ChainSource exposes tip and scan data, not a stable-view token or ancestry-proof format. | DOM node interface or RFC, bounded view vectors. |
| DEC-INDEPENDENT-SOURCES | Independent-source policy; 0005 | 0010; 0005,0012 | BLOCKING | Deployment privacy and availability policy is unselected. | Threat analysis and source-switch tests. |
| DEC-RESCAN-BOUNDARY | Full-rescan and repair boundary; 0005,0008 | 0008; 0005,0006,0007 | BLOCKING | Approved recovery boundary is unselected. | Recovery guarantee matrix and rescan tests. |
| DEC-REORG-BUDGET | Ancestor and resource budget; 0006 | 0012; 0005,0006 | BLOCKING | Deployment capacity has not selected safe limits. | Adversarial source and exhaustion tests. |
| DEC-PROVISIONAL-UX | Provisional-state presentation; 0006,0010 | 0010; 0006 | BLOCKING | User policy is unselected. | Interface review and non-authorizing display tests. |
| DEC-LIFECYCLE-PARTICIPANT-WIRE | Participant wire, proof and invoice semantics; 0003 | 0003; 0007,0009,0011 | BLOCKING | Direct DOM format evidence does not select all V3 interaction policy. | DOM format clarification and replay vectors. |
| DEC-LEGACY-DERIVATION | Existing coinbase and receive-request compatibility; 0007 | 0007; 0008,0011 | RESOLVED | Use authoritative DOM BIP-39/BIP-32/BIP-44 compatibility behavior, deterministic coinbase-by-height, and receive-request-by-index only with required DOM inputs; random change and receive-slate material is non-derivable. | DOM wallet-keys and wallet2 keychain vectors; restore limitation tests. |
| DEC-V3-SECRET-DOMAINS | New private-context, backup, and authentication domains; 0007 | 0007; 0003,0008,0010,0011 | BLOCKING | No approved V3 label, subkey, point/scalar, or authentication construction exists. | Cryptographic design, vectors, and review. |
| DEC-CRYPTO-ENVELOPE-BINDING | V3 authenticated-context encoding; Pass2,0004,0007,0008 | 0007; 0001,0002,0004,0008,0011,0012 | BLOCKING | Current DOM envelope uses no AEAD associated data and validates ChainId in encrypted payload; V3 construction is not selected. | DOM cryptographic approval, vectors, cross-chain and tamper tests. |
| DEC-KDF-UPGRADE | V3 KDF bounds and upgrade; 0007,0008 | 0007; 0008,0012 | BLOCKING | Current Argon2id/HKDF envelope is compatibility evidence; V3 profile policy is unselected. | Cryptographic review, bounds, upgrade vectors. |
| DEC-BACKUP-FORMAT | V3 magic, schema, merge and temporary retention; 0008 | 0008; 0004,0007,0011 | BLOCKING | V2 format is migration evidence only. | Approved format, conflict policy, publication/restart tests. |
| DEC-ECON-BLOCK-WEIGHT | RFC weight conflict; 0009 | 0009; 0003,0006,0012 | BLOCKING | RFC0010 and consensus source include coinbase weight while RFC0011 states a conflicting rule. | Corrected or superseding RFC/governance decision and regression vector. |
| DEC-ECON-WALLET-POLICY | Selection, dust, privacy, and bounds; 0009 | 0009; 0003,0012 | BLOCKING | Consensus resolves validity but not every V3 wallet policy. | Approved policy matrix and deterministic selection tests. |
| DEC-API-DEPLOYMENT | Transport, delegation, versions, limits; 0010 | 0010; 0001,0005,0012 | BLOCKING | No approved remote deployment policy selects these contracts. | Deployment design and adversarial API tests. |
| DEC-MIGRATION-MATRIX | V2 source support and normalization; 0011 | 0011; 0007,0008,0012 | BLOCKING | Source-version matrix and pending-state mappings are unselected. | Read-only source vectors and dry-run equivalence tests. |
| DEC-ASSURANCE-RELEASE | CI, reproducibility, release and review policy; 0012 | 0012; 0000 through 0011 | BLOCKING | Engineering governance has not selected release evidence policy. | CI matrix, provenance design, independent-review scope. |
| DEC-LIFECYCLE-SUBMIT-OBSERVATION | Adapter result versus later observation; 0003 | 0003; 0004,0005,0012 | RESOLVED | Adapter outcomes govern recovery only; matching ChainSource evidence may later create mempool or canonical observation. | Timeout/rejection to observation tests and no-confirmation-from-receipt test. |
| DEC-LIFECYCLE-FINALIZED-CONTROL | Input local control after finalization; 0002,0003,0004 | 0002; 0003,0004,0006,0009,0012 | RESOLVED | Finalization sets selected inputs to locally_finalized_spend(TransactionId) in the same DUW while retaining reservation evidence. | Model, concurrency, restart, and reorg tests. |
| DEC-RESTORE-ACTIVATION-ORDER | Restore reconciliation order; 0008 | 0008; 0004,0005,0006,0012 | RESOLVED | Reconciliation completes and is recorded in staging before AtomicActivation; post-activation verification is non-authorizing. | Stage/reconcile/activate crash tests. |
| DEC-ECON-CHANGE-CARDINALITY | No-change cardinality; 0003,0009 | 0009; 0003,0012 | RESOLVED | Cardinality zero is valid only for no-change; positive change plans require a nonzero permitted cardinality. | Exact-spend, zero-change, positive-change, malformed-count tests. |
| DEC-API-DELIVERY-UNCERTAINTY | Delayed or corrupted message record; 0010 | 0010; 0002,0003,0004 | RESOLVED | No lifecycle or ownership mutation occurs; only bounded redacted audit or recovery evidence may be durably recorded. | Corruption and delayed-message tests. |
| DEC-ASSURANCE-COVERAGE-SCOPE | Evidence matrix scope; 0012 | 0012; 0000 through 0011 | RESOLVED | Trace every normative principle in 0000 and requirement in 0001 through 0011. | Requirement-to-evidence matrix review. |

## Consequences

BLOCKING decisions prevent implementation of their affected contracts and keep affected specifications DRAFT. RESOLVED decisions are applied in the cited specifications. Every decision preserves ChainId binding, non-reuse, old-or-new durability, rollback safety, and redacted recovery evidence; no Epic protocol behavior is selected.
