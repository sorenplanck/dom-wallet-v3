# Foundational Specification Consistency Matrix

**Owner:** Soren Planck
**Review date:** 2026-07-11

**Closure Pass 1:** DEC-ECON-BLOCK-WEIGHT is resolved from current DOM consensus code and tests. The reconciled effective blocker references are DEC-ROLLBACK-PROTECTION, DEC-STABLE-VIEW, and DEC-V3-SECRET-DOMAINS; see [Blocker Status Reconciliation](../reports/FOUNDATIONAL_BLOCKER_STATUS_RECONCILIATION.md).

**Closure Pass 2:** DEC-ROLLBACK-PROTECTION is resolved for REVIEW with later implementation proof retained. DEC-STABLE-VIEW and DEC-V3-SECRET-DOMAINS remain authority blockers; see the [Pass 2 report](../reports/FOUNDATIONAL_BLOCKER_CLOSURE_PASS2.md).

| Subject | Authority | Dependents and records | Atomicity, restart, reorg, migration, and security rule | Evidence and decisions | Verdict |
|---|---|---|---|---|---|
| Identity, account, generation | 0002 | All specifications; WalletIdentity, AccountId, Generation | Chain-bound immutable identity; one expected-generation DUW; restore and migration validate before activation. | State invariant tests; DEC-ACCOUNT-POLICY | CONFIRMED_CONSISTENT |
| Cursor and StableView | 0005 | 0002,0003,0004,0006,0008,0011,0012; CanonicalCursor | Height plus hash only; cursor and observations commit together; divergence blocks selection and invokes reorg. | DOM-W2-SYNC-001 tests; DEC-STABLE-VIEW | CONFIRMED_CONSISTENT |
| Output and reservation | 0002 | 0003,0004,0006,0009 | Orthogonal observations; one reservation; finalization changes local control in its DUW; reorg retains evidence. | Model, concurrency, reorg tests; DEC-LIFECYCLE-FINALIZED-CONTROL | CONFIRMED_CONFLICT_RESOLVED |
| Lifecycle and external effects | 0003 | 0004,0005,0006,0007,0009,0012 | Durable preparation and intent precede exposure; exact bytes retry; source evidence alone controls observations. | Restart and node-result tests; DEC-LIFECYCLE-SUBMIT-OBSERVATION | CONFIRMED_CONFLICT_RESOLVED |
| Canonical storage | 0004 | 0002,0003,0005,0006,0008,0011 | Old-or-complete-new generation, expected generation, no sidecars, durable recovery event. | Crash matrix; DEC-CANONICAL-SERIALIZATION, DEC-ROLLBACK-PROTECTION | CONFIRMED_CONSISTENT |
| Reorganization | 0006 | 0002 through 0005,0008,0009,0011,0012 | Bounded plan, freeze, rewind, replay, restart; rollback plus replay equals fresh reconciliation. | Fork/state-machine tests; DEC-REORG-BUDGET | CONFIRMED_CONSISTENT |
| Secrets and non-reuse | 0007 | 0001,0002,0003,0004,0008,0011,0012 | Allocation before exposure, floors never decrease, random material never recreated, redaction required. | Key, restore, migration tests; DEC-LEGACY-DERIVATION, DEC-V3-SECRET-DOMAINS | CONFIRMED_CONSISTENT |
| Envelope binding | 0007 | 0001,0002,0004,0008,0011,0012 | Authenticate required identity fields before use; V3 authenticated-context construction is blocked. | Envelope tamper/cross-chain vectors; DEC-CRYPTO-ENVELOPE-BINDING | CONFIRMED_CONFLICT_RESOLVED |
| Backup and restore | 0008 | 0002,0004 through 0007,0011,0012 | One generation, bounded parse, stage then reconcile then activate; prior generation preserved. | Restore/restart/spend tests; DEC-RESTORE-ACTIVATION-ORDER, DEC-BACKUP-FORMAT | CONFIRMED_CONFLICT_RESOLVED |
| Economic selection | 0009 | 0002 through 0006,0012 | Exact spend permits zero change; positive change count bounded; finalization revalidates. | Validator/property tests; DEC-ECON-CHANGE-CARDINALITY, DEC-ECON-BLOCK-WEIGHT | CONFIRMED_CONFLICT_RESOLVED |
| API and transport | 0010 | 0001,0003 through 0005,0007,0008,0012 | Least privilege, local-safe binding, bounded parsing; uncertainty cannot create ownership state. | Capability/fuzz tests; DEC-API-DELIVERY-UNCERTAINTY, DEC-API-DEPLOYMENT | CONFIRMED_CONFLICT_RESOLVED |
| Migration | 0011 | 0002,0004 through 0008,0012 | Read-only V2, stage, preserve floors and source, reconcile before activation. | Dry-run/source-preservation tests; DEC-MIGRATION-MATRIX | CONFIRMED_CONSISTENT |
| Assurance and gates | 0012 | 0000 through 0011 | Requirements map to evidence; compilation or happy path is insufficient. | State-model, fuzz, CI evidence; DEC-ASSURANCE-COVERAGE-SCOPE, DEC-ASSURANCE-RELEASE | CONFIRMED_CONFLICT_RESOLVED |
