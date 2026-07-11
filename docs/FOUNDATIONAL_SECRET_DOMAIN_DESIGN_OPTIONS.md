# Foundational Secret-Domain Design Options

**Status:** PROPOSED_FOR_INDEPENDENT_REVIEW
**Decision:** DEC-V3-SECRET-DOMAINS
**Wallet input commit:** `d1b53d552397c6da8f9b0e03f0bfefd4d8855d6a`
**Input evidence:** DOM Git commit `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`; [DOM reference study](../reports/DOM_WALLET_SECRET_DOMAIN_REFERENCE_STUDY.md); [Tauri continuity](DOM_TAURI_PRODUCT_CONTINUITY.md); [Epic secondary study](../reports/EPIC_SECRET_DOMAIN_REFERENCE_STUDY.md).
**Selected option:** UNSELECTED
**Construction status:** NOT_SPECIFIED
**Vectors:** NOT_PROVIDED
**Independent review:** NOT_COMPLETED

## Authority and scope

This is a design-options package, not cryptographic approval. DOM consensus, current DOM cryptographic primitives, transaction/slate formats, chain identity, and approved protocol rules are authoritative. Validated DOM Wallet V1/V2 behavior is primary evidence for product continuity, funds compatibility, storage, backup, and recovery. Epic is secondary and may supply only verified gap-solving properties. Tauri and the DOM product identity remain the desktop baseline; no option replaces them.

No option supplies a new label, byte string, salt policy, KDF profile, expansion formula, scalar mapping, nonce algorithm, AEAD profile, associated-data layout, or vector output. Those are reviewer-owned values: `APPROVED_DOMAIN_LABEL`, `APPROVED_KDF_PROFILE`, `APPROVED_CANONICAL_ENCODING`, `APPROVED_SCALAR_MAPPING`, and `APPROVED_AEAD_PROFILE`.

## DOM evidence basis and Epic role

Pinned DOM evidence preserves these properties: DOM fund and slate compatibility; V2 explicit pending-slate secret persistence; retry stability before successful finalization; one-time secret wiping after success; versioned password-protected envelopes; full-backup state capture; chain mismatch rejection; atomic file replacement; seed-only recovery limits; and Tauri presentation that keeps sensitive settings out of its shared UI state. The legacy V1 exposed receive blinding, password-only backup derivation, and password-only coinbase fallback are rejected.

Epic does not define any V3 construction. Its completed study supports only properties where DOM needs strengthening: context persistence before dependent external effects, retryable records, explicit deletion after lifecycle completion, recovery/repair categories, capability separation, hostile-input handling, and assurance categories.

## Mandatory invariants

- No purpose silently authorizes or derives another purpose.
- Chain or network mismatch, unknown domain, unknown version, malformed encoding, and cryptographic failure fail closed with typed errors.
- Context encodings are unambiguous and canonical.
- Allocation and non-reuse floors never decrease. Durable allocation or external exposure creates a permanent non-reuse obligation.
- Private contexts needed for retry survive restart until a defined terminal deletion point.
- Secrets never enter frontend state, Tauri command responses, logs, errors, telemetry, support bundles, filenames, or public identifiers.
- Full backup preserves all state required to prevent reuse; seed-only recovery does not claim recovery of local-only contexts, credentials, or random output material.
- Migration never invents provenance; credential rotation never changes fund derivation; legacy exposed-secret behavior is rejected.

## Secret-class inventory

| Secret class | DOM V1/V2 evidence | Candidate handling common to all families | Recovery / UI rule | Reviewer-owned output |
| --- | --- | --- | --- | --- |
| Root seed and account derivation | DOM BIP-39/root derivation and V1/V2 compatibility | Preserve authoritative DOM fund derivation | Seed recovery only for derivable fund material; never UI-visible after entry | Compatibility boundary |
| Receive, change, coinbase and transaction blinding | V2 distinguishes deterministic coinbase from random receive/change | Preserve only DOM-authoritative fund behavior; non-reuse policy becomes explicit | Full backup covers non-derivable material | Scalar mapping and non-reuse proof |
| Participant nonce and sender excess | V2 `PendingSlate` persists sender secrets, retries before success, then wipes | Private context, durable before external effect; never renderer-visible | Full backup or explicit loss semantics | Nonce construction, object binding, deletion point |
| Private transaction context | V1/V2 pending/slate records | Encrypt and bind to approved object identity | Survives restart until terminal lifecycle action | Context encoding and envelope profile |
| State and stored transaction protection | Shared V1/V2 envelope and V2 state | Preserve protected properties, not automatic construction reuse | Restore validates version and chain | State key ownership and AAD |
| Full-backup protection | V2 full-backup captures `WalletV2State` | Chain/wallet-bound complete backup with non-reuse state | Seed-only limitations displayed honestly | Backup key and envelope policy |
| Password-derived unlock key | V1/V2 password envelope evidence | Scoped unlock, no frontend retention | Rotation does not change fund derivation | KDF policy, salt/IV handling |
| Owner, receiving, administration, node RPC, and transport credentials | DOM app has distinct command/node surfaces; no unified secret-domain framework proven | Separate capabilities and records from fund secrets | Rotate/revoke independently; never UI state | Credential roots, binding and rotation |
| Migration staging key and Tauri command-session capability token | V3-specific requirements; no final DOM construction | Typed, scoped, short-lived where applicable | Not seed-recoverable unless approved backup inclusion says so | Lifecycle, storage, expiry, revocation |

## Candidate families

### Option A — Hardened DOM Wallet Continuity

**Classification:** PARTIALLY_SUPPORTED.

Option A keeps verified DOM Wallet V2 properties as the primary baseline: authoritative DOM fund derivation, DOM transaction and slate compatibility, explicit private-context persistence, versioned password-protected state/backup envelopes, authenticated integrity, atomic publication, full-backup recovery, Tauri workflows, and existing operational boundaries. It rejects every confirmed V1/V2 weakness: exposed blinding material, password-only legacy derivation, missing V3 binding, ambiguous reuse policy, rollback weakness, and undocumented cross-purpose coupling.

Epic can only fill verified DOM gaps in context lifecycle, retry durability, recovery state, and assurance. Option A is DOM-first and is not Epic-like, Epic-derived, or an authorization to copy V2 code.

Advantages: highest compatibility continuity and clearest migration path. Risks requiring review: hidden legacy coupling, reuse of a construction outside its demonstrated envelope scope, insufficient domain separation, and backup rollback behavior.

### Option B — DOM-Native Labeled Subkey Hierarchy

**Classification:** REQUIRES_REVIEWER_DECISION.

Option B preserves authoritative DOM fund derivation and Tauri workflows, while an approved DOM root or intermediate material yields independently purpose-bound subkeys for missing V3 domains. The reviewer must specify the approved construction and unambiguous context containing chain ID, network where applicable, wallet identity, purpose, construction version, and relevant object identity. Fund derivation remains separate from private-context protection, state protection, full-backup protection, and authentication.

Benefits: explicit separability and a uniform binding model. Risks: label collision, ambiguous context encoding, correlated root compromise, deterministic-nonce misuse, migration complexity, and substantial review/vector burden. No KDF, labels, scalar mapping, or parameter is selected here.

### Option C — Hybrid DOM Fund Derivation with Independent Domain Roots

**Classification:** REQUIRES_REVIEWER_DECISION.

Option C preserves authoritative DOM fund/output derivation and the existing Tauri product while assigning independent reviewer-approved random roots or credentials to private-context protection, state protection where appropriate, full-backup protection, owner authentication, receiving authentication, administration, and other non-fund domains. It requires encrypted persistence, atomic lifecycle ownership, explicit backup inclusion or exclusion, rotation, chain/wallet binding, and conservative non-reuse.

Benefits: compromise compartmentalization and independent credential rotation. Risks: non-seed-recoverable material, backup complexity, partial-write hazards, restore ambiguity, credential synchronization, and migration burden. No random-source, KDF, cipher, envelope, or parameter is selected here.

## Option comparison

| Criterion | Option A | Option B | Option C |
| --- | --- | --- | --- |
| DOM consensus and wallet-format compatibility | EXPLICITLY_SUPPORTED_BY_DOM_EVIDENCE | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |
| Preserve validated V1/V2 properties | EXPLICITLY_SUPPORTED_BY_DOM_EVIDENCE | PARTIALLY_SUPPORTED | PARTIALLY_SUPPORTED |
| Eliminate confirmed weaknesses | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |
| Chain, wallet, account, transaction/slate, participant and purpose separation | REQUIRES_REVIEWER_DECISION | REQUIRES_REVIEWER_DECISION | REQUIRES_REVIEWER_DECISION |
| Versioning and canonical encoding | PARTIALLY_SUPPORTED | REQUIRES_REVIEWER_DECISION | REQUIRES_REVIEWER_DECISION |
| Deterministic fund recovery | EXPLICITLY_SUPPORTED_BY_DOM_EVIDENCE | EXPLICITLY_SUPPORTED_BY_DOM_EVIDENCE | EXPLICITLY_SUPPORTED_BY_DOM_EVIDENCE |
| Full-backup recovery and seed-only limitations | PARTIALLY_SUPPORTED | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |
| Retry stability and private-context lifecycle | PARTIALLY_SUPPORTED | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |
| Non-reuse and rollback resistance | REQUIRES_REVIEWER_DECISION | REQUIRES_REVIEWER_DECISION | REQUIRES_REVIEWER_DECISION |
| Compromise compartmentalization | PARTIALLY_SUPPORTED | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |
| Tauri integration impact | EXPLICITLY_SUPPORTED_BY_DOM_EVIDENCE | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |
| Implementation complexity, interoperability, and independent-review burden | PARTIALLY_SUPPORTED | REQUIRES_REVIEWER_DECISION | REQUIRES_REVIEWER_DECISION |
| Fail-closed behavior | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION | ACHIEVABLE_WITH_APPROVED_CONSTRUCTION |

## Threat, recovery, and migration review

All families must be evaluated against cross-chain, cross-network, cross-wallet, cross-account, and cross-purpose reuse; label collision; ambiguous encoding; transaction replay; participant-role confusion; nonce/blinding reuse; exposed blinding material; predictable legacy coinbase material; backup or database rollback; restored old allocation state; credential substitution; password downgrade and KDF abuse; truncation/ciphertext substitution; unknown version; migration provenance loss; frontend or Tauri IPC leakage; logging leakage; seed or authentication compromise; and partial writes.

Recovery must distinguish deterministic DOM fund material from random/local material. Full backup must carry the approved non-reuse and lifecycle state; seed-only recovery must not manufacture contexts or credentials. Migration must import proven V2 provenance or enter typed recovery, never infer it. Tauri surfaces show those boundaries without receiving the underlying secret records.

## Independent reviewer decision table

| Required decision | DOM evidence | Protected property | Required reviewer output | Affected specifications |
| --- | --- | --- | --- | --- |
| Architecture family | V1/V2 continuity and V2 context lifecycle | DOM compatibility | OPTION A, B, C, or rejection | 0003, 0007, 0008, 0010, 0011 |
| Reusable DOM construction versus replacement | `dom-wallet-crypto`, `dom-wallet-keys`, V2 backup/state | Preserve properties without accidental scope extension | Exact reusable scope and replacement boundaries | 0007, 0008, 0011 |
| Root ownership, KDF/expansion, domain identifiers, canonical encoding | Existing construction is limited to legacy wallet envelope | Purpose separation | Approved profiles and encoding | 0007, 0010 |
| Chain/wallet/account/transaction/slate/participant binding | V2 chain-aware slate and backup records | Cross-context rejection | Exact binding model | 0003, 0007, 0008, 0010 |
| Nonce generation and scalar mapping | Existing DOM slate/fund behavior | Non-reuse | Approved construction and misuse limits | 0003, 0007 |
| AEAD, password KDF, salt, IV/nonce, AAD, envelope versioning | V1/V2 envelope evidence | Confidentiality, integrity, typed rejection | Exact V3 profile or rejection | 0007, 0008, 0010 |
| Rotation, backup inclusion, restore, migration, rollback protection | V2 full backup and legacy limitations | Continuity and recovery safety | Record ownership and activation rules | 0008, 0011 |
| Vectors, negative tests, interoperability, Tauri boundary | Current evidence and V3 assurance requirements | Verifiable, secret-free interface | Approved vector suite and test plan | 0003, 0007, 0008, 0010, 0011, 0012 |

## Vector schema and selection rules

Vectors contain: vector version; chain ID; network ID; wallet identity; purpose; construction version; object identity; encoded context; expected representation; cross-domain, cross-chain, and cross-wallet inequality; malformed encoding; unknown version; retry stability; non-reuse; backup/restore continuity; migration; password change; authentication rotation; and interoperability identifiers. Every missing output is `TO_BE_PROVIDED_BY_APPROVED_REVIEWED_CONSTRUCTION`.

Selection must preserve DOM consensus and wallet-format compatibility, satisfy every mandatory invariant, provide typed failure behavior, include negative/property/interoperability vectors, and keep all secret material outside Tauri presentation. The reviewer may select or reject a family only with an approved construction and test-vector plan.

## Prohibited shortcuts and gate

Prohibited: copying Epic code, UI, APIs, transport, labels, formats, or cryptographic parameters; treating a legacy DOM construction as automatically approved; sending secrets through Tauri IPC; adding a domain label or formula without review; reducing non-reuse floors on restore/migration; or claiming seed-only recovery restores random/local material.

`DESIGN_OPTIONS_DOCUMENTED -> INDEPENDENT_CRYPTOGRAPHIC_REVIEW -> OPTION_SELECTED_OR_REJECTED -> CONSTRUCTION_SPECIFIED -> TEST_VECTORS_APPROVED -> SPECIFICATIONS_UPDATED -> IMPLEMENTATION_AUTHORIZED`

DEC-V3-SECRET-DOMAINS remains BLOCKING until this gate completes through independent cryptographic review.
