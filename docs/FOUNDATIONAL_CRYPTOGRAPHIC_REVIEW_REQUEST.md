# Foundational Cryptographic Review Request

**Owner:** Soren Planck
**Decision:** DEC-V3-SECRET-DOMAINS
**Severity:** HIGH

DOM Wallet V3 needs approved private-context, backup, and authentication domain construction. Existing DOM evidence covers legacy derivation and envelope behavior but not V3 labels, formulas, scalar mappings, or vectors. Ad hoc labels, KDFs, nonce constructions, scalar mappings, and associated-data layouts are prohibited.

The review must establish chain and purpose binding, canonical encodings, non-reuse, misuse resistance, backup and migration consequences, vectors, negative tests, property tests, and interoperability evidence.

**Reviewer outcome:** APPROVED / APPROVED WITH REQUIRED CHANGES / REJECTED

## Epic Reference Evidence

**Pinned evidence commit:** `cd3c9677cf67a68122a496cf601c47978cf99285`
**Study report:** [Epic Secret-Domain Reference Study](../reports/EPIC_SECRET_DOMAIN_REFERENCE_STUDY.md)
**Decision status:** BLOCKING
**Decision ownership:** CRYPTOGRAPHIC_REVIEW
**Severity:** HIGH

The pinned Epic source provides explicit transaction-context persistence keyed by slate identifier and participant position, random aggregate-signature nonces, monotonic child allocation, seed-file password encryption, and distinct API-secret files. It also shows separate legacy constructions for context masking, seed encryption, API-body encryption, transport messaging, and address derivation. These mechanisms do not establish one approved, unified secret-domain framework.

Protected properties worth retaining are durable private context before later signing, deletion after the applicable finalization path, permanently advancing allocation state, recovery scans that raise observed child indexes, separate handling of wallet-fund, API, and transport material, authenticated seed-envelope failure, bounded malformed-input rejection, and restart/repost evidence. Epic-specific formulas, constants, labels, KDF profiles, XOR masking, encrypted-file formats, derivation paths, APIs, slate formats, and transport constructions MUST NOT be copied into DOM Wallet V3.

The comparison finds no Epic equivalent that supplies an approved DOM V3 construction for chain-bound and purpose-bound private contexts, backup records, authentication material, canonical encoding, nonce and blinding lifetime, rollback resistance, migration floors, or interoperable vectors. The independent reviewer must therefore select or approve DOM-specific constructions, bindings, versioning, misuse controls, vectors, negative tests, property tests, and compatibility evidence. Epic evidence is limited to protected properties and engineering lessons; it does not resolve DEC-V3-SECRET-DOMAINS or alter this request's reviewer outcome field.

## DOM Wallet, Tauri Continuity, Epic Gap-Solving Evidence, and Design Options

**Primary DOM evidence commit:** `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`
**Tauri continuity:** [DOM Tauri Product Continuity](DOM_TAURI_PRODUCT_CONTINUITY.md)
**DOM source study:** [DOM Wallet Secret-Domain Reference Study](../reports/DOM_WALLET_SECRET_DOMAIN_REFERENCE_STUDY.md)
**Epic secondary study:** [Epic Secret-Domain Reference Study](../reports/EPIC_SECRET_DOMAIN_REFERENCE_STUDY.md)
**Candidate families:** [Foundational Secret-Domain Design Options](FOUNDATIONAL_SECRET_DOMAIN_DESIGN_OPTIONS.md)

DOM Wallet V1/V2 are the primary evidence for DOM compatibility, product continuity, Tauri desktop direction, explicit private-context lifecycle, encrypted state and backup properties, restoration boundaries, and existing user workflows. The Tauri shell and established DOM product identity are retained; no candidate family replaces Tauri or adopts Epic UI, APIs, transport, or product architecture.

The DOM study identifies properties to preserve—DOM fund/slate compatibility, explicit V2 pending-slate persistence, retry stability, terminal secret wipe, versioned password-protected envelopes, atomic publication, full-backup state, chain mismatch rejection, and typed rejection—while rejecting legacy V1 public `blinding_hex`, password-only backup protection, and password-only coinbase compatibility as new V3 behavior. It also identifies the absence of an approved unified V3 construction for private-context, backup, authentication, Tauri session, canonical context, and rollback/non-reuse domains.

Epic remains secondary: it supplies only verified gap-solving properties for durable context before dependent external effects, retry durability, terminal deletion, repair/recovery categories, privilege separation, hostile-input handling, and assurance. It does not supply a DOM cryptographic construction.

Three non-selecting candidate architecture families are documented: Option A, Hardened DOM Wallet Continuity; Option B, DOM-Native Labeled Subkey Hierarchy; and Option C, Hybrid DOM Fund Derivation with Independent Domain Roots. Option A is explicitly DOM-first, not Epic adoption. Each family requires independent review for root ownership, KDF/expansion, domain identifiers, canonical context encoding, chain/wallet/account/transaction/slate/participant binding, nonce and scalar handling, AEAD and associated data, password protection, backup/restore/migration, rollback protection, vectors, negative tests, interoperability, and Tauri secret-boundary enforcement.

**Selected option:** UNSELECTED
**Construction status:** NOT_SPECIFIED
**Vectors:** NOT_PROVIDED
**Independent review:** NOT_COMPLETED
**Decision status:** BLOCKING
**Decision ownership:** CRYPTOGRAPHIC_REVIEW
**Severity:** HIGH

DEC-V3-SECRET-DOMAINS remains BLOCKING. An internal design-options package is not independent approval. The existing reviewer outcome field remains intentionally unpopulated: **APPROVED / APPROVED WITH REQUIRED CHANGES / REJECTED**.
