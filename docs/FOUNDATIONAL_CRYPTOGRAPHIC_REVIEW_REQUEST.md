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
