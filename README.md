<div align="center">

<img src="assets/dom-wallet-v3-banner.svg" alt="DOM Wallet V3" width="760">

<br>

[![Project Status](https://img.shields.io/badge/status-specification%20%26%20architecture-008c95)](#project-status)
[![Language](https://img.shields.io/badge/language-Rust-186faf)](https://www.rust-lang.org/)
[![Foundation Checks](https://github.com/sorenplanck/dom-wallet-v3/actions/workflows/foundation.yml/badge.svg)](https://github.com/sorenplanck/dom-wallet-v3/actions/workflows/foundation.yml)
[![Security Policy](https://img.shields.io/badge/security-policy-102a43)](SECURITY.md)
[![Repository](https://img.shields.io/badge/repository-DOM%20Wallet%20V3-334e68)](https://github.com/sorenplanck/dom-wallet-v3)

# DOM Wallet V3

### A secure, recoverable, and DOM-native wallet architecture.

</div>

---

DOM Wallet V3 is a new, independently designed wallet implementation for the DOM Protocol.

The project combines:

* validated protocol knowledge and working properties from DOM Wallet V1 and V2;
* mature wallet-engineering strategies studied from Epic Wallet;
* a new DOM-native architecture;
* explicit state machines and invariants;
* atomic persistence and crash recovery;
* canonical synchronization using block height and block hash;
* complete backup, restore, and migration contracts;
* adversarial, property-based, restart, reorganization, and end-to-end testing.

DOM Wallet V3 is not a port of Epic Wallet and is not a cosmetic refactor of DOM Wallet V2.

Every implementation in this repository must be independently designed and written for the DOM Protocol.

> **Governing rule:** `DOM semantics > Epic strategy`

---

## Why DOM Wallet V3?

A wallet is more than a user interface for sending transactions.

It is responsible for protecting:

* ownership keys;
* private transaction contexts;
* outputs and balances;
* derivation positions;
* transaction history;
* backup integrity;
* synchronization state;
* recovery evidence;
* non-reuse guarantees.

A wallet can appear functional while still failing under:

* interrupted writes;
* node outages;
* duplicated requests;
* concurrent transactions;
* stale chain data;
* same-height reorganizations;
* corrupted backups;
* incomplete restores;
* migration errors;
* transaction resubmission;
* malicious or inconsistent node responses.

DOM Wallet V3 is being designed from the beginning to make these behaviors explicit, deterministic, recoverable, and testable.

---

# DOM Protocol Philosophy

DOM Wallet V3 preserves the philosophy and technical sovereignty of the DOM Protocol.

The wallet must follow exclusively:

* DOM consensus rules;
* DOM cryptographic primitives;
* DOM transaction and slate formats;
* DOM chain identity;
* DOM fee and weight rules;
* DOM coinbase and maturity rules;
* DOM privacy requirements;
* DOM backup and recovery guarantees.

Reference implementations may teach engineering strategies, but they do not define DOM behavior.

The project does not inherit Epic-specific:

* slate formats;
* transaction formats;
* derivation paths;
* fee formulas;
* weight formulas;
* kernel rules;
* commitment rules;
* proof-rewind mechanisms;
* KDF parameters;
* Tor, Epicbox, or Keybase transports;
* historical compatibility behavior.

---

# Core Design Principles

## One canonical wallet state

Outputs, reservations, transactions, private contexts, derivation positions, chain cursors, and recovery events must belong to one coherent, versioned state model.

## Explicit state machines

Every transition must define:

* preconditions;
* postconditions;
* invalid transitions;
* persistent effects;
* crash behavior;
* restart behavior;
* reorganization behavior;
* required tests.

## Atomic durable operations

A logical operation must not leave only part of its state committed.

For example, send preparation may require a single durable operation covering:

* input reservations;
* change derivation;
* transaction record;
* private transaction context;
* derivation counters;
* recovery metadata.

Either the complete operation commits, or none of it becomes active.

## Crash recovery by design

Every persistent operation must define what happens if the process stops:

* before the operation;
* during the operation;
* after the local commit;
* after an external message is sent;
* after node submission;
* before the result is recorded.

## Canonical chain identity

Height alone is not sufficient to prove wallet freshness.

DOM Wallet V3 identifies its canonical synchronization position using at least:

```text
(height, block_hash)
```

A same-height reorganization, lower-height canonical tip, missing hash, changed hash, or unverifiable hash must force reconciliation.

## Reorganization as normal behavior

Chain reorganizations are expected protocol events, not manual-repair exceptions.

The wallet must support:

* common-ancestor discovery;
* durable rollback planning;
* output reclassification;
* removed receive handling;
* removed spend handling;
* transaction reclassification;
* coinbase maturity recalculation;
* cursor rewind;
* canonical replay;
* restart during reorganization;
* deterministic convergence.

## No silent secret reuse

Restore, rollback, retry, cancellation, migration, and crash recovery must not cause reuse of:

* nonces;
* blindings;
* derivation positions;
* private transaction contexts;
* equivalent secret material.

## Recovery is an architectural requirement

Seed-only recovery and full-backup recovery are different products with different guarantees.

The project must explicitly define:

* what a seed can recover;
* what requires a full backup;
* what cannot be reconstructed;
* how derivation positions are preserved;
* how restores are validated;
* how cross-chain imports are rejected;
* how secret reuse is prevented.

---

# Project Status

> **Current phase: Foundation and Specification**

DOM Wallet V3 is not currently a production wallet.

The repository does not yet authorize:

* production wallet use;
* real funds;
* production seeds;
* mainnet wallet operation;
* replacement of DOM Wallet V1 or V2.

Mainnet-capable code paths may be implemented during development, but use with real funds requires:

1. complete specifications;
2. complete implementation gates;
3. adversarial and end-to-end verification;
4. testnet validation;
5. independent security review;
6. remediation of applicable findings;
7. reproducible release artifacts;
8. explicit project authorization.

---

# Target Architecture

```text
User interfaces and automation
              │
              ▼
Capability APIs and application services
              │
              ▼
Lifecycle, synchronization and recovery orchestration
              │
              ▼
Canonical DOM Wallet domain model
              │
      ┌───────┼────────┬──────────────┐
      ▼       ▼        ▼              ▼
   Crypto   Storage  ChainSource   Transport ports
      │       │        │              │
      └───────┴────────┴──────────────┘
              │
              ▼
        DOM Protocol adapters
```

Higher-level interfaces may depend on domain contracts.

Domain rules must not depend on:

* CLI;
* HTTP;
* GUI;
* database brands;
* concrete node clients;
* transport implementations;
* runtime frameworks.

---

# Planned Workspace

```text
dom-wallet-v3/
├── crates/
│   ├── dom-wallet-domain/
│   ├── dom-wallet-crypto/
│   ├── dom-wallet-storage/
│   ├── dom-wallet-chain-source/
│   ├── dom-wallet-sync/
│   ├── dom-wallet-reorg/
│   ├── dom-wallet-lifecycle/
│   ├── dom-wallet-backup/
│   ├── dom-wallet-node/
│   ├── dom-wallet-api/
│   ├── dom-wallet-cli/
│   └── dom-wallet-testkit/
├── specs/
├── docs/
├── tests/
│   ├── integration/
│   ├── e2e/
│   ├── restart/
│   ├── reorg/
│   ├── migration/
│   └── adversarial/
├── fuzz/
├── scripts/
├── examples/
├── reports/
└── .github/workflows/
```

Crates will be introduced only after their contracts and dependency directions are approved.

---

# Planned Capabilities

## Wallet lifecycle

* wallet creation;
* safe open and close;
* lock and unlock;
* credential rotation;
* integrity validation;
* restart recovery.

## Accounts and derivation

* versioned accounts;
* domain-separated derivation;
* independent coinbase, receive, and change domains;
* monotonic derivation positions;
* non-reuse evidence;
* migration-safe counters.

## Outputs and balances

* canonical output detection;
* confirmation;
* maturity;
* reservation;
* spending;
* rollback;
* historical retention;
* derived balance views.

Planned balance views include:

* total;
* confirmed;
* spendable;
* locked;
* immature;
* pending incoming;
* pending outgoing;
* reorganization-provisional.

## Transactions

* draft;
* preparation;
* input reservation;
* participant exchange;
* finalization;
* durable submission intent;
* node submission;
* mempool observation;
* canonical confirmation;
* cancellation;
* expiration;
* repost;
* rollback;
* reorganization reclassification.

## Synchronization

* initial scan;
* incremental synchronization;
* bounded pagination;
* stable chain views;
* source switching;
* interrupted-scan recovery;
* canonical reconciliation;
* same-height reorganization detection;
* lower-height rollback;
* full rescan.

## Backup and recovery

* versioned full backups;
* authenticated encryption;
* chain-bound metadata;
* consistent-generation snapshots;
* staged restore;
* seed-only recovery;
* full-backup recovery;
* post-restore validation;
* cross-chain rejection;
* derivation non-reuse verification.

## Migration

* DOM Wallet V2 dry-run;
* source validation;
* staged conversion;
* canonical chain reconciliation;
* derivation-floor calculation;
* difference report;
* activation or rollback;
* post-migration backup and restore.

---

# Security Model

DOM Wallet V3 must protect:

* root seed;
* private keys;
* blindings;
* nonces;
* private transaction contexts;
* passwords;
* authentication credentials;
* output ownership;
* balances;
* transaction metadata;
* derivation state;
* backups;
* canonical synchronization state.

The project is designed to resist or safely handle:

* malformed input;
* replay;
* duplicate requests;
* concurrent reservations;
* malicious or stale nodes;
* same-height reorganizations;
* partial storage writes;
* database corruption;
* backup theft;
* cross-chain substitution;
* resource exhaustion;
* credential misuse;
* secret leakage;
* migration inconsistencies;
* dependency and build-system compromise.

See [SECURITY.md](SECURITY.md) for the vulnerability-reporting policy.

---

# Verification Strategy

A feature is not complete because its happy path works.

DOM Wallet V3 requires multiple verification layers.

## Unit tests

For:

* predicates;
* state transitions;
* canonical encoding;
* parsers;
* economics;
* error mapping.

## Property tests

For:

* balance decomposition;
* reservation uniqueness;
* serialization round trips;
* synchronization idempotency;
* derivation monotonicity;
* secret non-reuse;
* rollback and replay convergence.

## Model-based tests

Generated command sequences will be compared against a simpler executable reference model.

## Restart tests

Every durable operation must be interrupted:

* before commit;
* during commit;
* after commit;
* before an external action;
* after an external action;
* before result persistence.

## Reorganization tests

Including:

* same-height reorganization;
* lower-height canonical tip;
* repeated reorganization;
* deep bounded reorganization;
* reorganization during rollback;
* source switching;
* no-common-ancestor fallback.

## End-to-end tests

Including:

* multiple wallets;
* multiple DOM nodes;
* complete send and receive flow;
* node restart;
* wallet restart;
* synchronization;
* reorganization;
* backup;
* restore;
* V2 migration.

## Fuzzing

Planned fuzz targets include:

* API payloads;
* transaction messages;
* backup containers;
* storage records;
* migration parsers;
* ChainSource responses;
* canonical decoders;
* state-machine command sequences.

---

# Implementation Gates

DOM Wallet V3 follows dependency-ordered gates rather than calendar estimates.

| Gate    | Scope                                           |
| ------- | ----------------------------------------------- |
| Gate 0  | Repository foundation and engineering baselines |
| Gate 1  | Accepted foundational specifications            |
| Gate 2  | Domain model and deterministic testkit          |
| Gate 3  | Cryptography and durable storage                |
| Gate 4  | ChainSource and synchronization                 |
| Gate 5  | Reorganization and rollback                     |
| Gate 6  | Transaction lifecycle                           |
| Gate 7  | Backup and recovery                             |
| Gate 8  | APIs, CLI, and transports                       |
| Gate 9  | DOM Wallet V2 migration                         |
| Gate 10 | Local/regtest DOM integration                   |
| Gate 11 | Testnet preview                                 |
| Gate 12 | Independent security review                     |
| Gate 13 | Audited operational release                     |

Each gate must produce reproducible evidence tied to an exact commit.

---

# Specifications

The normative project specifications live in [`specs/`](specs/).

Planned specifications include:

* Design Principles
* Threat Model
* Wallet State Model
* Transaction Lifecycle
* Storage and Atomicity
* ChainSource and Synchronization
* Reorganization and Rollback
* Key Derivation and Secret Handling
* Backup and Recovery
* Economic Rules
* API and Transport Security
* Migration from DOM Wallet V2
* Testing and Assurance

Implementation must not silently replace unresolved specification decisions.

---

# Engineering References

DOM Wallet V3 uses two primary sources of engineering knowledge.

## DOM Wallet V1 and V2

They provide DOM-specific experience involving:

* consensus integration;
* cryptographic primitives;
* chain ID;
* transaction and slate formats;
* fee and weight rules;
* coinbase behavior;
* backups;
* node integration;
* known failures;
* validated tests.

Existing DOM behavior is not migrated automatically.

Each component must be classified as:

* retained;
* adapted;
* independently reimplemented;
* rejected.

## Epic Wallet

Epic Wallet is studied as a mature reference for:

* architectural separation;
* storage and lifecycle contracts;
* transaction-context persistence;
* output reconciliation;
* API privilege separation;
* failure handling;
* recovery;
* test organization.

Epic Wallet is not the source-code base, protocol specification, or compatibility target for DOM Wallet V3.

See:

* [`docs/REFERENCE_BASELINE.md`](docs/REFERENCE_BASELINE.md)
* [`docs/ENGINEERING_SOURCES.md`](docs/ENGINEERING_SOURCES.md)
* [`docs/EPIC_DOM_ADOPTION_MATRIX.md`](docs/EPIC_DOM_ADOPTION_MATRIX.md)
* [`docs/CONFIRMED_DESIGN_INPUTS.md`](docs/CONFIRMED_DESIGN_INPUTS.md)

---

# Building

There is currently no functional wallet implementation to build.

The repository is in the specification and architecture phase.

When the first crates are introduced, the expected development workflow will include:

```bash
cargo fmt --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets
cargo test --workspace
```

Additional security and verification commands will be documented as their corresponding gates are introduced.

---

# Contributing

The project follows a specification-first process.

Before implementing a feature:

1. identify the protected property;
2. define the invariant;
3. update or create the specification;
4. define acceptance criteria;
5. define tests;
6. implement the smallest DOM-native solution;
7. run the required gates;
8. review the evidence.

All repository artifacts must be written in English.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

# Authorship

All commits and repository artifacts identify:

```text
Soren Planck <sorenplanck@tutamail.com>
```

`Co-authored-by` trailers and automated-tool attribution are prohibited.

---

# License

A project license has not yet been selected.

The license decision must consider:

* compatibility with the DOM Protocol;
* dependency licenses;
* patent provisions;
* contribution policy;
* redistribution objectives;
* attribution requirements.

See [`docs/LICENSE_DECISION.md`](docs/LICENSE_DECISION.md).

---

<div align="center">

## DOM Wallet V3

**Secure state. Deterministic recovery. Native DOM sovereignty.**

</div>
