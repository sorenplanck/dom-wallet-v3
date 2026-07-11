# DOM Wallet V3 Specifications

**Owner:** Soren Planck

| Specification | Status | First pass | Cross-review verdict | Review blockers |
|---|---|---|---|---|
| [0000 Design Principles](0000_DESIGN_PRINCIPLES.md) | REVIEW | Foundation | CONFIRMED_CONSISTENT | None |
| [0001 Threat Model](0001_THREAT_MODEL.md) | REVIEW | Complete | CONFIRMED_CONSISTENT | None |
| [0002 Wallet State Model](0002_WALLET_STATE_MODEL.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0003 Transaction Lifecycle](0003_TRANSACTION_LIFECYCLE.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-V3-SECRET-DOMAINS |
| [0004 Storage and Atomicity](0004_STORAGE_ATOMICITY.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0005 ChainSource and Synchronization](0005_CHAIN_SOURCE_AND_SYNC.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0006 Reorganization and Rollback](0006_REORG_AND_ROLLBACK.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0007 Key Derivation and Secrets](0007_KEY_DERIVATION_AND_SECRETS.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-V3-SECRET-DOMAINS |
| [0008 Backup and Recovery](0008_BACKUP_AND_RECOVERY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-V3-SECRET-DOMAINS |
| [0009 Economic Rules](0009_ECONOMIC_RULES.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |
| [0010 API and Transport Security](0010_API_AND_TRANSPORT_SECURITY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-V3-SECRET-DOMAINS |
| [0011 Migration from V2](0011_MIGRATION_FROM_V2.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-V3-SECRET-DOMAINS |
| [0012 Testing and Assurance](0012_TESTING_AND_ASSURANCE.md) | REVIEW | Complete | CONFIRMED_CONFLICT_RESOLVED | None |

Required dependency order: Threat Model -> Wallet State Model -> Storage and Atomicity -> ChainSource and Synchronization -> Reorganization and Rollback -> Transaction Lifecycle -> Key Derivation and Secrets -> Backup and Recovery -> Economic Rules -> API and Transport Security -> Migration from V2 -> Testing and Assurance.

Owner-approved StableView Option C result: 8 specifications in REVIEW, 5 specifications remaining DRAFT, 29 effective RESOLVED decisions, and 1 effective BLOCKING decision. DEC-STABLE-VIEW is resolved by the ScanTarget WALLET POLICY in 0005; DEC-V3-SECRET-DOMAINS remains the sole HIGH cryptographic-review blocker. Gate 1 is IN PROGRESS until every foundational specification is ACCEPTED and required gate evidence is complete.
