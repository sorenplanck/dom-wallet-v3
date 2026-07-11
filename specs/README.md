# DOM Wallet V3 Specifications

**Owner:** Soren Planck

| Specification | Status | First pass | Cross-review verdict | Review blockers |
|---|---|---|---|---|
| [0000 Design Principles](0000_DESIGN_PRINCIPLES.md) | DRAFT | Foundation | CONFIRMED_CONSISTENT | DEC-CRYPTO-ENVELOPE-BINDING, DEC-ECON-BLOCK-WEIGHT |
| [0001 Threat Model](0001_THREAT_MODEL.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-ROLLBACK-PROTECTION, DEC-API-DEPLOYMENT |
| [0002 Wallet State Model](0002_WALLET_STATE_MODEL.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-CANONICAL-SERIALIZATION, DEC-RESERVATION-LIFETIME |
| [0003 Transaction Lifecycle](0003_TRANSACTION_LIFECYCLE.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-LIFECYCLE-PARTICIPANT-WIRE, DEC-RESERVATION-LIFETIME |
| [0004 Storage and Atomicity](0004_STORAGE_ATOMICITY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-CRYPTO-ENVELOPE-BINDING, DEC-ROLLBACK-PROTECTION |
| [0005 ChainSource and Synchronization](0005_CHAIN_SOURCE_AND_SYNC.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-STABLE-VIEW, DEC-RESCAN-BOUNDARY |
| [0006 Reorganization and Rollback](0006_REORG_AND_ROLLBACK.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-STABLE-VIEW, DEC-REORG-BUDGET |
| [0007 Key Derivation and Secrets](0007_KEY_DERIVATION_AND_SECRETS.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-CRYPTO-ENVELOPE-BINDING, DEC-V3-SECRET-DOMAINS |
| [0008 Backup and Recovery](0008_BACKUP_AND_RECOVERY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-CRYPTO-ENVELOPE-BINDING, DEC-BACKUP-FORMAT, DEC-ROLLBACK-PROTECTION |
| [0009 Economic Rules](0009_ECONOMIC_RULES.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-ECON-BLOCK-WEIGHT, DEC-ECON-WALLET-POLICY |
| [0010 API and Transport Security](0010_API_AND_TRANSPORT_SECURITY.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-API-DEPLOYMENT |
| [0011 Migration from V2](0011_MIGRATION_FROM_V2.md) | DRAFT | Complete | CONFIRMED_CONSISTENT | DEC-MIGRATION-MATRIX, DEC-CRYPTO-ENVELOPE-BINDING |
| [0012 Testing and Assurance](0012_TESTING_AND_ASSURANCE.md) | DRAFT | Complete | CONFIRMED_CONFLICT_RESOLVED | DEC-ASSURANCE-RELEASE, DEC-ECON-BLOCK-WEIGHT |

Required dependency order: Threat Model -> Wallet State Model -> Storage and Atomicity -> ChainSource and Synchronization -> Reorganization and Rollback -> Transaction Lifecycle -> Key Derivation and Secrets -> Backup and Recovery -> Economic Rules -> API and Transport Security -> Migration from V2 -> Testing and Assurance.

Cross-review result: 0 specifications in REVIEW, 13 specifications remaining DRAFT, 7 RESOLVED decisions, and 23 BLOCKING decisions. Gate 1 is IN PROGRESS until every foundational specification is ACCEPTED and required gate evidence is complete.
