# DOM Wallet V3 Specifications

**Owner:** Soren Planck

| Specification | Status | First pass |
|---|---|---|
| [0000 Design Principles](0000_DESIGN_PRINCIPLES.md) | DRAFT | Foundation |
| [0001 Threat Model](0001_THREAT_MODEL.md) | DRAFT | Complete |
| [0002 Wallet State Model](0002_WALLET_STATE_MODEL.md) | DRAFT | Complete |
| [0003 Transaction Lifecycle](0003_TRANSACTION_LIFECYCLE.md) | DRAFT | Complete |
| [0004 Storage and Atomicity](0004_STORAGE_ATOMICITY.md) | DRAFT | Complete |
| [0005 ChainSource and Synchronization](0005_CHAIN_SOURCE_AND_SYNC.md) | DRAFT | Complete |
| [0006 Reorganization and Rollback](0006_REORG_AND_ROLLBACK.md) | DRAFT | Complete |
| [0007 Key Derivation and Secrets](0007_KEY_DERIVATION_AND_SECRETS.md) | DRAFT | Complete |
| [0008 Backup and Recovery](0008_BACKUP_AND_RECOVERY.md) | DRAFT | Complete |
| [0009 Economic Rules](0009_ECONOMIC_RULES.md) | DRAFT | Complete |
| [0010 API and Transport Security](0010_API_AND_TRANSPORT_SECURITY.md) | DRAFT | Complete |
| [0011 Migration from V2](0011_MIGRATION_FROM_V2.md) | DRAFT | Complete |
| [0012 Testing and Assurance](0012_TESTING_AND_ASSURANCE.md) | DRAFT | Complete |

All specifications 0001 through 0012 have completed a first design pass and remain DRAFT.

Required dependency order: Threat Model -> Wallet State Model -> Storage and Atomicity -> ChainSource and Synchronization -> Reorganization and Rollback -> Transaction Lifecycle -> Key Derivation and Secrets -> Backup and Recovery -> Economic Rules -> API and Transport Security -> Migration from V2 -> Testing and Assurance.

Gate 1 is IN PROGRESS until adversarial cross-review, blocking-decision closure, REVIEW promotion, and final ACCEPTED status. DOM semantics are sovereign; external references contribute protected properties and engineering strategies only.
