# Foundational Protocol Decision Request

**Owner:** Soren Planck
**Decision:** DEC-STABLE-VIEW
**Severity:** HIGH

DOM Wallet V3 requires one coherent multipage scan guarantee: target-tip binding, hash-at-height evidence, and bounded ancestry evidence. Current wallet2 ChainSource behavior exposes tip and scan range, not this V3 guarantee. The wallet can fail closed but cannot create a protocol witness.

Options: A, approve a DOM StableView node/RFC capability; B, approve an equivalent proof-capable interface; C, approve a documented limited source interface with fail-closed fallback. Required tests cover same-height divergence, lower tip, view change, missing hash, bounded ancestry failure, restart, and rollback-plus-replay equivalence.

**Approval:** APPROVED OPTION A / APPROVED OPTION B / APPROVED OPTION C / REJECTED FOR REVISION
