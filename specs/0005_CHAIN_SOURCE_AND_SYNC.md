# DOM Wallet V3 Chain Source and Synchronization

**Status:** DRAFT
**Owner:** Soren Planck

## Purpose and scope

This specification defines a transport-independent `ChainSource` contract and deterministic wallet synchronization. It controls observation of the DOM canonical chain; it does not define a network transport, a foreign wire format, consensus validation rules, or final transaction lifecycle. A source supplies evidence and bounded data; it never owns wallet state.

## Authoritative sources and terminology

Sources are 0000 through 0004, `docs/CONFIRMED_DESIGN_INPUTS.md`, and DOM Wallet V1/V2 chain reconciliation behavior. `DOM-W2-SYNC-001` is a confirmed mandatory requirement. A **canonical cursor** is the verified pair `(height, block_hash)` and stable-view evidence committed in the same DUW as the observations it summarizes. A **stable view** is a source-provided, bounded scan identity that binds tip, pagination, and ancestry responses to one claimed canonical view. A **reconciliation** derives wallet chain observations from a validated stable view and local intent.

## ChainSource contract and boundaries

An adapter MUST expose these transport-neutral capabilities, or explicitly report them unsupported before sync starts:

| Contract operation | Required result |
|---|---|
| Negotiate capabilities | Protocol/schema version, selected DOM chain ID, maximum page and response limits, stable-view support, hash-at-height, ancestry evidence, output/spend scan data, and error classification. |
| Obtain canonical tip | Claimed height, block hash, chain ID, view binding, and freshness metadata sufficient to validate the response. |
| Obtain hash at height | Exact height, hash, chain ID, and same view binding; absence is an explicit result, not an inferred hash. |
| Obtain ancestry evidence | Bounded sequence or proof of hashes linking requested heights to the claimed view. |
| Scan range | Ascending bounded pages of canonical DOM scan data, page continuation, range bounds, view binding, and resource accounting. |
| Query transaction or output observation | Bounded DOM-native identifiers and evidence under a view binding, where capability supports it. |

Source authentication identifies a responder or channel; data validity requires chain ID, schema, boundedness, view binding, and DOM-consistent evidence. An authenticated source MAY be stale or malicious. A source MUST NOT receive wallet secrets, private contexts, unredacted audit data, or authority to modify local control.

## Mandatory freshness rule: DOM-W2-SYNC-001

Freshness MUST compare both height and block hash. A wallet MAY skip reconciliation only when it can verify that the source's canonical tip has the same height and the same block hash as its committed cursor, with compatible chain ID and valid view evidence. A same-height reorg MUST force reconciliation. A lower-height canonical view MUST force reconciliation. A missing hash, changed hash, unverifiable hash, absent cursor, chain mismatch, or invalid view binding MUST force reconciliation or a fail-closed recovery state; none may be treated as fresh.

Cursor advancement and every corresponding output, spend, transaction, maturity, recovery-event, and audit change MUST commit atomically in the DUW defined by 0004. A height-only shortcut is prohibited.

## Synchronization behavior

**Initial scan** obtains capabilities, validates chain ID, obtains a stable tip, scans bounded pages from the configured genesis/recovery boundary to that tip, validates page continuity and view binding, derives observations, and commits one or more resumable DUWs whose cursor checkpoints match committed work. It MUST not present a final balance before the completed view is committed.

**Incremental sync** first executes the mandatory freshness rule. If not fresh, it obtains sufficient ancestry evidence to decide whether the cursor is on the claimed chain. If it is, it scans from the cursor successor through the stable tip. If it is not, it invokes 0006. A source response changing view binding, height, hash, chain ID, order, range, or page continuity during the scan invalidates the scan attempt; the wallet MUST restart from a committed checkpoint or switch source.

**Reconciliation** applies all observations and maturity recalculation to the canonical model, preserves local intent, and commits changes with the cursor. Repeating reconciliation against the same stable canonical view and local intent MUST be idempotent. A **full rescan** discards only derived chain observations and indexes as authorized by 0006, retains local intent and non-reuse evidence, and deterministically rebuilds observations from an approved scan boundary.

## Pagination, limits, retry, and source switching

Pages MUST be ascending, non-overlapping, bounded by negotiated limits, bound to the same stable view, and include enough identity to detect omission, duplication, or reordering. The wallet MUST set maximum response bytes, records per page, pages per operation, scan height span, ancestry depth, retries, time, and memory. Exhaustion, malformed response, inconsistent view, unavailable capability, timeout, authentication failure, and chain mismatch are distinct error classes.

Retries MAY repeat an idempotent read against the same or a new source. On switching sources, the wallet MUST renegotiate capabilities and revalidate the current committed cursor and target stable view; it MUST NOT splice pages from unrelated views. Repeated inconsistency or exceeded limits MUST fail closed into a resumable recovery state, with a user-visible provisional status and a safe full-rescan option.

## Persistence, crash, restart, and reorganization

Read responses are not durable wallet state. Before any cursor checkpoint is durable, all associated records MUST have passed domain validation and be included in the same DUW. A crash before acknowledgement leaves the previous cursor authoritative. A crash after acknowledgement resumes from the committed cursor and recovery event; it MAY re-read pages but MUST produce the same state. Stable-view tokens are hints unless their validity is independently verifiable; expired tokens require a fresh stable view and reconciliation.

Same-height hash divergence and lower tips are reorganization entry conditions. The wallet MUST preserve the triggering evidence, invoke the durable plan of 0006, and block selection from provisional chain observations until the plan reaches a committed safe phase. A source that cannot provide required bounded ancestry evidence MUST not cause guessed rollback; it requires safe full rescan or recovery.

## Valid and invalid behavior

Valid behavior validates negotiated chain identity and bounded stable-view data, reconciles idempotently, and commits the cursor with observations. Invalid behavior includes accepting height alone as freshness, advancing cursor independently, treating an authenticated source as authoritative consensus, accepting foreign-chain pages, mixing views, guessing ancestry, using unbounded responses, or marking a balance current after a failed or partial scan. Invalid input MUST not mutate canonical observations.

## Security considerations

Query minimization and capability separation SHOULD limit privacy leakage. The wallet SHOULD vary or batch source queries only when that does not weaken correctness. It MUST bound malicious-source work and preserve enough redacted evidence to diagnose recovery without revealing output ownership. Source selection and transport authentication are deferred to 0010; their absence cannot relax data validation.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Capability validation, cursor comparison, page continuity, error taxonomy, and rejection of mismatched chain/view/hash. |
| Property tests | Repeated reconciliation is idempotent; arbitrary page segmentation equals one-page scan; no cursor advances without matching observation state. |
| Integration tests | Initial scan, incremental scan, source switch, stale/malicious source, timeout, restart, full rescan, same-height reorg, lower-height tip, and DOM-native maturity observations. |
| Fault-injection tests | Failure before/after cursor DUW acknowledgement, page loss/duplication/reordering, changed view token, source failure during switch, and exhausted limits. |
| Fuzz targets | Capability replies, tip/hash/ancestry replies, page framing, oversized counts, inconsistent ranges, and malformed identifiers; no panic or unbounded allocation. |

## Acceptance criteria for REVIEW

Move to REVIEW only when the DOM-W2-SYNC-001 cases are demonstrated in the required test plan; 0004 proves cursor atomicity; 0006 proves bounded rollback; and the selected DOM consensus evidence specifies every scan datum and maturity input.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0004, and 0006. Specification 0003 supplies transaction observation/lifecycle mapping; 0009 supplies economic interpretation; 0010 supplies transport authorization.

* **Stable-view evidence format:** affects detection of moving-source responses. Evidence required: DOM node capability and consensus-interface analysis. Gate: chain-source design review.
* **Minimum independent-source policy:** affects detection of a consistently malicious but internally coherent source. Evidence required: privacy, availability, and deployment threat analysis. Gate: 0010 and 0012 review.
* **Full-rescan recovery boundary:** affects scan cost and recoverability. Evidence required: approved 0007/0008 recovery guarantees. Gate: 0008 review.

## Review Blockers

* DEC-STABLE-VIEW
* DEC-RESCAN-BOUNDARY
