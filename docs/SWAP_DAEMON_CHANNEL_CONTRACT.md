# Swap daemon channel — normative contract

Status: **RATIFIED REQUIREMENTS for the interop daemon integration.** The
wallet side of every requirement below is already implemented and pinned by
tests; the daemon channel MUST satisfy its side before it is wired in, or the
user-experience guarantees the wallet advertises become theater.

The discipline follows what production atomic-swap systems proved works:
persist every state before acting on it, refund automatically, resume
always, speak in typed events, and leave the user a self-custody exit that
needs no daemon at all.

## R1 — Persistence before action

No message leaves the wallet for the relay, a solver or any chain unless the
session state authorizing it is already committed to the encrypted store.

- Wallet side (done): `WalletService::swap_session_create_draft` and
  `swap_session_transition` commit the encrypted generation before
  returning; `swap_intent_create` persists the draft before any publish
  attempt. Pinned by
  `swap_draft_is_durable_before_any_publish_attempt_and_survives_restart`.
- Daemon side (required): every daemon-driven transition — publish, terms
  binding, refund armed, funding observed, claim, cancel, refund — calls the
  wallet's transition first and only acts on success. A daemon that acts
  first and records later is non-conforming.

## R2 — Refund is the machine's job, never the user's

Once refunds are armed, maturation of the cancel timelock MUST be watched
and the cancel/refund pair broadcast automatically — on the next wallet
start if the process was down when the clock struck. The user's only
obligation is to open the app.

- Wallet side (done): `swap_manual_refund_gate` encodes the exact
  permission logic (nothing locked / already terminal / not yet unlocked
  with the timestamp / maturity unknown / broadcastable), and the manual
  button is a fallback, not the mechanism.
- Daemon side (required): on connect, enumerate open sessions
  (`swap_open_sessions`), recompute timelocks, broadcast any matured
  refund, and populate `refund_unlock_unix` the moment refunds are armed.
  `RefundUnknown` states MUST be resolved on reconnect.

## R3 — Resume on every reconnect

Opening the wallet resumes every open session from committed state — the
enumeration is `swap_sessions_open` and it needs no daemon. On daemon
connect, the daemon MUST reconcile each open session against relay and
chain reality and advance it through wallet transitions, never by
replacing wallet state wholesale.

## R4 — Typed session events, never parsed logs

Every durable mutation is pushed to the UI as the committed
`SwapSessionRecord` on the `swap-session-update` event. The daemon channel
MUST route its updates through wallet transitions so this remains the only
event source. Log text is not an interface.

## R5 — Deposit watching semantics

While a session is in `UserFunding`, the daemon MUST keep
`SwapDepositWatch` truthful: quoted `minimum`/`maximum` bounds from the
accepted quote, `required_confirmations` from the destination profile's
finality, `observed_confirmations` and `observed_base_units` from chain
observation, and `insufficient_after_fees` computed with network fees
accounted for — a shortfall keeps waiting for a top-up, it never aborts
silently and never fabricates progress. The wallet renders exactly these
fields (QR, bounds, confirmations, shortfall warning) and invents none.

## R6 — Quotes carry their bounds

Every quote presented for acceptance MUST carry the deposit minimum and
maximum it commits to honor, so the user sees the bounds before anything
is locked; on acceptance those bounds are copied into the durable session
(`SwapAcceptedQuote`, `SwapDepositWatch`) and become the deposit screen.

## R7 — The recovery hatch owes the daemon nothing

`swap_leg_keys_export` derives the level-1 leg secrets from the wallet's
own seed, on demand, behind explicit acknowledgment, display-once and
never logged. No daemon design may make leg funds claimable only through
the daemon: the taproot and EVM outputs used for legs MUST remain
spendable by these exported keys in standard external tooling.
