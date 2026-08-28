# DOM Wallet — swap tab, working design

Status: **WORKING DRAFT, NOT RATIFIED, NOT PUBLISHED.** A product design for
the operator to react to. It invents no protocol rule: every object named here
is a type that already exists in `crates/rfq`, `crates/kaystra-core` or the
`contracts/` tree, and where a product choice is open it is marked as an open
question rather than silently decided.

## Premise, as agreed with the operator

1. **Level-1 wallet.** The DOM wallet derives Bitcoin and EVM keys from the
   same BIP39 seed it already uses (`dom-wallet-keys` is already BIP32/BIP39
   with conformance vectors; DOM is `coin_type` 330, so Bitcoin taproot is
   `m/86'/0'` and EVM is `m/44'/60'`). Those keys exist to sign swap legs.
   Funds **transit**; they do not rest there. No arbitrary send, no token
   browsing, no dApp connection in v1.
2. **Not an order book — an RFQ board.** The user publishes an intent; solvers
   answer with quotes; one quote is selected; a swap session runs. This is
   what the ratified F6 design already is, and it is what keeps I1
   (self-custody) intact: an order book needs custody or on-chain matching.
3. **Chain profiles.** Every enabled network is a profile, not a hardcode.

## The four screens

### 1. Intent — "what do you want"

The user states the route and the amount. Nothing is locked, nothing is
signed, nothing touches a chain.

```
   From  [ BTC        ▾ ]   0.01
   To    [ USDT/Base  ▾ ]   ~ 640 USDT
         ────────────────────────────
   Protection  minimum received  [ 635 ]
   Valid for   [ 10 min ▾ ]
                       [ Request quotes ]
```

Underneath this screen the app builds an `RfqV1`, whose fields map one to one
onto what the form collects:

| Form field | `RfqV1` field |
| --- | --- |
| From / To | `route: RouteV1` (legs and `LegDirectionV1`) |
| amount + "minimum received" | `mode: RfqModeV1::ExactIn { input_amount, minimum_output }` |
| — (or "exactly X out") | `mode: RfqModeV1::ExactOut { exact_output, maximum_input }` |
| "valid for" | `quote_deadline: TimelockSpec` |
| the fee ceiling the app applies | `fee_limit: FeeLimitV1` |
| implied by the chain profile | `timelock_domain: TimelockDomainV1` |
| assurance policy of the profile | `assurance_policy_ref`, `policy_version` |

`RfqModeV1` is why the form has a "minimum received" and not a price: the
user's protection bound is part of the request, so a quote that would leave
him worse than his own floor is inadmissible before he ever sees it.

**One constraint the UI must respect, not paper over:** `TimelockDomainV1` is
a single domain per settlement, and mixing domains is refused rather than
converted (A4). So a route whose two legs would need different domains cannot
be offered — the pair selector must know this and simply not present it.

### 2. Quotes — "what the market answers"

Quotes arrive over the relay for a few seconds and the list fills in.

```
   Quotes for your intent                    closing in 0:07
   ────────────────────────────────────────────────────────
   ● Solver A     642.10 USDT    fee 0.9    ~4 min   bond ✓
     Solver B     640.55 USDT    fee 1.2    ~4 min   bond ✓
     Solver C     639.80 USDT    fee 0.7    ~12 min  bond ✓
   ────────────────────────────────────────────────────────
   Selected by best real outcome (D-018)         [ Details ]
                                        [ Accept ]
```

Each row is a `QuoteV1`. Three things are shown because three things are
checked, and hiding them would be dishonest:

- **the output**, which is what the quote competes on in `ExactIn`;
- **the fee**, checked against `fee_limit` — `FeeAboveLimit` refuses anything
  over the ceiling;
- **the bond**, which is the `bond_reserved_exclusive` fact in the
  admissibility check. A solver without an exclusively reserved bond is
  inadmissible. This is the user's protection against a solver who accepts and
  vanishes, and it is worth surfacing as a visible tick rather than buried.
- **the estimated time**, which comes from the destination chain profile's
  finality, not from the solver's promise.

**Selection follows D-018: the user's real outcome, not the lowest advertised
fee.** The ratified rejection is explicit — lowest-fee-alone selection permits
worse execution behind a cheap headline. The UI therefore pre-selects by real
outcome and lets the user override; it must never sort by fee alone.

### 3. Execution — "watch it happen"

Once a quote is accepted the settlement machine runs. The screen mirrors the
real states of `SettlementState`, so the user is never shown a stage the
engine is not in:

```
   Swapping 0.01 BTC → 640 USDT on Base

   ✓ Refunds armed         your money is recoverable from here on
   ✓ You funded            Bitcoin  1/2 confirmations
   ✓ Solver funded         Base     verified
   ◐ Claiming              revealing the secret
   ○ Done

   If anything fails, your refund unlocks at 14:32.      [ Details ]
```

Two things in this screen are load-bearing and must not be cosmetic:

**"Refunds armed" comes first, and that is I5.** The refund is signed,
validated and persisted **before** any funding is broadcast. Showing it as the
first completed step is honest and is the single most reassuring thing the app
can tell a user: from that line onward, the worst case is a delay, not a loss.

**The refund time is always visible.** The user should never have to ask what
happens if it goes wrong; the answer is on screen with a clock.

### 4. History — the receipt

Per swap: the route, the amounts, the fee actually paid, the terminal
(`Settled` or `Refunded`), and the transaction ids on both chains. The
terminal is read from the durable store, not inferred from the UI's last
known state.

## What flows underneath

```
  user app            relay                 solver
     │                  │                      │
     │──── RfqV1 ──────►│───── broadcast ─────►│   intent, no chain touched
     │                  │                      │
     │◄─── QuoteV1 ─────│◄──── quotes ─────────│   each with bond + fee
     │                  │                      │
     │   [admissibility: fee ≤ limit, bond reserved, policy, deadline]
     │                  │                      │
     │──── AcceptanceV1 / SelectionV1 ────────►│   one quote chosen
     │                  │                      │
     │◄════ TermsBindingV1 — the frozen terms ═►│  terms_hash, adaptor point T
     │                  │                      │
     │        ── swap session (F1/F2/F5/F7) ──  │
     │   refunds armed → fundings → claim → t revealed → both legs settle
```

The intent and the quotes are **messages, never chain objects**. Nothing about
the RFQ is public on any chain, which is what preserves DOM
indistinguishability (I8): the DOM leg of a settled swap looks like an
ordinary DOM transaction.

`TermsBindingV1` is where the product stops and the proven protocol begins:
from the frozen terms onward this is exactly the machinery the F7 laboratory
has settled twenty-one live routes with.

## Chain profiles

A network is enabled by adding a profile, not by touching the engine:

```
profile {
  chain_id, deployed lock contract (native + ERC-20 variants),
  ChainTimingBoundsV1     — block time bounds, reorg, observation, broadcast
  FinalityPolicyV1        — min_confirmations, max_reorg_depth
  assets                  — native + the allowed ERC-20 list
}
```

Initial set, and the honest reason for each:

| Network | Status | Why |
| --- | --- | --- |
| Ethereum | ratified target | A9: EVM = Sepolia for F3, i.e. Ethereum |
| Arbitrum, Optimism, Base | **proposed** | EVM-equivalent, standard `ecrecover` precompile, and where USDT/USDC liquidity actually is at a fee a retail user will pay |
| zkSync Era, Polygon zkEVM, Linea, Scroll | **pending verification** | they reimplement precompiles; `ecrecover` must be proven bit-identical before any of them is offered |
| Bitcoin | ratified | Annex M v3.3, regtest + custom Signet |

**The verification for a zkEVM is cheap and already written:** run the
`Vectors.t.sol` scalar corpus on that chain and require every
`addressOfScalarTimesG(t)` to match `vm.addr(t)`. It either matches or the
chain does not ship.

**The risk on an L2 is not the contract — it is the timelock ladder.** The
deadline is `block.timestamp`, which on a rollup is the sequencer's. A stalled
sequencer is a real, documented event on every one of these networks. The
scenario that must be impossible is: the sequencer freezes, the other leg's
refund matures, and one side claims while the other refunds. That is exactly
the atomicity the product sells.

The defence already exists and is proven to work: `ChainTimingBoundsV1` per
profile, and `bind_and_validate_funding_anchors` refuses an unsafe window on
its own — that is what produced `UnsafeCrossChainWindow` in B-F7-013. Each L2
therefore needs its own generous bounds for sequencer stall, and the validator
enforces them without any new code.

**Consequence for the UI:** estimated time differs per network because
finality differs. Showing Base settling in minutes and Ethereum taking longer
is not a defect to hide; it is the truth, and it is a reason to choose the DOM
over a bridge that hides its own assumptions.

## The USDT question, answered

`ConditionLockERC20V2` already exists with its own Foundry suite and its own
gas report. Token swaps were designed in from the start; enabling USDT on a
network is a profile entry plus a deployment, not new protocol work.

One token-specific caveat to carry: USDT on Ethereum mainnet is a
non-standard ERC-20 (its `transfer` returns no boolean). The contract uses
OpenZeppelin `SafeERC20`, which handles exactly that class of token — so the
case is covered, but it should be verified per token rather than assumed, the
same way `ecrecover` is verified per chain.

## Open product questions — the operator's, not mine

1. **Who picks the quote.** Auto-select by D-018 with a "details" escape, or
   always let the user tap? Auto is kinder to a newcomer; manual feels more
   like an exchange. Recommendation: auto-select, always overridable.
2. **Intent lifetime and cancellation.** How long an intent lives, and whether
   cancelling before acceptance is free. It should be — nothing is locked
   until a quote is accepted.
3. **Partial fills.** Recommendation: **no** in v1. One intent, one atomic
   swap. Partial fills fight atomicity and make the refund story hard to
   explain.
4. **Solver registry.** Open to anyone with a bond, or curated at launch? Open
   is the protocol's spirit; curated reduces launch-day UX risk. A curated
   start with a written path to open satisfies both.
5. **How the user pays the DOM protocol fee.** Under the operator's 80/20 fee
   decision the fee is denominated in DOM, but a user arriving with BTC holds
   no DOM. Either the app guides a small DOM acquisition first, or the first
   operation nets the fee out of the result. This is the one open question
   that touches the fee minute and should be settled with it.

## What this design does not decide

Nothing here is ratified. It reuses ratified objects and marks every product
choice as open. The one place it would touch protocol is question 5, and it
deliberately stops there.

---

## Adjudicated decisions — operator, 2026-08-28

The five open questions above are closed. Each answer below was given or
ratified by the operator, Soren Planck, in the coordination session of
2026-08-28; this section records them so the implementation has a single
normative source.

**1. Who picks the quote — auto-select by D-018, always overridable.**
The recommendation is adopted as written: the list pre-selects by real
outcome and the user may tap another row.

**2. Intent lifetime and cancellation — cancellation is free before
acceptance.** Nothing is locked until a quote is accepted; the intent
expires on its own `quote_deadline`.

**3. Partial fills — no.** One intent, one atomic swap, exactly as
recommended.

**4. Solver registry — curated at launch, with a written path to open.**
The launch set is operator-curated; the path to permissionless entry (bond
requirements, no allowlist) is a stated commitment, not an afterthought.

**5. The fee — decided in full.**

- The protocol fee is denominated in DOM and computed automatically by the
  wallet from the transaction value.
- While no market price exists, the **DEPC-3 estimated production cost is
  the conversion reference** (frozen basket `DEPC-3-2026H2`; the emission
  term follows the live subsidy). Before a market exists, production cost
  is the only honest price anchor; the reference is revisited by operator
  decision once a market price is established, not by code drift.
- The user chooses the payment asset: **DOM, BTC or USDT**. Paying in BTC
  or USDT deducts the proportional equivalent of the DOM-denominated fee.
- Conversion into the payment asset uses **no external price feed**: USDT
  is treated as the USD leg directly, and the BTC rate is taken from the
  accepted quote's own implied exchange ratio. The exact figures and the
  DEPC basket version are recorded in the swap history entry.

**Accepted deviation — recorded, not overlooked.** Charging the fee in BTC
or USDT at launch relaxes the strict fee-in-DOM posture and its
indistinguishability benefit. The operator weighed this against the
impossibility of requiring users to acquire DOM before DOM has established
financial value, and accepted the deviation for the launch phase as a
final decision. This paragraph exists so that no future audit mistakes the
trade-off for an oversight.

**Ratified — operator, 2026-08-28:** the fee is tiered by the number of
external legs the route settles, in units of per-thousand. At most one
external leg (DOM->DOM, DOM<->BTC or DOM<->EVM): 0.5% — a 1,000 DOM
operation pays 5 DOM. Two external legs (BTC<->EVM crossing the DOM):
1% — a 1,000 DOM operation pays 10 DOM. Every route through the DOM
is valid, including same-asset round trips (BTC->DOM->BTC,
EVM->DOM->EVM), which settle two external legs and pay the 1% tier.

**Asset identity is the (ticker, network) pair — operator, 2026-08-28:**
USDT on Ethereum and USDT on Base are distinct external assets, so
USDT(Ethereum)->DOM->USDT(Base) is a two-external-leg route at the 1%
tier like any other external-to-external route. The tier rule needs
only the DOM-or-external distinction and is already network-correct;
the per-network asset identities live in the curated asset registry
that arrives with the interop daemon integration (decision D-018). The implementation carries the
tiers as two named constants (`SWAP_FEE_BPS_SINGLE_LEG` = 50,
`SWAP_FEE_BPS_DUAL_LEG` = 100), pinned by test; changing either is a
deliberate, operator-authorized act.
