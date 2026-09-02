//! The wallet client end to end against the ratified machinery: the
//! wallet's `RfqV1` crosses the real relay mailbox and the real §5.4
//! pipeline to the reference solver; the signed `QuoteV1` comes back
//! the same way; the wallet verifies, adjudicates and freezes terms;
//! the ACCEPTANCE and SELECTION envelopes then cross the pipeline
//! again — sequence 1 and 2 of the same flow, which only passes if the
//! client's transcript chaining is byte-correct.

use btc_crypto::SecpContext;
use dom_wallet_swap_client::{
    AttestedFactsV1, LabInProcessRelayV1, SwapClientError, SwapIntentRequestV1,
    SwapNetworkDescriptorV1, SwapRfqClientV1,
};
use relay::auth::{accept_envelope, message_type, RecipientContextV1, TranscriptStateV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use rfq::{AcceptanceV1, QuoteV1, RfqV1, SelectionV1, TermsBindingV1};
use solver::{BondFactsV1, ReferenceSolverV1, SolverPolicyV1};

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE_ID: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const USER: [u8; 32] = [0x31; 32];
const SOLVER: [u8; 32] = [0x61; 32];
const WALLET_SEED: [u8; 64] = [0x42; 64];
const SOLVER_SECRET: [u8; 32] = [0x51; 32];
const SECP_SEED: [u8; 32] = [0x99; 32];

fn secp() -> SecpContext {
    SecpContext::new(&SECP_SEED)
}

fn solver_xonly() -> [u8; 32] {
    secp()
        .sign_bip340(&SOLVER_SECRET, &[0u8; 32], &[0u8; 32])
        .expect("solver key valid")
        .1
}

fn wallet_xonly() -> [u8; 32] {
    dom_wallet_swap_client::initiator_keypair(&WALLET_SEED, &secp())
        .expect("wallet key derives")
        .1
}

fn descriptor_json() -> String {
    format!(
        r#"{{
  "version": 1,
  "network_id": "{network}",
  "dom_chain_id": "{dom_chain}",
  "assurance_policy_ref": "{policy}",
  "policy_version": 1,
  "roster_snapshot": "{snapshot}",
  "user_participant_id": "{user}",
  "members": [
    {{ "participant_id": "{user}", "xonly_key": "{user_key}", "role": "initiator" }},
    {{ "participant_id": "{solver}", "xonly_key": "{solver_key}", "role": "solver" }}
  ],
  "solvers": ["{solver}"],
  "assets": [
    {{ "code": "DOM", "chain_id": "{dom_chain}", "asset_id": "{dom_asset}" }},
    {{ "code": "BTC", "chain_id": "{btc_chain}", "asset_id": "{btc_asset}" }}
  ]
}}"#,
        network = hex::encode(NETWORK),
        dom_chain = hex::encode([0xD0; 32]),
        policy = hex::encode([0xAA; 32]),
        snapshot = hex::encode(SNAPSHOT),
        user = hex::encode(USER),
        user_key = hex::encode(wallet_xonly()),
        solver = hex::encode(SOLVER),
        solver_key = hex::encode(solver_xonly()),
        dom_asset = hex::encode([0x02; 32]),
        btc_chain = hex::encode([0xB1; 32]),
        btc_asset = hex::encode([0x01; 32]),
    )
}

fn descriptor() -> SwapNetworkDescriptorV1 {
    SwapNetworkDescriptorV1::from_json(&descriptor_json()).expect("descriptor validates")
}

fn client() -> SwapRfqClientV1 {
    SwapRfqClientV1::new(descriptor(), &WALLET_SEED, &SECP_SEED, SESSION, ROUTE_ID)
        .expect("client builds")
}

fn intent() -> SwapIntentRequestV1 {
    SwapIntentRequestV1 {
        give_code: "BTC".into(),
        receive_code: "DOM".into(),
        input_amount: 1_000_000,
        minimum_output: 900_000,
        fee_limit_dom_max: 30_000,
        fee_limit_counterparty_max: 0,
        quote_deadline_unix: 5_000,
    }
}

fn reference_solver() -> ReferenceSolverV1 {
    ReferenceSolverV1::new(
        ParticipantId(SOLVER),
        SolverPolicyV1 {
            rate_num: 1,
            rate_den: 1,
            spread_bps: 50,
            execution_delta: 1_000,
            expiry_delta: 500,
        },
        SOLVER_SECRET,
        SECP_SEED,
    )
}

fn solver_quote_envelope(quote: &QuoteV1, sequence: u64, previous: [u8; 32]) -> Vec<u8> {
    let mut envelope = RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: message_type::QUOTE,
        session_id: SESSION,
        route_id: ROUTE_ID,
        sender_id: ParticipantId(SOLVER),
        recipient_id: ParticipantId(USER),
        sender_role: SenderRoleV1::Solver,
        sequence,
        previous_transcript_hash: previous,
        payload: quote.canonical_bytes().expect("quote encodes"),
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    };
    let digest = envelope.envelope_digest().expect("digest");
    let (signature, _) = secp()
        .sign_bip340(&SOLVER_SECRET, &digest, &[0x02; 32])
        .expect("solver signs");
    envelope.signature = signature;
    envelope.canonical_bytes().expect("encodes")
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

/// The whole loop, with the ratified machinery on both sides.
#[test]
fn wallet_rfq_to_frozen_terms_end_to_end_over_the_ratified_relay() {
    let mut lab = LabInProcessRelayV1::new();
    let mut wallet = client();
    let rosters = descriptor().rosters();

    // 1. The wallet authors and publishes the intent (persist, then act).
    let prepared = wallet
        .prepare_rfq(&intent(), 10_000, &[0x01; 32])
        .expect("rfq prepares");
    assert_eq!(prepared.envelopes.len(), 1, "one solver, one envelope");
    for envelope in &prepared.envelopes {
        wallet.submit_prepared(&mut lab, envelope).expect("submits");
        // Retransmission of the exact bytes is idempotent, never fatal.
        wallet
            .submit_prepared(&mut lab, envelope)
            .expect("resubmit of identical bytes is safe");
    }

    // 2. The solver side receives through the REAL §5.4 pipeline.
    let solver_ctx = RecipientContextV1 {
        recipient_id: ParticipantId(SOLVER),
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE_ID,
    };
    let mut solver_transcript = TranscriptStateV1::new();
    let raws = lab.relay_mut().deliver(&ParticipantId(SOLVER));
    assert_eq!(raws.len(), 1, "duplicate submission stored once");
    let accepted = accept_envelope(
        &raws[0],
        &solver_ctx,
        &rosters,
        &mut solver_transcript,
        now(),
    )
    .expect("the wallet's envelope passes the ratified pipeline");
    assert_eq!(accepted.envelope.message_type, message_type::RFQ);
    let received_rfq = RfqV1::decode(&accepted.envelope.payload).expect("rfq decodes");
    assert_eq!(received_rfq, prepared.rfq, "byte-identical intent");

    // 3. The reference solver prices and answers.
    let quote = reference_solver()
        .answer(
            &received_rfq,
            rfq::ChainId([0xD0; 32]),
            BondFactsV1 {
                reservation_id: [0xBD; 32],
                policy_version: 7,
            },
            [0x02; 32],
        )
        .expect("the solver answers");
    assert_eq!(quote.net_output, 995_000, "1:1 rate, 0.50% spread");
    lab.relay_mut()
        .submit(&solver_quote_envelope(&quote, 0, [0u8; 32]))
        .expect("quote submits");

    // 4. The wallet ingests through the pipeline and verifies the
    //    quote signature against the roster — a fact, not a claim.
    let refused = wallet.ingest_quotes(&mut lab, 1_000).expect("ingests");
    assert_eq!(refused, 0);
    assert_eq!(wallet.quotes().len(), 1);
    let held = wallet.quotes()[0];
    assert!(held.signature_valid, "BIP340 verified against the roster");
    assert!(held.solver_registered);

    // 5. Acceptance: ratified admissibility, selection, frozen terms.
    let outcome = wallet
        .accept_quote(
            held.quote.quote_id,
            AttestedFactsV1 {
                bond_reserved_exclusive: true,
                exposure_covered: true,
                coverage_excess: 0,
                solver_active: true,
                policy_version_accepted: true,
            },
            [
                TimelockSpec::TimestampSeconds { value: 8_000 },
                TimelockSpec::TimestampSeconds { value: 9_000 },
            ],
            [[0xC1; 32], [0xC2; 32]],
            10_000,
            &[0x03; 32],
            1_000,
        )
        .expect("acceptance freezes");
    // The terms are exactly what the counterparty recomputes.
    let recomputed = TermsBindingV1::from_parts(
        &received_rfq,
        &quote,
        [
            TimelockSpec::TimestampSeconds { value: 8_000 },
            TimelockSpec::TimestampSeconds { value: 9_000 },
        ],
        [[0xC1; 32], [0xC2; 32]],
    )
    .expect("terms rebind");
    assert_eq!(
        outcome.terms_hash,
        recomputed.terms_hash().expect("hash"),
        "one terms hash on both sides"
    );
    assert_eq!(outcome.selection.winning_quote, quote.quote_id);

    // 6. ACCEPTANCE and SELECTION cross the pipeline as sequences 1 and
    //    2 of the same flow — transcript continuity is the proof that
    //    the client's chaining is byte-correct.
    for envelope in &outcome.envelopes {
        wallet.submit_prepared(&mut lab, envelope).expect("submits");
    }
    // Delivery is at-least-once: the mailbox replays the already-seen
    // RFQ envelope too. The pipeline's replay protection refuses it;
    // exactly the two new sequences accept, in chain order.
    let raws = lab.relay_mut().deliver(&ParticipantId(SOLVER));
    assert_eq!(raws.len(), 3);
    let mut newly_accepted = Vec::new();
    for raw in &raws {
        if let Ok(accepted) =
            accept_envelope(raw, &solver_ctx, &rosters, &mut solver_transcript, now())
        {
            newly_accepted.push(accepted);
        }
    }
    assert_eq!(newly_accepted.len(), 2, "the replayed rfq is refused");
    let acceptance = newly_accepted
        .iter()
        .find(|accepted| accepted.envelope.message_type == message_type::ACCEPTANCE)
        .expect("an acceptance arrived");
    let acceptance = AcceptanceV1::decode(&acceptance.envelope.payload).expect("decodes");
    assert_eq!(acceptance.terms_hash, outcome.terms_hash);
    assert_eq!(acceptance.accepted_by, ParticipantId(USER));
    let selection = newly_accepted
        .iter()
        .find(|accepted| accepted.envelope.message_type == message_type::SELECTION)
        .expect("a selection arrived");
    let selection = SelectionV1::decode(&selection.envelope.payload).expect("decodes");
    assert_eq!(selection.winning_quote, quote.quote_id);
}

/// One RFQ per session: a second authoring under the same client is a
/// refused equivocation risk, not a convenience.
#[test]
fn a_second_rfq_under_the_same_session_is_refused() {
    let mut wallet = client();
    wallet
        .prepare_rfq(&intent(), 10_000, &[0x01; 32])
        .expect("first prepares");
    assert_eq!(
        wallet.prepare_rfq(&intent(), 10_000, &[0x01; 32]),
        Err(SwapClientError::RfqAlreadyPrepared)
    );
}

/// A forged quote signature is held as unverified and dies at the
/// ratified admissibility inside acceptance.
#[test]
fn a_forged_quote_signature_cannot_be_accepted() {
    let mut lab = LabInProcessRelayV1::new();
    let mut wallet = client();
    let prepared = wallet
        .prepare_rfq(&intent(), 10_000, &[0x01; 32])
        .expect("prepares");
    for envelope in &prepared.envelopes {
        wallet.submit_prepared(&mut lab, envelope).expect("submits");
    }
    let mut quote = reference_solver()
        .answer(
            &prepared.rfq,
            rfq::ChainId([0xD0; 32]),
            BondFactsV1 {
                reservation_id: [0xBD; 32],
                policy_version: 7,
            },
            [0x02; 32],
        )
        .expect("answers");
    quote.solver_signature[10] ^= 0x01;
    lab.relay_mut()
        .submit(&solver_quote_envelope(&quote, 0, [0u8; 32]))
        .expect("submits");
    wallet.ingest_quotes(&mut lab, 1_000).expect("ingests");
    assert_eq!(wallet.quotes().len(), 1);
    assert!(!wallet.quotes()[0].signature_valid);
    assert_eq!(
        wallet.accept_quote(
            quote.quote_id,
            AttestedFactsV1 {
                bond_reserved_exclusive: true,
                exposure_covered: true,
                coverage_excess: 0,
                solver_active: true,
                policy_version_accepted: true,
            },
            [
                TimelockSpec::TimestampSeconds { value: 8_000 },
                TimelockSpec::TimestampSeconds { value: 9_000 },
            ],
            [[0xC1; 32], [0xC2; 32]],
            10_000,
            &[0x03; 32],
            1_000,
        ),
        Err(SwapClientError::QuoteInadmissible)
    );
}

/// A frame from outside the negotiation is refused by the pipeline and
/// never becomes a held quote.
#[test]
fn an_unsolicited_or_foreign_frame_is_dropped_not_held() {
    let mut lab = LabInProcessRelayV1::new();
    let mut wallet = client();
    let prepared = wallet
        .prepare_rfq(&intent(), 10_000, &[0x01; 32])
        .expect("prepares");
    for envelope in &prepared.envelopes {
        wallet.submit_prepared(&mut lab, envelope).expect("submits");
    }
    let quote = reference_solver()
        .answer(
            &prepared.rfq,
            rfq::ChainId([0xD0; 32]),
            BondFactsV1 {
                reservation_id: [0xBD; 32],
                policy_version: 7,
            },
            [0x02; 32],
        )
        .expect("answers");
    // Tampered envelope bytes die at the relay's own codec: the payload
    // hash no longer binds, and the frame is refused before storage.
    let mut raw = solver_quote_envelope(&quote, 0, [0u8; 32]);
    let index = raw.len() - 70; // inside the payload, before the signature
    raw[index] ^= 0x01;
    assert!(
        lab.relay_mut().submit(&raw).is_err(),
        "the relay refuses a frame whose payload hash does not bind"
    );
    // A correctly signed quote answering a FOREIGN rfq passes the
    // pipeline but dies at the consumer correspondence check.
    let mut foreign_request = intent();
    foreign_request.minimum_output = 900_001;
    let foreign_rfq = rfq::RfqV1::create(
        ParticipantId(USER),
        prepared.rfq.route,
        rfq::RfqModeV1::ExactIn {
            input_amount: foreign_request.input_amount,
            minimum_output: foreign_request.minimum_output,
        },
        prepared.rfq.fee_limit,
        prepared.rfq.timelock_domain,
        prepared.rfq.quote_deadline,
        prepared.rfq.assurance_policy_ref,
        prepared.rfq.policy_version,
        SESSION,
    )
    .expect("foreign rfq builds");
    let foreign_quote = reference_solver()
        .answer(
            &foreign_rfq,
            rfq::ChainId([0xD0; 32]),
            BondFactsV1 {
                reservation_id: [0xBE; 32],
                policy_version: 7,
            },
            [0x04; 32],
        )
        .expect("answers the foreign rfq");
    lab.relay_mut()
        .submit(&solver_quote_envelope(&foreign_quote, 0, [0u8; 32]))
        .expect("the relay stores the well-formed frame");
    let refused = wallet.ingest_quotes(&mut lab, 1_000).expect("ingests");
    assert_eq!(refused, 1, "the consumer check refuses the foreign quote");
    assert!(wallet.quotes().is_empty());
}

/// The client refuses to exist under a roster that does not carry the
/// wallet's seed-derived key.
#[test]
fn a_roster_without_the_wallet_key_refuses_the_client() {
    let json = descriptor_json().replace(&hex::encode(wallet_xonly()), &hex::encode([0x5A; 32]));
    let descriptor = SwapNetworkDescriptorV1::from_json(&json).expect("descriptor still parses");
    assert_eq!(
        SwapRfqClientV1::new(descriptor, &WALLET_SEED, &SECP_SEED, SESSION, ROUTE_ID).err(),
        Some(SwapClientError::UserKeyNotInRoster)
    );
}

/// Descriptor fail-closed refusals, by name.
#[test]
fn descriptors_fail_closed() {
    // A solver listed without the Solver role.
    let bad_role = descriptor_json().replace("\"role\": \"solver\"", "\"role\": \"observer\"");
    assert!(SwapNetworkDescriptorV1::from_json(&bad_role).is_err());
    // A registry without the DOM on the DOM chain.
    let no_dom = descriptor_json().replace("\"code\": \"DOM\"", "\"code\": \"DUM\"");
    assert!(SwapNetworkDescriptorV1::from_json(&no_dom).is_err());
    // An unknown asset code refuses at intent time.
    let mut wallet = client();
    let mut request = intent();
    request.give_code = "XMR".into();
    assert_eq!(
        wallet.prepare_rfq(&request, 10_000, &[0x01; 32]),
        Err(SwapClientError::UnknownAsset)
    );
}
