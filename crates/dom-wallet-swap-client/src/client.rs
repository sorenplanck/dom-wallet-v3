//! The Initiator-side RFQ client.
//!
//! Mirrors the ratified end-to-end flow the reference solver proves
//! (dom-protocol `crates/solver/tests/rfq_end_to_end.rs`): author
//! `RfqV1`, sign relay envelopes as `Initiator`, run every incoming
//! frame through the §5.4 `accept_envelope` pipeline plus the consumer
//! correspondence checks, verify quote signatures against the roster
//! with the pinned BIP340 backend, adjudicate §4.1 admissibility and
//! §4.3 selection, and freeze `TermsBindingV1` on acceptance.
//!
//! Discipline inherited from the protocol (D-020): an envelope is
//! prepared once per flow sequence and the exact bytes are what may be
//! retransmitted — preparing twice at one sequence is refused here,
//! because signing different bytes under the same key is provable
//! equivocation and fails the session closed.

use std::collections::BTreeMap;

use btc_crypto::SecpContext;
use relay::auth::{accept_envelope, message_type, RecipientContextV1, TranscriptStateV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec, MAX_PAYLOAD_BYTES};
use rfq::selection::{admissibility, select_winner, CandidateFactsV1};
use rfq::{
    AcceptanceV1, FeeLimitV1, LegDirectionV1, QuoteV1, RfqModeV1, RfqV1, RouteLegV1, RouteV1,
    SelectionV1, TermsBindingV1, TimelockDomainV1,
};
use zeroize::Zeroizing;

use crate::descriptor::{Digest32, SwapNetworkDescriptorV1};
use crate::identity::initiator_keypair;
use crate::transport::RelayTransportV1;
use crate::SwapClientError;

/// What the wallet asks the network: one route, exact-in, with the
/// user's protection floor — the same quartet the swap tab's intent
/// form captures.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapIntentRequestV1 {
    /// Wallet code of the asset the user gives.
    pub give_code: String,
    /// Wallet code of the asset the user receives.
    pub receive_code: String,
    /// Exact amount given, smallest unit.
    pub input_amount: u128,
    /// The least the user accepts; below it, no deal.
    pub minimum_output: u128,
    /// Ratified F2 fee bound, DOM side.
    pub fee_limit_dom_max: u128,
    /// Ratified F2 fee bound, counterparty side.
    pub fee_limit_counterparty_max: u128,
    /// UNIX deadline for quotes (the RFQ's single timelock domain is
    /// `TimestampSeconds`).
    pub quote_deadline_unix: u64,
}

/// One prepared envelope: the exact signed bytes and where they go.
/// The caller persists these BEFORE submitting (persist-before-act);
/// retransmission is always these bytes, never a re-signature.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedEnvelopeV1 {
    /// The addressed solver.
    pub recipient: ParticipantId,
    /// Canonical signed envelope bytes.
    pub bytes: Vec<u8>,
    /// The signed envelope digest (transcript currency).
    pub digest: Digest32,
}

/// The published intent: the RFQ and one prepared envelope per solver.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PreparedRfqV1 {
    /// The authored request for quotes.
    pub rfq: RfqV1,
    /// One envelope per descriptor solver, in descriptor order.
    pub envelopes: Vec<PreparedEnvelopeV1>,
}

/// A quote held by the client with the facts it PROVED locally. The
/// remaining §4.1 facts are F4 assurance attestations the wallet cannot
/// observe; they enter at acceptance, explicitly, as
/// [`AttestedFactsV1`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HeldQuoteV1 {
    /// The received quote, byte-exact through the pipeline.
    pub quote: QuoteV1,
    /// BIP340 verification of `solver_signature` over `quote_id`
    /// against the solver's roster key — proven here, not claimed.
    pub signature_valid: bool,
    /// The solver exists in the descriptor roster with role Solver.
    pub solver_registered: bool,
}

/// The §4.1 facts the wallet cannot verify itself (bond reservation,
/// exposure coverage, solver standing, policy acceptance). They come
/// from the operator's assurance surface and are supplied explicitly at
/// acceptance — never defaulted to true silently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AttestedFactsV1 {
    /// §4.1.6/8 — the bond reservation is exclusive to this quote.
    pub bond_reserved_exclusive: bool,
    /// §4.1.7 — exposure covered under the F4 policy.
    pub exposure_covered: bool,
    /// Coverage in excess of the requirement (selection tie chain).
    pub coverage_excess: u128,
    /// §4.1.9 — the solver is active, not suspended or slashed.
    pub solver_active: bool,
    /// §4.1.10 — the quoted policy version is accepted.
    pub policy_version_accepted: bool,
}

/// The frozen outcome of acceptance: terms, adjudication and the
/// prepared envelopes that carry them to the winning solver.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AcceptedTermsV1 {
    /// The ratified §4.2 terms binding.
    pub terms: TermsBindingV1,
    /// Its authority hash — the settlement identity from here on.
    pub terms_hash: Digest32,
    /// The recorded §4.3 selection with its candidate-set digest.
    pub selection: SelectionV1,
    /// The recorded acceptance.
    pub acceptance: AcceptanceV1,
    /// ACCEPTANCE then SELECTION envelopes to the winning solver.
    pub envelopes: Vec<PreparedEnvelopeV1>,
}

#[derive(Clone, Copy)]
struct FlowStateV1 {
    next_sequence: u64,
    previous_digest: Digest32,
}

/// The Initiator-side client of one negotiation session.
pub struct SwapRfqClientV1 {
    descriptor: SwapNetworkDescriptorV1,
    secret: Zeroizing<[u8; 32]>,
    secp: SecpContext,
    session_id: Digest32,
    route_id: Digest32,
    flows: BTreeMap<[u8; 32], FlowStateV1>,
    inbound: TranscriptStateV1,
    rfq: Option<RfqV1>,
    quotes: Vec<HeldQuoteV1>,
}

impl SwapRfqClientV1 {
    /// Builds the client for one session from the operator descriptor
    /// and the wallet seed. Fails closed if the descriptor's roster
    /// entry for this wallet does not carry the seed-derived key: a
    /// wallet must never sign under an identity the roster does not
    /// grant it.
    pub fn new(
        descriptor: SwapNetworkDescriptorV1,
        seed: &[u8; 64],
        secp_seed: &[u8; 32],
        session_id: Digest32,
        route_id: Digest32,
    ) -> Result<Self, SwapClientError> {
        let secp = SecpContext::new(secp_seed);
        let (secret, xonly) = initiator_keypair(seed, &secp)?;
        if descriptor.member_xonly(&descriptor.user) != Some(xonly) {
            return Err(SwapClientError::UserKeyNotInRoster);
        }
        Ok(Self {
            descriptor,
            secret,
            secp,
            session_id,
            route_id,
            flows: BTreeMap::new(),
            inbound: TranscriptStateV1::new(),
            rfq: None,
            quotes: Vec::new(),
        })
    }

    /// The session this client negotiates under.
    pub fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// The authored RFQ, once prepared.
    pub fn rfq(&self) -> Option<&RfqV1> {
        self.rfq.as_ref()
    }

    /// Quotes accepted through the pipeline so far.
    pub fn quotes(&self) -> &[HeldQuoteV1] {
        &self.quotes
    }

    fn build_envelope(
        &mut self,
        kind: u16,
        recipient: ParticipantId,
        payload: Vec<u8>,
        expiry_unix: u64,
        aux_rand: &[u8; 32],
    ) -> Result<PreparedEnvelopeV1, SwapClientError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(SwapClientError::PayloadTooLarge);
        }
        let flow = self.flows.entry(recipient.0).or_insert(FlowStateV1 {
            next_sequence: 0,
            previous_digest: [0u8; 32],
        });
        let mut envelope = RelayEnvelopeV1 {
            network_id: self.descriptor.network_id,
            message_type: kind,
            session_id: self.session_id,
            route_id: self.route_id,
            sender_id: self.descriptor.user,
            recipient_id: recipient,
            sender_role: SenderRoleV1::Initiator,
            sequence: flow.next_sequence,
            previous_transcript_hash: flow.previous_digest,
            payload,
            expiry: TimelockSpec::TimestampSeconds { value: expiry_unix },
            policy_version: self.descriptor.policy_version,
            roster_snapshot: self.descriptor.roster_snapshot,
            signature: [0u8; 64],
        };
        let digest = envelope
            .envelope_digest()
            .map_err(|_| SwapClientError::EnvelopeEncoding)?;
        let (signature, _) = self
            .secp
            .sign_bip340(&self.secret, &digest, aux_rand)
            .map_err(|_| SwapClientError::Signing)?;
        envelope.signature = signature;
        let bytes = envelope
            .canonical_bytes()
            .map_err(|_| SwapClientError::EnvelopeEncoding)?;
        // The sequence is consumed by the act of signing: the next
        // envelope in this flow chains on this digest, and this
        // sequence can never carry different bytes again.
        flow.next_sequence = flow
            .next_sequence
            .checked_add(1)
            .ok_or(SwapClientError::SequenceExhausted)?;
        flow.previous_digest = digest;
        Ok(PreparedEnvelopeV1 {
            recipient,
            bytes,
            digest,
        })
    }

    /// Authors the RFQ and prepares one signed envelope per descriptor
    /// solver. Pure protocol work — nothing is transmitted; the caller
    /// persists the returned bytes durably, then submits them. One RFQ
    /// per client: a second negotiation is a new session, never a
    /// re-signature under this one.
    pub fn prepare_rfq(
        &mut self,
        request: &SwapIntentRequestV1,
        envelope_expiry_unix: u64,
        aux_rand: &[u8; 32],
    ) -> Result<PreparedRfqV1, SwapClientError> {
        if self.rfq.is_some() {
            return Err(SwapClientError::RfqAlreadyPrepared);
        }
        let give = self
            .descriptor
            .asset(&request.give_code)
            .ok_or(SwapClientError::UnknownAsset)?;
        let receive = self
            .descriptor
            .asset(&request.receive_code)
            .ok_or(SwapClientError::UnknownAsset)?;
        let route = RouteV1 {
            legs: [
                RouteLegV1 {
                    chain_id: give.chain_id,
                    asset: give.asset_id,
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: receive.chain_id,
                    asset: receive.asset_id,
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        };
        let rfq = RfqV1::create(
            self.descriptor.user,
            route,
            RfqModeV1::ExactIn {
                input_amount: request.input_amount,
                minimum_output: request.minimum_output,
            },
            FeeLimitV1 {
                dom_max: request.fee_limit_dom_max,
                counterparty_max: request.fee_limit_counterparty_max,
            },
            TimelockDomainV1::TimestampSeconds,
            TimelockSpec::TimestampSeconds {
                value: request.quote_deadline_unix,
            },
            self.descriptor.assurance_policy_ref,
            self.descriptor.policy_version,
            self.session_id,
        )
        .map_err(SwapClientError::Rfq)?;
        let payload = rfq.canonical_bytes().map_err(SwapClientError::Rfq)?;

        let solvers = self.descriptor.solvers.clone();
        let mut envelopes = Vec::with_capacity(solvers.len());
        for solver in solvers {
            envelopes.push(self.build_envelope(
                message_type::RFQ,
                solver,
                payload.clone(),
                envelope_expiry_unix,
                aux_rand,
            )?);
        }
        self.rfq = Some(rfq);
        Ok(PreparedRfqV1 { rfq, envelopes })
    }

    /// Submits prepared bytes exactly as signed. Safe to call again
    /// with the same envelope after a failure: the relay's ACK is
    /// idempotent on identical bytes.
    pub fn submit_prepared<T: RelayTransportV1>(
        &self,
        transport: &mut T,
        prepared: &PreparedEnvelopeV1,
    ) -> Result<(), SwapClientError> {
        transport
            .submit_envelope(&prepared.bytes)
            .map_err(SwapClientError::Transport)
    }

    /// Pulls this wallet's mailbox and runs every frame through the
    /// ratified acceptance pipeline plus the consumer correspondence
    /// checks (the same four `f6-engine` applies: kind, sender, session
    /// and RFQ binding). Verified quotes are held; anything refused is
    /// dropped, and the count of refusals is returned for telemetry —
    /// a refusal is diagnostic, never fatal to the session.
    pub fn ingest_quotes<T: RelayTransportV1>(
        &mut self,
        transport: &mut T,
        now_unix: u64,
    ) -> Result<usize, SwapClientError> {
        let rfq = self.rfq.ok_or(SwapClientError::NoRfqPrepared)?;
        let raws = transport
            .deliver_envelopes(&self.descriptor.user)
            .map_err(SwapClientError::Transport)?;
        let context = RecipientContextV1 {
            recipient_id: self.descriptor.user,
            network_id: self.descriptor.network_id,
            session_id: self.session_id,
            route_id: self.route_id,
        };
        let rosters = self.descriptor.rosters();
        let now = TimelockSpec::TimestampSeconds { value: now_unix };
        let mut refused = 0usize;
        for raw in raws {
            let Ok(accepted) = accept_envelope(&raw, &context, &rosters, &mut self.inbound, now)
            else {
                refused += 1;
                continue;
            };
            let envelope = &accepted.envelope;
            // Consumer correspondences, mirroring f6-engine's contract.
            if envelope.message_type != message_type::QUOTE {
                refused += 1;
                continue;
            }
            let Ok(quote) = QuoteV1::decode(&envelope.payload) else {
                refused += 1;
                continue;
            };
            if quote.solver != envelope.sender_id
                || envelope.session_id != self.session_id
                || quote.rfq_id != rfq.rfq_id
            {
                refused += 1;
                continue;
            }
            if self
                .quotes
                .iter()
                .any(|held| held.quote.quote_id == quote.quote_id)
            {
                continue;
            }
            let solver_key = self.descriptor.member_xonly(&quote.solver);
            let signature_valid = solver_key.is_some_and(|key| {
                self.secp
                    .verify_bip340(&key, &quote.quote_id, &quote.solver_signature)
                    .is_ok()
            });
            self.quotes.push(HeldQuoteV1 {
                quote,
                signature_valid,
                solver_registered: solver_key.is_some(),
            });
        }
        Ok(refused)
    }

    /// Accepts one held quote: ratified §4.1 admissibility over the
    /// FULL candidate set, §4.3 selection (the chosen quote must be the
    /// ratified winner — the wallet records an adjudication, it does
    /// not overrule one), the frozen §4.2 terms, and the prepared
    /// ACCEPTANCE and SELECTION envelopes to the winning solver.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_quote(
        &mut self,
        quote_id: Digest32,
        attested: AttestedFactsV1,
        refund_deadlines: [TimelockSpec; 2],
        payout_commitments: [Digest32; 2],
        envelope_expiry_unix: u64,
        aux_rand: &[u8; 32],
        now_unix: u64,
    ) -> Result<AcceptedTermsV1, SwapClientError> {
        let rfq = self.rfq.ok_or(SwapClientError::NoRfqPrepared)?;
        let now = TimelockSpec::TimestampSeconds { value: now_unix };
        let facts_of = |held: &HeldQuoteV1| CandidateFactsV1 {
            solver_registered: held.solver_registered,
            signature_valid: held.signature_valid,
            bond_reserved_exclusive: attested.bond_reserved_exclusive,
            exposure_covered: attested.exposure_covered,
            coverage_excess: attested.coverage_excess,
            solver_active: attested.solver_active,
            policy_version_accepted: attested.policy_version_accepted,
        };
        let chosen = self
            .quotes
            .iter()
            .find(|held| held.quote.quote_id == quote_id)
            .copied()
            .ok_or(SwapClientError::QuoteNotHeld)?;
        admissibility(
            &rfq,
            &chosen.quote,
            &facts_of(&chosen),
            self.descriptor.dom_chain_id,
            now,
        )
        .map_err(|_| SwapClientError::QuoteInadmissible)?;
        let candidates = self
            .quotes
            .iter()
            .map(|held| (held.quote, facts_of(held)))
            .collect::<Vec<_>>();
        let outcome = select_winner(&rfq, &candidates, self.descriptor.dom_chain_id, now)
            .map_err(|_| SwapClientError::SelectionFailed)?;
        if outcome.selection.winning_quote != quote_id {
            return Err(SwapClientError::ChoiceIsNotTheRatifiedWinner);
        }

        let terms =
            TermsBindingV1::from_parts(&rfq, &chosen.quote, refund_deadlines, payout_commitments)
                .map_err(SwapClientError::Rfq)?;
        let terms_hash = terms.terms_hash().map_err(SwapClientError::Rfq)?;
        let acceptance = AcceptanceV1 {
            terms_hash,
            rfq_id: rfq.rfq_id,
            quote_id,
            accepted_by: self.descriptor.user,
        };
        let selection = outcome.selection;

        let winner = chosen.quote.solver;
        let envelopes = vec![
            self.build_envelope(
                message_type::ACCEPTANCE,
                winner,
                acceptance.canonical_bytes(),
                envelope_expiry_unix,
                aux_rand,
            )?,
            self.build_envelope(
                message_type::SELECTION,
                winner,
                selection.canonical_bytes(),
                envelope_expiry_unix,
                aux_rand,
            )?,
        ];
        Ok(AcceptedTermsV1 {
            terms,
            terms_hash,
            selection,
            acceptance,
            envelopes,
        })
    }
}
