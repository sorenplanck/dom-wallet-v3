//! User-side (Initiator) client of the DOM interop F6 RFQ flow.
//!
//! dom-protocol defines the wallet-shaped seam of its swap engine as
//! the public `rfq` object set (`RfqV1`, `QuoteV1`, `TermsBindingV1`,
//! `AcceptanceV1`, `SelectionV1`) carried inside ratified `relay`
//! envelopes, authenticated per-envelope with BIP340 against a roster.
//! This crate is that client, byte-exact: the same codecs, the same
//! §5.4 acceptance pipeline, the same §4.1/§4.3 adjudication, the same
//! pinned BIP340 backend — consumed from the pinned protocol revision,
//! never re-implemented.
//!
//! Fail-closed by construction: the client only exists once the
//! operator's network descriptor validates, it only signs under the
//! roster identity derived from the wallet's own seed, and the
//! production transport is [`transport::DisconnectedTransportV1`] until
//! a reachable endpoint is configured — nothing is sent, nothing is
//! fabricated.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod client;
pub mod descriptor;
pub mod identity;
pub mod transport;

pub use client::{
    AcceptedTermsV1, AttestedFactsV1, HeldQuoteV1, PreparedEnvelopeV1, PreparedRfqV1,
    SwapIntentRequestV1, SwapRfqClientV1,
};
pub use descriptor::{AssetEntryV1, SwapNetworkDescriptorV1};
pub use identity::{initiator_keypair, initiator_public_identity};
pub use transport::{DisconnectedTransportV1, LabInProcessRelayV1, RelayTransportV1};

use rfq::RfqObjectError;

use crate::transport::TransportRefusal;

/// Fail-closed refusals of the swap client, by name.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SwapClientError {
    /// The descriptor is absent, malformed, or inconsistent.
    #[error("the network descriptor does not validate")]
    DescriptorInvalid,
    /// The Initiator key could not be derived from the seed.
    #[error("initiator identity derivation failed")]
    IdentityDerivation,
    /// The roster does not grant this wallet's seed-derived key the
    /// Initiator identity the descriptor names.
    #[error("the roster entry does not carry this wallet's key")]
    UserKeyNotInRoster,
    /// The requested asset code is not in the curated registry.
    #[error("asset is not in the curated registry")]
    UnknownAsset,
    /// An F6 object refused to build or encode.
    #[error("rfq object refusal: {0}")]
    Rfq(RfqObjectError),
    /// The envelope refused to encode.
    #[error("envelope encoding refused")]
    EnvelopeEncoding,
    /// The payload exceeds the relay's frozen bound.
    #[error("payload exceeds the relay bound")]
    PayloadTooLarge,
    /// BIP340 signing failed.
    #[error("signing failed")]
    Signing,
    /// The transport refused.
    #[error("transport: {0}")]
    Transport(TransportRefusal),
    /// The flow's sequence space is exhausted.
    #[error("sequence exhausted")]
    SequenceExhausted,
    /// This client already authored its RFQ; a new negotiation is a
    /// new session.
    #[error("an rfq was already prepared under this session")]
    RfqAlreadyPrepared,
    /// No RFQ has been prepared yet.
    #[error("no rfq prepared")]
    NoRfqPrepared,
    /// The named quote is not held by this client.
    #[error("quote not held")]
    QuoteNotHeld,
    /// The chosen quote fails ratified admissibility.
    #[error("quote inadmissible")]
    QuoteInadmissible,
    /// No winner exists under the ratified selection.
    #[error("selection failed")]
    SelectionFailed,
    /// The chosen quote is not the ratified winner; the wallet records
    /// adjudications, it does not overrule them.
    #[error("choice is not the ratified winner")]
    ChoiceIsNotTheRatifiedWinner,
}
