//! The transport port.
//!
//! dom-protocol ships no wallet-facing relay endpoint: `relay` is a
//! codec-plus-mailbox library, and the only shipped network face
//! replicates relay databases between two daemon peers over pinned-key
//! Noise XX. The client therefore speaks through this narrow port. In
//! production the port stays [`DisconnectedTransportV1`] until the
//! operator supplies a reachable endpoint; the laboratory
//! [`LabInProcessRelayV1`] wraps the real `relay::server::RelayV1`
//! mailbox so the whole protocol is proven byte-exact in tests.

use relay::server::{RelayRefusal, RelayV1};
use relay::ParticipantId;

/// Fail-closed transport refusals, by name.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TransportRefusal {
    /// No transport endpoint is configured or reachable. Nothing was
    /// sent; nothing was received.
    #[error("no transport endpoint is connected")]
    NotConnected,
    /// The relay refused the envelope (equivocation, storage bounds or
    /// a malformed frame). The submitted bytes must not be re-signed —
    /// resubmit the exact persisted bytes or abandon the flow.
    #[error("the relay refused the envelope")]
    Refused,
}

/// The port a swap client sends and receives through.
pub trait RelayTransportV1 {
    /// Submits one canonical envelope, exactly as signed. At-least-once:
    /// resubmitting the same bytes is safe by the relay's idempotent
    /// ACK; submitting DIFFERENT bytes under the same flow key is
    /// provable equivocation, so callers only ever pass persisted bytes.
    fn submit_envelope(&mut self, raw: &[u8]) -> Result<(), TransportRefusal>;

    /// Delivers the stored envelopes addressed to `recipient`.
    /// At-least-once and unordered, exactly like the relay's own
    /// delivery contract; the §5.4 pipeline downstream is what makes
    /// replays harmless.
    fn deliver_envelopes(
        &mut self,
        recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, TransportRefusal>;
}

/// The production default: no endpoint, nothing moves, no pretending.
#[derive(Clone, Copy, Default, Debug)]
pub struct DisconnectedTransportV1;

impl RelayTransportV1 for DisconnectedTransportV1 {
    fn submit_envelope(&mut self, _raw: &[u8]) -> Result<(), TransportRefusal> {
        Err(TransportRefusal::NotConnected)
    }

    fn deliver_envelopes(
        &mut self,
        _recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, TransportRefusal> {
        Err(TransportRefusal::NotConnected)
    }
}

/// Laboratory transport: the real ratified relay mailbox, in process.
/// Every byte crosses the same codec, idempotency and equivocation
/// checks production will apply.
#[derive(Default)]
pub struct LabInProcessRelayV1 {
    relay: RelayV1,
}

impl LabInProcessRelayV1 {
    /// A fresh in-memory relay.
    pub fn new() -> Self {
        Self {
            relay: RelayV1::new(),
        }
    }

    /// Direct access for the counterparty side of a test.
    pub fn relay_mut(&mut self) -> &mut RelayV1 {
        &mut self.relay
    }
}

impl RelayTransportV1 for LabInProcessRelayV1 {
    fn submit_envelope(&mut self, raw: &[u8]) -> Result<(), TransportRefusal> {
        self.relay.submit(raw).map(|_| ()).map_err(|refusal| {
            let _named: RelayRefusal = refusal;
            TransportRefusal::Refused
        })
    }

    fn deliver_envelopes(
        &mut self,
        recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, TransportRefusal> {
        Ok(self.relay.deliver(recipient))
    }
}
