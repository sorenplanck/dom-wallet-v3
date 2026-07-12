#![forbid(unsafe_code)]

//! Thin, protocol-pinned boundary for DOM interactive slate operations.
//!
//! This crate intentionally owns no wallet state and exports no wallet secret
//! DTO.  It converts public canonical slate bytes to and from the authoritative
//! DOM serialization and returns private material only to the encrypted core.

use dom_consensus::{validate_balance_equation, validate_transaction_structure};
use dom_crypto::bp2_verify;
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use dom_slate::{build_send, finalize, respond_receive, SlateInput};
use dom_tx::slate::Slate;
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

pub const TRANSPORT_PREFIX: &str = "dom-slate-v1:";
pub const MAX_TRANSPORT_BYTES: usize = 1_048_576;
pub const MIN_RELAY_FEE_RATE: u64 = dom_core::MIN_RELAY_FEE_RATE;
pub const MAX_INPUTS: usize = dom_core::MAX_INPUTS_PER_TX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputMaterial {
    pub commitment: [u8; 33],
    pub blinding: [u8; 32],
    pub value: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeMaterial {
    pub commitment: [u8; 33],
    pub value: u64,
    pub blinding: [u8; 32],
}

/// Private material returned only to encrypted wallet persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct SenderSecrets {
    pub excess_blinding: [u8; 32],
    pub nonce: [u8; 32],
}

impl std::fmt::Debug for SenderSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SenderSecrets(REDACTED)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecipientSecrets {
    pub output_blinding: [u8; 32],
}

impl std::fmt::Debug for RecipientSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecipientSecrets(REDACTED)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderBuild {
    pub slate_bytes: Vec<u8>,
    pub secrets: SenderSecrets,
    pub change: Option<ChangeMaterial>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientResponse {
    pub slate_bytes: Vec<u8>,
    pub recipient_commitment: [u8; 33],
    pub secrets: RecipientSecrets,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedTransaction {
    pub bytes: Vec<u8>,
    pub transaction_hash: [u8; 32],
    pub kernel_excess: [u8; 33],
    pub weight: u32,
    pub fee: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlatePublicDetails {
    pub chain_id: [u8; 32],
    pub amount: u64,
    pub fee: u64,
    pub input_count: usize,
    pub has_sender_change: bool,
    pub has_recipient_response: bool,
}

#[derive(Debug, Error)]
pub enum ProtocolAdapterError {
    #[error("invalid canonical DOM slate or transaction")]
    InvalidCanonicalEncoding,
    #[error("invalid transaction amount or fee")]
    InvalidAmountOrFee,
    #[error("transaction fee is below the authoritative relay floor")]
    FeeTooLow,
    #[error("transaction input material is invalid")]
    InvalidInput,
    #[error("DOM protocol rejected slate construction")]
    ProtocolRejected,
    #[error("manual slate envelope is malformed")]
    InvalidTransport,
    #[error("manual slate envelope does not match the expected slate")]
    SlateBindingMismatch,
}

/// Conservative protocol-derived expected weight: selected inputs, optional
/// sender change and recipient output, and one plain kernel.
pub fn expected_weight(
    input_count: usize,
    change_output: bool,
) -> Result<u32, ProtocolAdapterError> {
    let outputs = 1usize
        .checked_add(usize::from(change_output))
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?;
    let inputs = u32::try_from(input_count).map_err(|_| ProtocolAdapterError::InvalidInput)?;
    let outputs = u32::try_from(outputs).map_err(|_| ProtocolAdapterError::InvalidInput)?;
    Ok(inputs
        .saturating_mul(dom_core::WEIGHT_INPUT)
        .saturating_add(outputs.saturating_mul(dom_core::WEIGHT_OUTPUT))
        .saturating_add(dom_core::WEIGHT_KERNEL))
}

pub fn minimum_fee(input_count: usize, change_output: bool) -> Result<u64, ProtocolAdapterError> {
    u64::from(expected_weight(input_count, change_output)?)
        .checked_mul(MIN_RELAY_FEE_RATE)
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)
}

pub fn build_sender(
    inputs: &[InputMaterial],
    amount: u64,
    fee: u64,
    chain_id: [u8; 32],
) -> Result<SenderBuild, ProtocolAdapterError> {
    if inputs.is_empty()
        || inputs.len() > MAX_INPUTS
        || amount == 0
        || fee < minimum_fee(inputs.len(), true)?
    {
        return Err(ProtocolAdapterError::InvalidAmountOrFee);
    }
    let mut unique = BTreeSet::new();
    let total = inputs.iter().try_fold(0u64, |sum, input| {
        if !unique.insert(input.commitment) {
            return Err(ProtocolAdapterError::InvalidInput);
        }
        sum.checked_add(input.value)
            .ok_or(ProtocolAdapterError::InvalidAmountOrFee)
    })?;
    let required = amount
        .checked_add(fee)
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?;
    let change_value = total
        .checked_sub(required)
        .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?;
    let built = build_send(
        &inputs
            .iter()
            .map(|input| SlateInput {
                commitment: input.commitment,
                blinding: input.blinding,
            })
            .collect::<Vec<_>>(),
        change_value,
        amount,
        fee,
        chain_id,
    )
    .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    let slate_bytes = encode_slate(&built.slate)?;
    Ok(SenderBuild {
        slate_bytes,
        secrets: SenderSecrets {
            excess_blinding: built.excess_blinding,
            nonce: built.nonce,
        },
        change: built.change.map(|change| ChangeMaterial {
            commitment: change.commitment,
            value: change.value,
            blinding: change.blinding,
        }),
    })
}

pub fn create_recipient_response(
    slate_bytes: &[u8],
    expected_chain_id: [u8; 32],
) -> Result<RecipientResponse, ProtocolAdapterError> {
    let slate = decode_slate(slate_bytes)?;
    let response = respond_receive(slate, &expected_chain_id)
        .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    let commitment = response
        .slate
        .recipient_output
        .as_ref()
        .ok_or(ProtocolAdapterError::ProtocolRejected)?
        .commitment
        .as_bytes();
    let mut recipient_commitment = [0u8; 33];
    recipient_commitment.copy_from_slice(commitment);
    Ok(RecipientResponse {
        slate_bytes: encode_slate(&response.slate)?,
        recipient_commitment,
        secrets: RecipientSecrets {
            output_blinding: response.recipient_output_blinding,
        },
    })
}

pub fn slate_public_details(
    slate_bytes: &[u8],
) -> Result<SlatePublicDetails, ProtocolAdapterError> {
    let slate = decode_slate(slate_bytes)?;
    Ok(SlatePublicDetails {
        chain_id: slate.chain_id,
        amount: slate.amount,
        fee: slate.fee,
        input_count: slate.sender_inputs.len(),
        has_sender_change: slate.sender_change_output.is_some(),
        has_recipient_response: slate.recipient_output.is_some()
            || slate.recipient_public_excess.is_some()
            || slate.recipient_public_nonce.is_some()
            || slate.recipient_partial_sig.is_some(),
    })
}

pub fn finalize_sender(
    response_bytes: &[u8],
    expected_request_bytes: &[u8],
    secrets: &SenderSecrets,
    chain_id: [u8; 32],
) -> Result<FinalizedTransaction, ProtocolAdapterError> {
    let response = decode_slate(response_bytes)?;
    let expected = decode_slate(expected_request_bytes)?;
    let stripped = dom_slate::sender_phase_slate(&response);
    if encode_slate(&stripped)? != encode_slate(&expected)? {
        return Err(ProtocolAdapterError::SlateBindingMismatch);
    }
    let tx = finalize(
        &response,
        &secrets.excess_blinding,
        &secrets.nonce,
        &chain_id,
    )
    .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    let weight = tx.weight();
    let fee = tx
        .total_fee()
        .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    if fee
        < u64::from(weight)
            .checked_mul(MIN_RELAY_FEE_RATE)
            .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?
    {
        return Err(ProtocolAdapterError::FeeTooLow);
    }
    validate_transaction(&tx)?;
    let bytes = encode_transaction(&tx)?;
    let kernel = tx
        .kernels
        .first()
        .ok_or(ProtocolAdapterError::ProtocolRejected)?
        .excess
        .as_bytes();
    let mut kernel_excess = [0u8; 33];
    kernel_excess.copy_from_slice(kernel);
    let transaction_hash = *dom_crypto::blake2b_256(&bytes).as_bytes();
    Ok(FinalizedTransaction {
        bytes,
        transaction_hash,
        kernel_excess,
        weight,
        fee,
    })
}

pub fn validate_finalized_bytes(
    bytes: &[u8],
) -> Result<FinalizedTransaction, ProtocolAdapterError> {
    let tx = decode_transaction(bytes)?;
    validate_transaction(&tx)?;
    let weight = tx.weight();
    let fee = tx
        .total_fee()
        .map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    if fee
        < u64::from(weight)
            .checked_mul(MIN_RELAY_FEE_RATE)
            .ok_or(ProtocolAdapterError::InvalidAmountOrFee)?
    {
        return Err(ProtocolAdapterError::FeeTooLow);
    }
    let kernel = tx
        .kernels
        .first()
        .ok_or(ProtocolAdapterError::ProtocolRejected)?
        .excess
        .as_bytes();
    let mut kernel_excess = [0u8; 33];
    kernel_excess.copy_from_slice(kernel);
    let transaction_hash = *dom_crypto::blake2b_256(bytes).as_bytes();
    Ok(FinalizedTransaction {
        bytes: bytes.to_vec(),
        transaction_hash,
        kernel_excess,
        weight,
        fee,
    })
}

pub fn export_transport(
    slate_id: Uuid,
    response: bool,
    slate_bytes: &[u8],
) -> Result<String, ProtocolAdapterError> {
    if slate_bytes.len() > MAX_TRANSPORT_BYTES {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let canonical = encode_slate(&decode_slate(slate_bytes)?)?;
    if canonical != slate_bytes {
        return Err(ProtocolAdapterError::InvalidCanonicalEncoding);
    }
    Ok(format!(
        "{TRANSPORT_PREFIX}{}:{}:{}",
        if response { "response" } else { "request" },
        slate_id.hyphenated(),
        hex::encode(slate_bytes)
    ))
}

pub fn import_transport(text: &str) -> Result<(Uuid, bool, Vec<u8>), ProtocolAdapterError> {
    if text.len() > MAX_TRANSPORT_BYTES.saturating_mul(2).saturating_add(128) || !text.is_ascii() {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let mut parts = text.split(':');
    if parts.next() != Some("dom-slate-v1") {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let kind = match parts.next() {
        Some("request") => false,
        Some("response") => true,
        _ => return Err(ProtocolAdapterError::InvalidTransport),
    };
    let slate_id = parts
        .next()
        .ok_or(ProtocolAdapterError::InvalidTransport)?
        .parse()
        .map_err(|_| ProtocolAdapterError::InvalidTransport)?;
    let encoded = parts.next().ok_or(ProtocolAdapterError::InvalidTransport)?;
    if parts.next().is_some()
        || encoded.len() % 2 != 0
        || encoded
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(ProtocolAdapterError::InvalidTransport);
    }
    let bytes = hex::decode(encoded).map_err(|_| ProtocolAdapterError::InvalidTransport)?;
    if bytes.len() > MAX_TRANSPORT_BYTES || encode_slate(&decode_slate(&bytes)?)? != bytes {
        return Err(ProtocolAdapterError::InvalidCanonicalEncoding);
    }
    Ok((slate_id, kind, bytes))
}

fn encode_slate(slate: &Slate) -> Result<Vec<u8>, ProtocolAdapterError> {
    let mut writer = Writer::new();
    slate
        .serialize(&mut writer)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(writer.finish())
}
fn decode_slate(bytes: &[u8]) -> Result<Slate, ProtocolAdapterError> {
    if bytes.len() > MAX_TRANSPORT_BYTES {
        return Err(ProtocolAdapterError::InvalidCanonicalEncoding);
    }
    let mut reader = Reader::new(bytes);
    let slate = Slate::deserialize(&mut reader)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    reader
        .finish()
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(slate)
}
fn encode_transaction(
    tx: &dom_consensus::transaction::Transaction,
) -> Result<Vec<u8>, ProtocolAdapterError> {
    let mut writer = Writer::new();
    tx.serialize(&mut writer)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(writer.finish())
}
fn decode_transaction(
    bytes: &[u8],
) -> Result<dom_consensus::transaction::Transaction, ProtocolAdapterError> {
    let mut reader = Reader::new(bytes);
    let tx = dom_consensus::transaction::Transaction::deserialize(&mut reader)
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    reader
        .finish()
        .map_err(|_| ProtocolAdapterError::InvalidCanonicalEncoding)?;
    Ok(tx)
}
fn validate_transaction(
    tx: &dom_consensus::transaction::Transaction,
) -> Result<(), ProtocolAdapterError> {
    validate_transaction_structure(tx).map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    validate_balance_equation(tx).map_err(|_| ProtocolAdapterError::ProtocolRejected)?;
    for output in &tx.outputs {
        if !bp2_verify(output.commitment.as_bytes(), &output.proof)
            .map_err(|_| ProtocolAdapterError::ProtocolRejected)?
        {
            return Err(ProtocolAdapterError::ProtocolRejected);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::{bp2_prove, BlindingFactor};

    #[test]
    fn authoritative_round_trip_is_canonical() {
        let blind = BlindingFactor::from_bytes([7; 32]).unwrap();
        let (_, commitment) = bp2_prove(500_000, &blind).unwrap();
        let sender = build_sender(
            &[InputMaterial {
                commitment,
                blinding: [7; 32],
                value: 500_000,
            }],
            400_000,
            50_000,
            [9; 32],
        )
        .unwrap();
        let response = create_recipient_response(&sender.slate_bytes, [9; 32]).unwrap();
        let finalized = finalize_sender(
            &response.slate_bytes,
            &sender.slate_bytes,
            &sender.secrets,
            [9; 32],
        )
        .unwrap();
        assert_eq!(
            validate_finalized_bytes(&finalized.bytes)
                .unwrap()
                .kernel_excess,
            finalized.kernel_excess
        );
        let text = export_transport(Uuid::nil(), false, &sender.slate_bytes).unwrap();
        assert_eq!(import_transport(&text).unwrap().2, sender.slate_bytes);
    }

    #[test]
    fn transport_rejects_noncanonical_and_wrong_role_data() {
        assert!(import_transport("dom-slate-v1:request:not-a-uuid:00").is_err());
        assert!(
            import_transport("dom-slate-v1:unknown:00000000-0000-0000-0000-000000000000:00")
                .is_err()
        );
        assert!(
            import_transport("dom-slate-v1:request:00000000-0000-0000-0000-000000000000:AA")
                .is_err()
        );
    }
}
