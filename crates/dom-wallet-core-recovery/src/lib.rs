//! Wallet-owned BIP-39 and frozen Recovery Capsule v1 construction boundary.

#![forbid(unsafe_code)]

use bip39::{Language, Mnemonic};
use dom_consensus::TransactionOutput;
use dom_crypto::{
    pedersen::Commitment,
    range_proof_verify_with_extra_commit,
    recovery::{
        derive_recovery_root, recover_output_from_capsule, OutputRecoveryDomain, PublicOutputKind,
        RecoveredOutput, RecoveryCapsule, RecoveryChainContext, RecoveryRoot,
        RECOVERY_CAPSULE_SIZE, RECOVERY_VERSION,
    },
    MAX_PROVABLE_VALUE, RANGE_PROOF_SERIALIZATION_VERSION, RANGE_PROOF_SIZE,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_slate::{
    build_send_recoverable, finalize, respond_receive_recoverable, sender_phase_slate,
    RecoveryBuildContext, SlateInput,
};
use dom_tx::{build_recoverable_output, slate::Slate};
use dom_wallet_core_api::ScanBlock;
use dom_wallet_core_protocol::{RecoverySlateBody, RecoverySlateSidecars};
use dom_wallet_core_sync::CoreChainIdentity;
use dom_wallet_domain::{
    RecoveryOutputClass, ReservedRecoveryCoordinate, WalletState, RECOVERY_SCHEME_BIP39_256_V1,
};
use dom_wallet_recovery::{restore_from_canonical_scan, RestoreError, RestoredWalletState};
use rand::RngCore;
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Frozen canonical serialized output size: commitment plus length and envelope.
pub const CANONICAL_TRANSACTION_OUTPUT_SIZE: usize = 33 + 4 + 835;
/// Frozen proof envelope size.
pub const RECOVERY_PROOF_ENVELOPE_SIZE: usize = RANGE_PROOF_SIZE + RECOVERY_CAPSULE_SIZE;

/// Canonical English 24-word BIP-39 seed boundary.
pub struct CanonicalWalletSeed {
    mnemonic: Mnemonic,
    seed: Zeroizing<[u8; 64]>,
}

impl fmt::Debug for CanonicalWalletSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalWalletSeed([REDACTED])")
    }
}

impl CanonicalWalletSeed {
    /// Generate exactly 256 bits of operating-system entropy.
    pub fn generate() -> Result<Self, RecoveryMaterialError> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(entropy.as_mut())
            .map_err(|_| RecoveryMaterialError::RandomnessUnavailable)?;
        Self::from_entropy(&entropy)
    }

    /// Reconstruct the canonical boundary from encrypted 256-bit entropy.
    pub fn from_entropy(entropy: &[u8; 32]) -> Result<Self, RecoveryMaterialError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
            .map_err(|_| RecoveryMaterialError::InvalidMnemonic)?;
        Self::from_mnemonic(mnemonic)
    }

    /// Parse an English mnemonic, including BIP-39 Unicode normalization.
    pub fn parse(phrase: &str) -> Result<Self, RecoveryMaterialError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| RecoveryMaterialError::InvalidMnemonic)?;
        if mnemonic.word_count() != 24 || mnemonic.to_entropy().len() != 32 {
            return Err(RecoveryMaterialError::InvalidMnemonic);
        }
        Self::from_mnemonic(mnemonic)
    }

    fn from_mnemonic(mnemonic: Mnemonic) -> Result<Self, RecoveryMaterialError> {
        if mnemonic.word_count() != 24 || mnemonic.to_entropy().len() != 32 {
            return Err(RecoveryMaterialError::InvalidMnemonic);
        }
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        Ok(Self { mnemonic, seed })
    }

    /// Copy entropy into the caller's encrypted-state buffer.
    pub fn copy_entropy_to(&self, destination: &mut [u8; 32]) {
        let entropy = Zeroizing::new(self.mnemonic.to_entropy());
        destination.copy_from_slice(&entropy);
    }

    /// Return a one-time zeroizing phrase for the explicit creation ceremony.
    pub fn mnemonic_text(&self) -> Zeroizing<String> {
        Zeroizing::new(self.mnemonic.to_string())
    }

    fn recovery_root(
        &self,
        chain: RecoveryChainContext,
    ) -> Result<RecoveryRoot, RecoveryMaterialError> {
        derive_recovery_root(self.seed.as_slice(), chain)
            .map_err(|_| RecoveryMaterialError::RecoveryRootDerivation)
    }

    /// Run the frozen canonical ownership-recovery algorithm without exposing seed bytes.
    pub fn restore_canonical_scan(
        &self,
        chain: RecoveryChainContext,
        blocks: &[ScanBlock],
    ) -> Result<RestoredWalletState, RestoreError> {
        restore_from_canonical_scan(self.seed.as_slice(), chain, blocks)
    }
}

/// Public production-path declaration used to prevent proof-only additions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionOutputPath {
    pub class: RecoveryOutputClass,
    pub constructor: &'static str,
    pub recovery_required: bool,
}

/// Every Wallet V3 output class has one frozen recoverable constructor.
pub const PRODUCTION_OUTPUT_PATHS: [ProductionOutputPath; 5] = [
    ProductionOutputPath {
        class: RecoveryOutputClass::ReceiveRequest,
        constructor: "RecoverableOutputBuilder::build",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::ReceiveSlate,
        constructor: "respond_receive_recoverable",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::Change,
        constructor: "build_send_recoverable",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::SelfTransfer,
        constructor: "RecoverableOutputBuilder::build",
        recovery_required: true,
    },
    ProductionOutputPath {
        class: RecoveryOutputClass::Coinbase,
        constructor: "RecoverableOutputBuilder::build",
        recovery_required: true,
    },
];

/// Wallet-owned result with public output data and an opaque spend secret.
pub struct RecoverableOutputResult {
    pub output: TransactionOutput,
    pub canonical_bytes: Vec<u8>,
    pub commitment: [u8; 33],
    pub range_proof: [u8; RANGE_PROOF_SIZE],
    pub recovery_capsule: [u8; RECOVERY_CAPSULE_SIZE],
    pub proof_envelope: [u8; RECOVERY_PROOF_ENVELOPE_SIZE],
    pub account: u32,
    pub derivation_index: u64,
    pub class: RecoveryOutputClass,
    secret: OutputSpendSecret,
}

impl RecoverableOutputResult {
    /// Compare encrypted-state spending evidence without exposing this blinding.
    pub fn matches_spend_blinding(&self, candidate: &[u8; 32]) -> bool {
        self.secret.0.as_bytes() == candidate
    }
}

impl fmt::Debug for RecoverableOutputResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableOutputResult")
            .field("commitment", &"[PUBLIC COMMITMENT]")
            .field("account", &self.account)
            .field("derivation_index", &self.derivation_index)
            .field("class", &self.class)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

struct OutputSpendSecret(dom_crypto::BlindingFactor);

impl fmt::Debug for OutputSpendSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutputSpendSecret([REDACTED])")
    }
}

/// Authenticated recovery result with an opaque spend secret.
pub struct RecoveredWalletOutput {
    pub value: u64,
    pub account: u32,
    pub derivation_index: u64,
    pub class: RecoveryOutputClass,
    secret: OutputSpendSecret,
}

impl fmt::Debug for RecoveredWalletOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveredWalletOutput")
            .field("value", &"[REDACTED]")
            .field("account", &self.account)
            .field("derivation_index", &self.derivation_index)
            .field("class", &self.class)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl RecoveredWalletOutput {
    /// Compare opaque spending evidence without exposing either blinding.
    pub fn matches_original(&self, original: &RecoverableOutputResult) -> bool {
        self.secret.0.as_bytes() == original.secret.0.as_bytes()
    }
}

/// Wallet orchestration around frozen Recovery Capsule and output APIs.
pub struct RecoverableOutputBuilder {
    root: RecoveryRoot,
    chain: RecoveryChainContext,
}

impl fmt::Debug for RecoverableOutputBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableOutputBuilder")
            .field("root", &"[REDACTED]")
            .field("network_magic", &self.chain.network_magic)
            .field("chain_id", &"[PUBLIC CHAIN ID]")
            .finish()
    }
}

impl RecoverableOutputBuilder {
    pub fn new(
        seed: &CanonicalWalletSeed,
        identity: &CoreChainIdentity,
    ) -> Result<Self, RecoveryMaterialError> {
        validate_identity(identity)?;
        let chain = RecoveryChainContext {
            network_magic: identity.network_magic,
            chain_id: identity.chain_id,
        };
        Ok(Self {
            root: seed.recovery_root(chain)?,
            chain,
        })
    }

    /// Build, canonically decode, verify, and self-recover before exposure.
    pub fn build(
        &self,
        value: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableOutputResult, RecoveryMaterialError> {
        if value > MAX_PROVABLE_VALUE {
            return Err(RecoveryMaterialError::ValueOutOfRange);
        }
        let domain = domain_for_class(coordinate.class());
        let material = build_recoverable_output(
            &self.root,
            self.chain,
            value,
            coordinate.account(),
            coordinate.derivation_index(),
            domain,
        )
        .map_err(|_| RecoveryMaterialError::OutputConstruction)?;
        let output = material.output;
        let canonical_bytes = output
            .to_bytes()
            .map_err(|_| RecoveryMaterialError::CanonicalEncoding)?;
        if canonical_bytes.len() != CANONICAL_TRANSACTION_OUTPUT_SIZE {
            return Err(RecoveryMaterialError::CanonicalSize);
        }
        let decoded = TransactionOutput::from_bytes(&canonical_bytes)
            .map_err(|_| RecoveryMaterialError::CanonicalEncoding)?;
        if decoded != output {
            return Err(RecoveryMaterialError::CanonicalEncoding);
        }
        let range_proof: [u8; RANGE_PROOF_SIZE] = output
            .range_proof_bytes()
            .map_err(|_| RecoveryMaterialError::CanonicalSize)?
            .try_into()
            .map_err(|_| RecoveryMaterialError::CanonicalSize)?;
        let capsule = output
            .recovery_capsule()
            .map_err(|_| RecoveryMaterialError::InvalidCapsule)?
            .ok_or(RecoveryMaterialError::RecoveryRequired)?;
        let recovery_capsule = *capsule.as_bytes();
        let proof_envelope: [u8; RECOVERY_PROOF_ENVELOPE_SIZE] = output
            .proof
            .as_slice()
            .try_into()
            .map_err(|_| RecoveryMaterialError::CanonicalSize)?;
        if !range_proof_verify_with_extra_commit(
            output.commitment.as_bytes(),
            &range_proof,
            &recovery_capsule,
        )
        .map_err(|_| RecoveryMaterialError::ProofVerification)?
        {
            return Err(RecoveryMaterialError::ProofVerification);
        }
        let recovered = recover_output_from_capsule(
            &self.root,
            self.chain,
            output.commitment.as_bytes(),
            RANGE_PROOF_SERIALIZATION_VERSION,
            domain.public_kind(),
            &capsule,
        )
        .map_err(|_| RecoveryMaterialError::CapsuleAuthentication)?
        .ok_or(RecoveryMaterialError::CapsuleAuthentication)?;
        validate_recovery(
            &recovered,
            value,
            coordinate.account(),
            coordinate.derivation_index(),
            domain,
            output.commitment.as_bytes(),
        )?;
        if recovered.blinding.as_bytes() != material.blinding.as_bytes() {
            return Err(RecoveryMaterialError::SelfRecoveryMismatch);
        }
        Ok(RecoverableOutputResult {
            commitment: *output.commitment.as_bytes(),
            output,
            canonical_bytes,
            range_proof,
            recovery_capsule,
            proof_envelope,
            account: coordinate.account(),
            derivation_index: coordinate.derivation_index(),
            class: coordinate.class(),
            secret: OutputSpendSecret(material.blinding),
        })
    }

    /// Build a spendable recovery-capable coinbase through the canonical DOM
    /// wallet-miner constructor. Only the public coinbase leaves this boundary.
    pub fn build_coinbase(
        &self,
        height: dom_core::BlockHeight,
        total_fees: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<dom_consensus::CoinbaseTransaction, RecoveryMaterialError> {
        if coordinate.class() != RecoveryOutputClass::Coinbase {
            return Err(RecoveryMaterialError::CoordinateDomainMismatch);
        }
        dom_node::miner::build_seed_recoverable_coinbase(
            height,
            total_fees,
            &self.chain.chain_id,
            &self.root,
            self.chain,
            coordinate.account(),
            coordinate.derivation_index(),
        )
        .map_err(|_| RecoveryMaterialError::OutputConstruction)
    }

    /// Attempt authenticated ownership recovery without exposing secret bytes.
    pub fn try_recover(
        &self,
        output: &TransactionOutput,
        class: RecoveryOutputClass,
    ) -> Result<Option<RecoveredWalletOutput>, RecoveryMaterialError> {
        let domain = domain_for_class(class);
        let capsule = output
            .recovery_capsule()
            .map_err(|_| RecoveryMaterialError::InvalidCapsule)?
            .ok_or(RecoveryMaterialError::RecoveryRequired)?;
        let recovered = recover_output_from_capsule(
            &self.root,
            self.chain,
            output.commitment.as_bytes(),
            RANGE_PROOF_SERIALIZATION_VERSION,
            domain.public_kind(),
            &capsule,
        )
        .map_err(|_| RecoveryMaterialError::CapsuleAuthentication)?;
        match recovered {
            Some(value) if value.domain != domain => {
                Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
            Some(value) => Ok(Some(recovered_wallet_output(value, class))),
            None => Ok(None),
        }
    }

    /// Create sender change through the frozen recovery-capable Slate builder.
    pub fn build_sender_offer(
        &self,
        inputs: &[WalletSlateInput],
        change_value: u64,
        amount: u64,
        fee: u64,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableSlateMaterial, RecoveryMaterialError> {
        if coordinate.class() != RecoveryOutputClass::Change {
            return Err(RecoveryMaterialError::CoordinateDomainMismatch);
        }
        let core_inputs: Vec<SlateInput> = inputs
            .iter()
            .map(|input| SlateInput {
                commitment: input.commitment,
                blinding: input.blinding,
            })
            .collect();
        let sender = build_send_recoverable(
            &core_inputs,
            change_value,
            amount,
            fee,
            self.chain.chain_id,
            RecoveryBuildContext {
                root: &self.root,
                chain: self.chain,
                account: coordinate.account(),
                derivation_index: coordinate.derivation_index(),
            },
        )
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        let private = SlatePrivateMaterial::Sender {
            excess_blinding: Zeroizing::new(sender.excess_blinding),
            nonce: Zeroizing::new(sender.nonce),
            change: sender.change.map(|change| {
                (
                    change.commitment,
                    change.value,
                    Zeroizing::new(change.blinding),
                )
            }),
        };
        RecoverableSlateMaterial::from_slate(sender.slate, private)
    }

    /// Create a recipient output through the frozen recovery-capable responder.
    pub fn build_recipient_response(
        &self,
        offer: &RecoverySlateBody,
        coordinate: ReservedRecoveryCoordinate,
    ) -> Result<RecoverableSlateMaterial, RecoveryMaterialError> {
        if !matches!(
            coordinate.class(),
            RecoveryOutputClass::ReceiveRequest | RecoveryOutputClass::ReceiveSlate
        ) {
            return Err(RecoveryMaterialError::CoordinateDomainMismatch);
        }
        let slate = Slate::from_bytes(offer.canonical_bytes())
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        let response = respond_receive_recoverable(
            slate,
            &self.chain.chain_id,
            RecoveryBuildContext {
                root: &self.root,
                chain: self.chain,
                account: coordinate.account(),
                derivation_index: coordinate.derivation_index(),
            },
        )
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        RecoverableSlateMaterial::from_slate(
            response.slate,
            SlatePrivateMaterial::Recipient {
                output_blinding: Zeroizing::new(response.recipient_output_blinding),
            },
        )
    }
}

/// Wallet input material with redacted blinding diagnostics.
#[derive(Clone)]
pub struct WalletSlateInput {
    pub commitment: [u8; 33],
    blinding: [u8; 32],
}

impl WalletSlateInput {
    pub fn new(commitment: [u8; 33], blinding: [u8; 32]) -> Self {
        Self {
            commitment,
            blinding,
        }
    }
}

impl fmt::Debug for WalletSlateInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSlateInput")
            .field("commitment", &"[PUBLIC COMMITMENT]")
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

/// Canonical Slate v4 body plus exact ordered sidecars.
pub struct RecoverableSlateMaterial {
    pub body: RecoverySlateBody,
    pub sidecars: RecoverySlateSidecars,
    private: SlatePrivateMaterial,
}

impl RecoverableSlateMaterial {
    fn from_slate(
        slate: Slate,
        private: SlatePrivateMaterial,
    ) -> Result<Self, RecoveryMaterialError> {
        let sender_change = optional_capsule(&slate.sender_change_recovery_capsule)?;
        let recipient = optional_capsule(&slate.recipient_recovery_capsule)?;
        let canonical = slate
            .to_bytes()
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        Ok(Self {
            body: RecoverySlateBody::from_canonical_bytes(&canonical)
                .map_err(|_| RecoveryMaterialError::SlateConstruction)?,
            sidecars: RecoverySlateSidecars {
                sender_change,
                recipient,
            },
            private,
        })
    }

    /// Confirm that required private material remains retained without exposing it.
    pub fn retains_private_material(&self) -> bool {
        match &self.private {
            SlatePrivateMaterial::Sender {
                excess_blinding,
                nonce,
                change,
            } => {
                excess_blinding.iter().any(|byte| *byte != 0)
                    && nonce.iter().any(|byte| *byte != 0)
                    && change
                        .as_ref()
                        .is_none_or(|value| value.2.iter().any(|byte| *byte != 0))
            }
            SlatePrivateMaterial::Recipient { output_blinding } => {
                output_blinding.iter().any(|byte| *byte != 0)
            }
        }
    }

    /// Consume sender material into encrypted-state secrets and public change data.
    pub fn into_sender_parts(self) -> Result<RecoverableSenderParts, RecoveryMaterialError> {
        match self.private {
            SlatePrivateMaterial::Sender {
                excess_blinding,
                nonce,
                change,
            } => Ok(RecoverableSenderParts {
                body: self.body,
                sidecars: self.sidecars,
                excess_blinding,
                nonce,
                change: change.map(|(commitment, value, blinding)| RecoverableOwnedOutput {
                    commitment,
                    value,
                    blinding,
                }),
            }),
            SlatePrivateMaterial::Recipient { .. } => {
                Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
        }
    }

    /// Consume recipient material into encrypted-state secrets and public output data.
    pub fn into_recipient_parts(self) -> Result<RecoverableRecipientParts, RecoveryMaterialError> {
        let (commitment, value) = recipient_public(&self.body)?;
        match self.private {
            SlatePrivateMaterial::Recipient { output_blinding } => Ok(RecoverableRecipientParts {
                body: self.body,
                sidecars: self.sidecars,
                output: RecoverableOwnedOutput {
                    commitment,
                    value,
                    blinding: output_blinding,
                },
            }),
            SlatePrivateMaterial::Sender { .. } => {
                Err(RecoveryMaterialError::CoordinateDomainMismatch)
            }
        }
    }
}

/// Public output coordinates plus a secret intended only for encrypted Wallet state.
pub struct RecoverableOwnedOutput {
    pub commitment: [u8; 33],
    pub value: u64,
    blinding: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RecoverableOwnedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverableOwnedOutput")
            .field("commitment", &"[PUBLIC COMMITMENT]")
            .field("value", &"[REDACTED]")
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

impl RecoverableOwnedOutput {
    pub fn copy_blinding_to(&self, destination: &mut [u8; 32]) {
        destination.copy_from_slice(self.blinding.as_ref());
    }
}

pub struct RecoverableSenderParts {
    pub body: RecoverySlateBody,
    pub sidecars: RecoverySlateSidecars,
    pub change: Option<RecoverableOwnedOutput>,
    excess_blinding: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RecoverableSenderParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverableSenderParts([REDACTED])")
    }
}

impl RecoverableSenderParts {
    /// Rehydrate encrypted sender context after restart without changing Slate bytes.
    pub fn from_encrypted_context(
        body: RecoverySlateBody,
        excess_blinding: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<Self, RecoveryMaterialError> {
        let slate = Slate::from_bytes(body.canonical_bytes())
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
        if slate.version != dom_tx::slate::RECOVERY_SLATE_VERSION
            || excess_blinding == [0u8; 32]
            || nonce == [0u8; 32]
        {
            return Err(RecoveryMaterialError::SlateConstruction);
        }
        Ok(Self {
            sidecars: RecoverySlateSidecars {
                sender_change: optional_capsule(&slate.sender_change_recovery_capsule)?,
                recipient: optional_capsule(&slate.recipient_recovery_capsule)?,
            },
            body,
            change: None,
            excess_blinding: Zeroizing::new(excess_blinding),
            nonce: Zeroizing::new(nonce),
        })
    }

    pub fn copy_signing_secrets_to(&self, excess: &mut [u8; 32], nonce: &mut [u8; 32]) {
        excess.copy_from_slice(self.excess_blinding.as_ref());
        nonce.copy_from_slice(self.nonce.as_ref());
    }
}

pub struct RecoverableRecipientParts {
    pub body: RecoverySlateBody,
    pub sidecars: RecoverySlateSidecars,
    pub output: RecoverableOwnedOutput,
}

impl fmt::Debug for RecoverableRecipientParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoverableRecipientParts([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedRecoverableTransaction {
    pub canonical_bytes: Vec<u8>,
    pub transaction_hash: [u8; 32],
    pub kernel_excess: [u8; 33],
    pub fee: u64,
    pub weight: u32,
}

/// Finalize only when the response strips exactly to the persisted recovery offer.
pub fn finalize_recoverable_transaction(
    response: &RecoverySlateBody,
    offer: &RecoverySlateBody,
    sender: &RecoverableSenderParts,
    chain_id: [u8; 32],
) -> Result<FinalizedRecoverableTransaction, RecoveryMaterialError> {
    let response_slate = Slate::from_bytes(response.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let offer_slate = Slate::from_bytes(offer.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let stripped = sender_phase_slate(&response_slate)
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let expected = offer_slate
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    if stripped != expected || sender.body.canonical_bytes() != offer.canonical_bytes() {
        return Err(RecoveryMaterialError::SlateBindingMismatch);
    }
    let transaction = finalize(
        &response_slate,
        &sender.excess_blinding,
        &sender.nonce,
        &chain_id,
    )
    .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let canonical_bytes = transaction
        .to_bytes()
        .map_err(|_| RecoveryMaterialError::CanonicalEncoding)?;
    let transaction_hash = *dom_crypto::blake2b_256(&canonical_bytes).as_bytes();
    let kernel = transaction
        .kernels
        .first()
        .ok_or(RecoveryMaterialError::SlateConstruction)?;
    Ok(FinalizedRecoverableTransaction {
        canonical_bytes,
        transaction_hash,
        kernel_excess: *kernel.excess.as_bytes(),
        fee: transaction
            .total_fee()
            .map_err(|_| RecoveryMaterialError::SlateConstruction)?,
        weight: transaction.weight(),
    })
}

fn recipient_public(body: &RecoverySlateBody) -> Result<([u8; 33], u64), RecoveryMaterialError> {
    let slate = Slate::from_bytes(body.canonical_bytes())
        .map_err(|_| RecoveryMaterialError::SlateConstruction)?;
    let output = slate
        .recipient_output
        .ok_or(RecoveryMaterialError::SlateConstruction)?;
    Ok((*output.commitment.as_bytes(), slate.amount))
}

enum SlatePrivateMaterial {
    Sender {
        excess_blinding: Zeroizing<[u8; 32]>,
        nonce: Zeroizing<[u8; 32]>,
        change: Option<([u8; 33], u64, Zeroizing<[u8; 32]>)>,
    },
    Recipient {
        output_blinding: Zeroizing<[u8; 32]>,
    },
}

fn optional_capsule(
    bytes: &[u8],
) -> Result<Option<[u8; RECOVERY_CAPSULE_SIZE]>, RecoveryMaterialError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let capsule =
        RecoveryCapsule::from_bytes(bytes).map_err(|_| RecoveryMaterialError::InvalidCapsule)?;
    Ok(Some(*capsule.as_bytes()))
}

fn validate_identity(identity: &CoreChainIdentity) -> Result<(), RecoveryMaterialError> {
    if identity.network_magic != identity.network.magic()
        || identity.chain_id == [0u8; 32]
        || identity.protocol_version != dom_core::PROTOCOL_VERSION
        || identity.range_proof_serialization_version != RANGE_PROOF_SERIALIZATION_VERSION
    {
        return Err(RecoveryMaterialError::ChainIdentityMismatch);
    }
    Ok(())
}

fn domain_for_class(class: RecoveryOutputClass) -> OutputRecoveryDomain {
    match class {
        RecoveryOutputClass::ReceiveRequest | RecoveryOutputClass::ReceiveSlate => {
            OutputRecoveryDomain::Received
        }
        RecoveryOutputClass::Change => OutputRecoveryDomain::Change,
        RecoveryOutputClass::SelfTransfer => OutputRecoveryDomain::SelfTransfer,
        RecoveryOutputClass::Coinbase => OutputRecoveryDomain::Coinbase,
    }
}

fn class_for_domain(domain: OutputRecoveryDomain) -> RecoveryOutputClass {
    match domain {
        OutputRecoveryDomain::Received => RecoveryOutputClass::ReceiveSlate,
        OutputRecoveryDomain::Change => RecoveryOutputClass::Change,
        OutputRecoveryDomain::SelfTransfer => RecoveryOutputClass::SelfTransfer,
        OutputRecoveryDomain::Coinbase => RecoveryOutputClass::Coinbase,
    }
}

fn recovered_wallet_output(
    recovered: RecoveredOutput,
    requested_class: RecoveryOutputClass,
) -> RecoveredWalletOutput {
    let class = if recovered.domain == OutputRecoveryDomain::Received {
        requested_class
    } else {
        class_for_domain(recovered.domain)
    };
    RecoveredWalletOutput {
        value: recovered.value,
        account: recovered.account,
        derivation_index: recovered.derivation_index,
        class,
        secret: OutputSpendSecret(recovered.blinding),
    }
}

fn validate_recovery(
    recovered: &RecoveredOutput,
    value: u64,
    account: u32,
    derivation_index: u64,
    domain: OutputRecoveryDomain,
    commitment: &[u8; 33],
) -> Result<(), RecoveryMaterialError> {
    let recomputed = Commitment::commit(recovered.value, &recovered.blinding);
    if recovered.value != value
        || recovered.account != account
        || recovered.derivation_index != derivation_index
        || recovered.domain != domain
        || recomputed.as_bytes() != commitment
    {
        return Err(RecoveryMaterialError::SelfRecoveryMismatch);
    }
    Ok(())
}

/// Typed failures contain no mnemonic, seed, recovery root, value, or blinding.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMaterialError {
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("BIP-39 mnemonic is invalid")]
    InvalidMnemonic,
    #[error("recovery root derivation failed")]
    RecoveryRootDerivation,
    #[error("Core chain identity is incompatible")]
    ChainIdentityMismatch,
    #[error("output value is outside the frozen proof range")]
    ValueOutOfRange,
    #[error("recovery coordinate has the wrong output domain")]
    CoordinateDomainMismatch,
    #[error("frozen output construction failed")]
    OutputConstruction,
    #[error("canonical output encoding failed")]
    CanonicalEncoding,
    #[error("canonical output size is invalid")]
    CanonicalSize,
    #[error("Recovery Capsule v1 is required")]
    RecoveryRequired,
    #[error("Recovery Capsule v1 framing is invalid")]
    InvalidCapsule,
    #[error("range-proof verification failed")]
    ProofVerification,
    #[error("capsule authentication failed")]
    CapsuleAuthentication,
    #[error("self-recovery did not match constructed material")]
    SelfRecoveryMismatch,
    #[error("recoverable Slate construction failed")]
    SlateConstruction,
    #[error("recoverable Slate response does not bind to the persisted offer")]
    SlateBindingMismatch,
}

/// Whether encrypted state is eligible for the canonical BIP-39 boundary.
pub fn state_uses_canonical_seed(state: &WalletState) -> bool {
    state
        .recovery
        .as_ref()
        .is_some_and(|value| value.scheme == RECOVERY_SCHEME_BIP39_256_V1)
}

/// Frozen public constants used by the output boundary.
pub fn frozen_versions() -> (u16, u8) {
    (RECOVERY_VERSION, RANGE_PROOF_SERIALIZATION_VERSION)
}

/// Public kind for a Wallet output class.
pub fn public_output_kind(class: RecoveryOutputClass) -> PublicOutputKind {
    domain_for_class(class).public_kind()
}
