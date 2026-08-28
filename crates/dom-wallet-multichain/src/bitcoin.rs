//! Bitcoin taproot accounts at `m/86'/0'` (BIP-86).
//!
//! Key-path-only taproot: the output key is the BIP-341 tweak of the internal
//! key with an empty script tree. The address pipeline — BIP-39 seed →
//! BIP-32 path → BIP-341 tweak → BIP-350 bech32m — is pinned end to end by
//! the published BIP-86 test vectors.

use crate::bech32m::encode_segwit_v1;
use crate::MultichainError;
use dom_wallet_keys::ExtendedPrivKey;
use secp256k1::{Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Networks the swap tab can render taproot addresses for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BitcoinNetwork {
    /// Mainnet (`bc1p…`).
    Mainnet,
    /// Signet/testnet (`tb1p…`) — the swap laboratory networks.
    Testnet,
    /// Regtest (`bcrt1p…`).
    Regtest,
}

impl BitcoinNetwork {
    fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet => "tb",
            Self::Regtest => "bcrt",
        }
    }
}

/// One derived taproot account: internal key, tweaked output key, address.
pub struct TaprootAccount {
    secret: Zeroizing<[u8; 32]>,
    internal_key: XOnlyPublicKey,
    output_key: XOnlyPublicKey,
    address: String,
}

/// BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || message)`.
fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_digest = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_digest);
    hasher.update(tag_digest);
    hasher.update(message);
    hasher.finalize().into()
}

impl TaprootAccount {
    /// Derive `m/86'/0'/0'/0/index` and produce the BIP-341 key-path output.
    pub(crate) fn derive(
        master: &ExtendedPrivKey,
        network: BitcoinNetwork,
        index: u32,
    ) -> Result<Self, MultichainError> {
        let path = format!("m/86'/0'/0'/0/{index}");
        let child = master
            .derive_path(&path)
            .map_err(|_| MultichainError::Derivation)?;
        let secret = Zeroizing::new(*child.key_bytes());

        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(secret.as_slice()).map_err(|_| MultichainError::InvalidKey)?;
        let (internal_key, _parity) = secret_key.public_key(&secp).x_only_public_key();

        // BIP-341, key-path spend with an empty script tree: the tweak is the
        // tagged hash of the internal key alone.
        let tweak_bytes = tagged_hash(b"TapTweak", &internal_key.serialize());
        let tweak =
            Scalar::from_be_bytes(tweak_bytes).map_err(|_| MultichainError::TaprootTweak)?;
        let (output_key, _output_parity) = internal_key
            .add_tweak(&secp, &tweak)
            .map_err(|_| MultichainError::TaprootTweak)?;

        let address = encode_segwit_v1(network.hrp(), &output_key.serialize());
        Ok(Self {
            secret,
            internal_key,
            output_key,
            address,
        })
    }

    /// The x-only internal key (pre-tweak), as BIP-86 defines it.
    pub fn internal_key(&self) -> [u8; 32] {
        self.internal_key.serialize()
    }

    /// The tweaked x-only output key — the 32-byte witness program.
    pub fn output_key(&self) -> [u8; 32] {
        self.output_key.serialize()
    }

    /// The bech32m address for the configured network.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The derived private key, zeroized on drop. Exists for leg signing;
    /// never logged, never serialized.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::bip86_reference_seed;
    use crate::MultichainRoot;

    /// The three published BIP-86 vectors for the standard test mnemonic.
    #[test]
    fn bip86_published_vectors_match_end_to_end() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed()).expect("root");

        let first = root
            .taproot_account(BitcoinNetwork::Mainnet, 0)
            .expect("account 0/0");
        assert_eq!(
            hex::encode(first.internal_key()),
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
        );
        assert_eq!(
            hex::encode(first.output_key()),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
        assert_eq!(
            first.address(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );

        let second = root
            .taproot_account(BitcoinNetwork::Mainnet, 1)
            .expect("account 0/1");
        assert_eq!(
            second.address(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
    }

    #[test]
    fn networks_change_only_the_prefix() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed()).expect("root");
        let mainnet = root
            .taproot_account(BitcoinNetwork::Mainnet, 0)
            .expect("mainnet");
        let testnet = root
            .taproot_account(BitcoinNetwork::Testnet, 0)
            .expect("testnet");
        assert!(mainnet.address().starts_with("bc1p"));
        assert!(testnet.address().starts_with("tb1p"));
        assert_eq!(mainnet.output_key(), testnet.output_key());
    }
}
