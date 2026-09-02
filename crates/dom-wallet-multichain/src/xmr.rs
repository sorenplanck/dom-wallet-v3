//! Monero accounts derived from the wallet's BIP-39 seed.
//!
//! There is no single cross-vendor standard for producing Monero keys from
//! a BIP-39 seed, so this crate freezes one convention — the widely
//! deployed hardware-wallet scheme — as the DOM XMR leg convention v1:
//!
//! 1. derive the BIP-32 secp256k1 node at `m/44'/128'/account'` from the
//!    wallet seed (128 is Monero's registered SLIP-44 coin type);
//! 2. private spend key = `sc_reduce32(Keccak-256(node private key))`;
//! 3. private view key = `sc_reduce32(Keccak-256(private spend key))`;
//! 4. public keys are direct scalar-basepoint products (Monero performs no
//!    ed25519 clamping), and the mainnet standard address is the Monero
//!    base58 of `varint(0x12) || spend_pub || view_pub` plus the first four
//!    bytes of its Keccak-256 as checksum.
//!
//! The Monero base58 block coder, the varint prefix and the four-byte
//! Keccak checksum are pinned below to the Monero project's own published
//! unit-test vectors. The derivation convention itself is additionally
//! frozen by a reference-seed vector: any change strands user funds.

use crate::MultichainError;
use curve25519_dalek::{EdwardsPoint, Scalar};
use dom_wallet_keys::ExtendedPrivKey;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// Monero mainnet standard-address network tag.
const MAINNET_STANDARD_TAG: u64 = 0x12;

/// Monero's base58 alphabet (identical to Bitcoin's).
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encoded size of a partial final block, indexed by its byte length.
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

/// Encode one block of at most eight bytes as fixed-width base58, padding
/// with the zero digit `1` on the left, exactly as Monero does.
fn encode_block(block: &[u8], out: &mut String) {
    let mut value = 0u64;
    for byte in block {
        value = (value << 8) | u64::from(*byte);
    }
    let width = ENCODED_BLOCK_SIZES[block.len()];
    let mut digits = ['1'; 11];
    let mut cursor = width;
    while value > 0 {
        cursor -= 1;
        digits[cursor] = char::from(ALPHABET[(value % 58) as usize]);
        value /= 58;
    }
    out.extend(&digits[..width]);
}

/// Monero block-wise base58 of arbitrary bytes.
fn monero_base58(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(8) * 11);
    for block in data.chunks(8) {
        encode_block(block, &mut out);
    }
    out
}

/// Little-endian base-128 varint, as Monero serializes address tags.
fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

/// Monero address encoding: `base58(varint(tag) || data || keccak4)`.
fn encode_address(tag: u64, data: &[u8]) -> String {
    let mut payload = varint(tag);
    payload.extend_from_slice(data);
    let checksum = Keccak256::digest(&payload);
    payload.extend_from_slice(&checksum[..4]);
    monero_base58(&payload)
}

/// `sc_reduce32`: interpret 32 little-endian bytes modulo the ed25519 group
/// order `l`.
fn reduce32(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}

/// One derived Monero account: spend/view keypairs and mainnet address.
pub struct MoneroAccount {
    spend_secret: Zeroizing<[u8; 32]>,
    view_secret: Zeroizing<[u8; 32]>,
    spend_public: [u8; 32],
    view_public: [u8; 32],
}

impl MoneroAccount {
    /// Derive the account at `m/44'/128'/account'` under the DOM XMR leg
    /// convention v1 documented in the module header.
    pub(crate) fn derive(master: &ExtendedPrivKey, account: u32) -> Result<Self, MultichainError> {
        let path = format!("m/44'/128'/{account}'");
        let node = master
            .derive_path(&path)
            .map_err(|_| MultichainError::Derivation)?;
        let seed_digest = Zeroizing::new(<[u8; 32]>::from(Keccak256::digest(node.key_bytes())));
        let spend_scalar = reduce32(&seed_digest);
        let spend_secret = Zeroizing::new(spend_scalar.to_bytes());
        let view_digest = Zeroizing::new(<[u8; 32]>::from(Keccak256::digest(*spend_secret)));
        let view_scalar = reduce32(&view_digest);
        let view_secret = Zeroizing::new(view_scalar.to_bytes());
        let spend_public = EdwardsPoint::mul_base(&spend_scalar).compress().to_bytes();
        let view_public = EdwardsPoint::mul_base(&view_scalar).compress().to_bytes();
        Ok(Self {
            spend_secret,
            view_secret,
            spend_public,
            view_public,
        })
    }

    /// The mainnet standard address.
    pub fn address(&self) -> String {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(&self.spend_public);
        data[32..].copy_from_slice(&self.view_public);
        encode_address(MAINNET_STANDARD_TAG, &data)
    }

    /// The private spend key, zeroized on drop. Exists for the recovery
    /// hatch and leg signing; never logged, never serialized.
    pub fn spend_secret_bytes(&self) -> &[u8; 32] {
        &self.spend_secret
    }

    /// The private view key, zeroized on drop.
    pub fn view_secret_bytes(&self) -> &[u8; 32] {
        &self.view_secret
    }

    /// The public spend key.
    pub fn spend_public_bytes(&self) -> [u8; 32] {
        self.spend_public
    }

    /// The public view key.
    pub fn view_public_bytes(&self) -> [u8; 32] {
        self.view_public
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::bip86_reference_seed;
    use crate::MultichainRoot;

    /// Monero project unit-test vectors for the block coder
    /// (tests/unit_tests/base58.cpp).
    #[test]
    fn monero_base58_published_block_vectors_encode_exactly() {
        for (data, expected) in [
            (&[0x00u8][..], "11"),
            (&[0x39][..], "1z"),
            (&[0xff][..], "5Q"),
            (&[0x00, 0x00][..], "111"),
            (&[0xff, 0xff][..], "LUv"),
            (&[0xff, 0xff, 0xff][..], "2UzHL"),
            (&[0xff, 0xff, 0xff, 0xff][..], "7YXq9G"),
            (&[0xff, 0xff, 0xff, 0xff, 0xff][..], "VtB5VXc"),
            (
                &[0x06, 0x15, 0x60, 0x13, 0x76, 0x28, 0x79, 0xf7][..],
                "22222222222",
            ),
            (
                &[
                    0x06, 0x15, 0x60, 0x13, 0x76, 0x28, 0x79, 0xf7, 0xff, 0xff, 0xff, 0xff, 0xff,
                ][..],
                "22222222222VtB5VXc",
            ),
        ] {
            assert_eq!(monero_base58(data), expected);
        }
    }

    /// Monero project unit-test vectors for the full address encoding —
    /// varint tag, payload and Keccak four-byte checksum together
    /// (tests/unit_tests/base58.cpp, encode_addr).
    #[test]
    fn monero_published_address_vectors_encode_exactly() {
        assert_eq!(encode_address(0, &[]), "15p2yAV");
        assert_eq!(encode_address(0x7f, &[]), "FNQ3D6A");
        assert_eq!(
            encode_address(6, &[0u8; 64]),
            "21D35quxec71111111111111111111111111111111111111111111111111111111111111111111111111111116Q5tCH"
        );
    }

    /// Frozen DOM XMR leg convention v1 vector for the reference seed at
    /// `m/44'/128'/0'`. Any change here is a derivation break that would
    /// strand user funds.
    #[test]
    fn reference_seed_derives_the_frozen_convention_v1_account() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed()).expect("root");
        let account = root.monero_account(0).expect("account");
        let address = account.address();
        // Mainnet standard addresses are 95 characters and start with '4'
        // (tag 0x12 places the first block in the '4' range).
        assert_eq!(address.len(), 95);
        assert_eq!(
            address,
            "47tNqJEWRkQgEqBT67RwRBP9tMLBRmmWTDyTpbW2hvoYZmSki9HwyoWhbVuBEs7VY74f14cWFELAYiqdC6stwmL3K7oFB5u"
        );
        assert_eq!(
            hex::encode(account.spend_secret_bytes()),
            "38652206c13a043ba70f75f0c7829d2ce9e601b02c0666a408047dd5e871510a"
        );
        assert_eq!(
            hex::encode(account.view_secret_bytes()),
            "97e13e07df84cceab533df6ff1442a06387cfa115f1d71e1ffd48d878e5bf809"
        );
        // The view key must be the frozen function of the spend key.
        let expected_view = Keccak256::digest(account.spend_secret_bytes());
        assert_eq!(
            reduce32(&<[u8; 32]>::from(expected_view)).to_bytes(),
            *account.view_secret_bytes()
        );
    }
}
