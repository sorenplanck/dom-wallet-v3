//! EVM accounts at `m/44'/60'` with EIP-55 checksummed addresses.
//!
//! The address is the last twenty bytes of the Keccak-256 of the
//! uncompressed public key body, checksummed per EIP-55. Pinned to the
//! EIP-55 published vectors.

use crate::MultichainError;
use dom_wallet_keys::ExtendedPrivKey;
use secp256k1::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// One derived EVM account: key material and checksummed address.
pub struct EvmAccount {
    secret: Zeroizing<[u8; 32]>,
    address: [u8; 20],
}

/// EIP-55 checksummed rendering of a 20-byte address.
fn checksummed(address: &[u8; 20]) -> String {
    let lower = hex_lower(address);
    let digest = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = (digest[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0x0f;
        if c.is_ascii_alphabetic() && nibble >= 8 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn hex_lower(bytes: &[u8; 20]) -> String {
    let mut out = String::with_capacity(40);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

impl EvmAccount {
    /// Derive `m/44'/60'/0'/0/index`.
    pub(crate) fn derive(master: &ExtendedPrivKey, index: u32) -> Result<Self, MultichainError> {
        let path = format!("m/44'/60'/0'/0/{index}");
        let child = master
            .derive_path(&path)
            .map_err(|_| MultichainError::Derivation)?;
        let secret = Zeroizing::new(*child.key_bytes());

        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_slice(secret.as_slice()).map_err(|_| MultichainError::InvalidKey)?;
        let uncompressed = secret_key.public_key(&secp).serialize_uncompressed();
        let digest = Keccak256::digest(&uncompressed[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&digest[12..]);
        Ok(Self { secret, address })
    }

    /// The EIP-55 checksummed address string.
    pub fn address(&self) -> String {
        checksummed(&self.address)
    }

    /// The raw 20-byte address.
    pub fn address_bytes(&self) -> [u8; 20] {
        self.address
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

    /// EIP-55 published checksum vectors.
    #[test]
    fn eip55_published_vectors_checksum_exactly() {
        for expected in [
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ] {
            let mut raw = [0u8; 20];
            let bytes = hex::decode(expected[2..].to_lowercase()).expect("fixed hex");
            raw.copy_from_slice(&bytes);
            assert_eq!(checksummed(&raw), *expected);
        }
    }

    /// The standard test mnemonic's first `m/44'/60'/0'/0/0` account is a
    /// widely published cross-implementation vector.
    #[test]
    fn reference_seed_derives_the_published_first_account() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed()).expect("root");
        let account = root.evm_account(0).expect("account");
        assert_eq!(
            account.address(),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
    }

    #[test]
    fn distinct_indices_produce_distinct_addresses() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed()).expect("root");
        let a = root.evm_account(0).expect("0");
        let b = root.evm_account(1).expect("1");
        assert_ne!(a.address_bytes(), b.address_bytes());
    }
}
