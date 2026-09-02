//! Solana accounts at `m/44'/501'` over SLIP-0010 ed25519.
//!
//! Solana wallets standardized on hardened-only SLIP-0010 derivation from
//! the BIP-39 seed at `m/44'/501'/index'/0'`; the address is the base58 of
//! the 32-byte ed25519 public key. The SLIP-0010 machinery below is pinned
//! to the published SLIP-0010 ed25519 test vectors — private keys, chain
//! codes and public keys alike — so both the derivation and the RFC 8032
//! public-key rule are vector-locked.

use crate::MultichainError;
use curve25519_dalek::{EdwardsPoint, Scalar};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

type HmacSha512 = Hmac<Sha512>;

/// One SLIP-0010 ed25519 node: 32-byte key and 32-byte chain code.
struct Slip10Node {
    key: Zeroizing<[u8; 32]>,
    chain: Zeroizing<[u8; 32]>,
}

/// SLIP-0010 master node for curve ed25519: `HMAC-SHA512("ed25519 seed", S)`.
fn slip10_master(seed: &[u8]) -> Result<Slip10Node, MultichainError> {
    let mut mac =
        HmacSha512::new_from_slice(b"ed25519 seed").map_err(|_| MultichainError::Derivation)?;
    mac.update(seed);
    let digest = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    chain.copy_from_slice(&digest[32..]);
    Ok(Slip10Node { key, chain })
}

/// SLIP-0010 hardened child for ed25519:
/// `HMAC-SHA512(chain, 0x00 || key || ser32(index + 2^31))`.
/// ed25519 defines hardened derivation only; this function therefore takes
/// the unhardened index and hardens it unconditionally.
fn slip10_hardened_child(node: &Slip10Node, index: u32) -> Result<Slip10Node, MultichainError> {
    let hardened = index
        .checked_add(0x8000_0000)
        .ok_or(MultichainError::Derivation)?;
    let mut mac = HmacSha512::new_from_slice(node.chain.as_slice())
        .map_err(|_| MultichainError::Derivation)?;
    mac.update(&[0u8]);
    mac.update(node.key.as_slice());
    mac.update(&hardened.to_be_bytes());
    let digest = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    chain.copy_from_slice(&digest[32..]);
    Ok(Slip10Node { key, chain })
}

/// RFC 8032 public key of a 32-byte ed25519 secret: clamp the low half of
/// `SHA-512(secret)` and multiply the basepoint. The basepoint has prime
/// order, so reducing the clamped integer mod `l` first leaves the point
/// unchanged.
fn ed25519_public_key(secret: &[u8; 32]) -> [u8; 32] {
    let digest = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(secret)));
    let mut scalar_bytes = Zeroizing::new([0u8; 32]);
    scalar_bytes.copy_from_slice(&digest[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(*scalar_bytes);
    EdwardsPoint::mul_base(&scalar).compress().to_bytes()
}

/// One derived Solana account: ed25519 seed key and base58 address.
pub struct SolanaAccount {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl SolanaAccount {
    /// Derive `m/44'/501'/index'/0'` (every step hardened, the Solana
    /// wallet standard).
    pub(crate) fn derive(seed: &[u8; 64], index: u32) -> Result<Self, MultichainError> {
        let mut node = slip10_master(seed)?;
        for step in [44u32, 501, index, 0] {
            node = slip10_hardened_child(&node, step)?;
        }
        let public = ed25519_public_key(&node.key);
        Ok(Self {
            secret: node.key,
            public,
        })
    }

    /// The base58 address (the encoded ed25519 public key).
    pub fn address(&self) -> String {
        bs58::encode(self.public).into_string()
    }

    /// The raw 32-byte ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// The derived 32-byte ed25519 secret, zeroized on drop. Exists for leg
    /// signing and the recovery hatch; never logged, never serialized.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::bip86_reference_seed;
    use crate::MultichainRoot;

    fn hex32(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(text, &mut out).expect("fixed hex");
        out
    }

    /// SLIP-0010 published test vector 1 for ed25519, including the chained
    /// deep path — pins master derivation, hardened children and the
    /// RFC 8032 public-key rule (the vectors publish `00 || public`).
    #[test]
    fn slip10_ed25519_published_vector_1_is_reproduced_exactly() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").expect("fixed hex");
        let master = slip10_master(&seed).expect("master");
        assert_eq!(
            *master.key,
            hex32("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
        );
        assert_eq!(
            *master.chain,
            hex32("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
        );
        assert_eq!(
            ed25519_public_key(&master.key),
            hex32("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed")
        );

        let child = slip10_hardened_child(&master, 0).expect("m/0'");
        assert_eq!(
            *child.key,
            hex32("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3")
        );
        assert_eq!(
            *child.chain,
            hex32("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69")
        );
        assert_eq!(
            ed25519_public_key(&child.key),
            hex32("8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c")
        );

        let mut deep = child;
        for step in [1u32, 2, 2, 1_000_000_000] {
            deep = slip10_hardened_child(&deep, step).expect("deep chain");
        }
        assert_eq!(
            *deep.key,
            hex32("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793")
        );
        assert_eq!(
            *deep.chain,
            hex32("68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230")
        );
        assert_eq!(
            ed25519_public_key(&deep.key),
            hex32("3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a")
        );
    }

    /// SLIP-0010 published test vector 2 for ed25519 (the 64-byte seed —
    /// the same shape a BIP-39 seed has).
    #[test]
    fn slip10_ed25519_published_vector_2_is_reproduced_exactly() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2\
             9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        )
        .expect("fixed hex");
        let master = slip10_master(&seed).expect("master");
        assert_eq!(
            *master.key,
            hex32("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012")
        );
        let child = slip10_hardened_child(&master, 0).expect("m/0'");
        assert_eq!(
            *child.key,
            hex32("1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635")
        );
        assert_eq!(
            ed25519_public_key(&child.key),
            hex32("86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037")
        );
    }

    /// The standard test mnemonic's first `m/44'/501'/0'/0'` account is
    /// the address the Solana wallet ecosystem (solana-keygen, Phantom)
    /// publishes for it. Any change here is a derivation break that would
    /// strand user funds.
    #[test]
    fn reference_seed_derives_the_published_first_account() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed()).expect("root");
        let a = root.solana_account(0).expect("0");
        assert_eq!(a.address(), "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
        assert_eq!(a.address(), bs58::encode(a.public_bytes()).into_string());
        let b = root.solana_account(1).expect("1");
        assert_ne!(a.public_bytes(), b.public_bytes());
    }
}
