//! Level-1 multichain accounts for the DOM wallet swap tab.
//!
//! The swap tab design (docs/SWAP_TAB_DESIGN.md, premise 1) fixes the model:
//! the wallet derives every swap-leg key from the same BIP-39 seed it
//! already uses. DOM lives at `coin_type` 330, Bitcoin taproot at `m/86'/0'`,
//! EVM at `m/44'/60'`, Solana at `m/44'/501'` (SLIP-0010 ed25519) and Monero
//! at `m/44'/128'` (DOM XMR leg convention v1). Those keys exist to sign
//! swap legs; funds transit, they do not rest here.
//!
//! Everything cryptographic is reused, not reimplemented: BIP-32 derivation
//! comes from the audited `dom-wallet-keys` crate at the same pinned protocol
//! revision the rest of this wallet consumes, and curve operations come from
//! `secp256k1`. This crate adds only what the swap legs need on top: the
//! BIP-341 taproot output tweak, bech32m address encoding (BIP-350) and the
//! EIP-55 checksummed EVM address.
//!
//! Every construction in this crate is pinned to published standard vectors:
//! BIP-86 addresses, EIP-55 checksums and BIP-350 bech32m strings. If any of
//! those tests fail, nothing else about this crate can be trusted.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bech32m;
mod bitcoin;
mod evm;
mod solana;
mod xmr;

pub use bitcoin::{BitcoinNetwork, TaprootAccount};
pub use evm::EvmAccount;
pub use solana::SolanaAccount;
pub use xmr::MoneroAccount;

use dom_wallet_keys::ExtendedPrivKey;
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors surfaced while deriving multichain accounts.
#[derive(Debug, Error)]
pub enum MultichainError {
    /// The BIP-32 derivation itself failed (invalid seed or path).
    #[error("hierarchical derivation failed")]
    Derivation,
    /// A derived private key was not a valid secp256k1 scalar.
    #[error("derived key is not a valid secp256k1 scalar")]
    InvalidKey,
    /// The taproot output-key tweak failed.
    #[error("taproot output tweak failed")]
    TaprootTweak,
}

/// A multichain account root bound to one BIP-39 seed.
///
/// Holds the BIP-32 master key in a zeroizing wrapper; child keys are derived
/// on demand and never stored. This mirrors the route-scalar rule: derive,
/// do not persist.
pub struct MultichainRoot {
    master: Zeroizing<ExtendedPrivKey>,
    seed: Zeroizing<[u8; 64]>,
}

impl MultichainRoot {
    /// Build the root from the wallet's 64-byte BIP-39 seed.
    pub fn from_bip39_seed(seed: &[u8; 64]) -> Result<Self, MultichainError> {
        let master = ExtendedPrivKey::from_seed(seed).map_err(|_| MultichainError::Derivation)?;
        Ok(Self {
            master: Zeroizing::new(master),
            seed: Zeroizing::new(*seed),
        })
    }

    /// Derive the EVM account at `m/44'/60'/0'/0/index`.
    pub fn evm_account(&self, index: u32) -> Result<EvmAccount, MultichainError> {
        EvmAccount::derive(&self.master, index)
    }

    /// Derive the Bitcoin taproot account at `m/86'/0'/0'/0/index`.
    pub fn taproot_account(
        &self,
        network: BitcoinNetwork,
        index: u32,
    ) -> Result<TaprootAccount, MultichainError> {
        TaprootAccount::derive(&self.master, network, index)
    }

    /// Derive the Solana account at `m/44'/501'/index'/0'` (SLIP-0010
    /// ed25519, hardened-only).
    pub fn solana_account(&self, index: u32) -> Result<SolanaAccount, MultichainError> {
        SolanaAccount::derive(&self.seed, index)
    }

    /// Derive the Monero account at `m/44'/128'/account'` under the DOM
    /// XMR leg convention v1.
    pub fn monero_account(&self, account: u32) -> Result<MoneroAccount, MultichainError> {
        MoneroAccount::derive(&self.master, account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-39 reference seed for the standard test mnemonic
    /// "abandon abandon ... about" with an empty passphrase — the seed the
    /// BIP-86 vectors are published against.
    pub(crate) fn bip86_reference_seed() -> [u8; 64] {
        let mut seed = [0u8; 64];
        let bytes = hex::decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        )
        .expect("fixed hex");
        seed.copy_from_slice(&bytes);
        seed
    }

    #[test]
    fn the_root_derives_from_the_reference_seed() {
        let root = MultichainRoot::from_bip39_seed(&bip86_reference_seed())
            .expect("reference seed derives");
        root.evm_account(0).expect("evm account derives");
        root.taproot_account(BitcoinNetwork::Mainnet, 0)
            .expect("taproot account derives");
    }
}
