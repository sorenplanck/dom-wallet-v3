//! The wallet's Initiator identity.
//!
//! The relay authenticates every envelope with a BIP340 signature
//! against the roster, so the wallet needs one canonical signing key.
//! It is derived deterministically from the wallet's own BIP-39 seed
//! under a dedicated domain — self-custody all the way down: recovering
//! the seed recovers the swap identity, and the operator's roster entry
//! is registered against the public key this derivation prints.

use btc_crypto::SecpContext;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::SwapClientError;

/// HKDF salt domain of the Initiator signing key.
pub const INITIATOR_KEY_DOMAIN: &[u8] = b"DOM-WALLET/SWAP-INITIATOR-KEY/V1";

/// Derives the wallet's BIP340 Initiator keypair from the 64-byte
/// BIP-39 seed: HKDF-SHA512 under the frozen domain, with a counter in
/// the info so the negligible invalid-scalar case retries instead of
/// failing. Returns the zeroizing secret and the x-only public key the
/// operator registers in the roster.
pub fn initiator_keypair(
    seed: &[u8; 64],
    secp: &SecpContext,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), SwapClientError> {
    let hk = Hkdf::<Sha512>::new(Some(INITIATOR_KEY_DOMAIN), seed);
    for counter in 0u8..=7 {
        let mut candidate = Zeroizing::new([0u8; 32]);
        hk.expand(&[b'k', counter], candidate.as_mut())
            .map_err(|_| SwapClientError::IdentityDerivation)?;
        // Probing with a signature over a fixed digest both validates
        // the scalar and yields the x-only key from the same pinned
        // backend that will sign envelopes.
        if let Ok((_, xonly)) = secp.sign_bip340(&candidate, &[0u8; 32], &[0u8; 32]) {
            return Ok((candidate, xonly));
        }
    }
    Err(SwapClientError::IdentityDerivation)
}

/// The wallet's Initiator public key alone, deriving the backend
/// context seed from the same wallet seed under a distinct info label —
/// for surfaces (the UI's roster-registration card) that need the
/// public identity without holding a context.
pub fn initiator_public_identity(seed: &[u8; 64]) -> Result<[u8; 32], SwapClientError> {
    let hk = Hkdf::<Sha512>::new(Some(INITIATOR_KEY_DOMAIN), seed);
    let mut context_seed = Zeroizing::new([0u8; 32]);
    hk.expand(b"secp-context", context_seed.as_mut())
        .map_err(|_| SwapClientError::IdentityDerivation)?;
    let secp = SecpContext::new(&context_seed);
    initiator_keypair(seed, &secp).map(|(_, xonly)| xonly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_identity_matches_the_keypair_derivation() {
        let secp = SecpContext::new(&[0x07; 32]);
        let (_, xonly) = initiator_keypair(&[0x42; 64], &secp).expect("derives");
        assert_eq!(
            initiator_public_identity(&[0x42; 64]).expect("derives"),
            xonly
        );
    }

    #[test]
    fn the_identity_is_deterministic_and_seed_bound() {
        let secp = SecpContext::new(&[0x07; 32]);
        let (secret_a, xonly_a) = initiator_keypair(&[0x42; 64], &secp).expect("derives");
        let (secret_b, xonly_b) = initiator_keypair(&[0x42; 64], &secp).expect("derives again");
        assert_eq!(*secret_a, *secret_b);
        assert_eq!(xonly_a, xonly_b);
        let (_, other) = initiator_keypair(&[0x43; 64], &secp).expect("derives");
        assert_ne!(xonly_a, other);
    }

    #[test]
    fn the_derived_key_signs_and_verifies_under_the_pinned_backend() {
        let secp = SecpContext::new(&[0x07; 32]);
        let (secret, xonly) = initiator_keypair(&[0x42; 64], &secp).expect("derives");
        let message = [0xAB; 32];
        let (signature, signer) = secp
            .sign_bip340(&secret, &message, &[0x01; 32])
            .expect("signs");
        assert_eq!(signer, xonly);
        secp.verify_bip340(&xonly, &message, &signature)
            .expect("verifies");
    }
}
