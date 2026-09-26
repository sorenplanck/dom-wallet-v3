#![forbid(unsafe_code)]

//! Versioned Option A at-rest envelope boundary.
//!
//! The profile preserves DOM Wallet continuity properties—Argon2id password
//! hardening, authenticated encryption, versioning, bounded parameters and
//! atomic caller-owned publication—without exposing raw keys across layers.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

pub const PROFILE_NAME: &str = "HARDENED_DOM_WALLET_CONTINUITY_V1";
pub const ENVELOPE_MAGIC: [u8; 8] = *b"DOMWV3A1";
/// Version written by every current writer: the ciphertext is carried as one
/// canonical, padded standard-alphabet base64 string (about 1.33 bytes per
/// ciphertext byte).
pub const ENVELOPE_VERSION: u16 = 2;
/// Version written by wallets released before the compact envelope. The
/// ciphertext is a JSON array of decimal numbers (about 3.6 bytes per
/// ciphertext byte). It stays readable forever and writable only on explicit
/// request (fixtures, downgrade tooling).
pub const ENVELOPE_VERSION_LEGACY_V1: u16 = 1;
/// Hard bound for the plaintext of a current (v2) envelope.
///
/// Measured, not averaged: an owned output costs 778 plaintext bytes in a
/// typical state and at most 964 bytes with every field at its widest JSON
/// width, so the domain ceiling (`MAX_OUTPUTS` = 100 000) needs at most
/// ~92.7 MiB including the 2048-block reorg window. 128 MiB keeps ~35 MiB for
/// the remaining persisted structures (transactions, swap sessions,
/// Scriptless reservations). It bounds allocation on corrupted or hostile
/// files; a state beyond it fails with a typed storage-limit error.
pub const MAX_PLAINTEXT_BYTES: usize = 128 * 1024 * 1024;
/// Hard bound for an encoded current (v2) envelope file: base64 of the
/// maximal ciphertext (plaintext + 16-byte tag, 4/3 expansion) plus 2 MiB for
/// the JSON header, i.e. about 172.7 MiB.
pub const MAX_ENVELOPE_BYTES: usize = MAX_PLAINTEXT_BYTES / 3 * 4 + 2 * 1024 * 1024;
/// The exact bound every pre-v2 writer enforced, for both plaintext and
/// encoded bytes. A genuine legacy envelope can never be larger, so the
/// reader keeps enforcing it for v1.
pub const LEGACY_V1_MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
const AEAD_TAG_BYTES: usize = 16;
pub const MAX_KDF_MEMORY_KIB: u32 = 256 * 1024;
pub const MAX_KDF_TIME_COST: u32 = 10;
pub const MAX_KDF_PARALLELISM: u32 = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParameters {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl KdfParameters {
    pub const DOM_CONTINUITY: Self = Self {
        memory_kib: 65_536,
        time_cost: 3,
        parallelism: 1,
    };
    pub const TEST: Self = Self {
        memory_kib: 64,
        time_cost: 1,
        parallelism: 1,
    };

    pub fn validate(self) -> Result<(), CryptoError> {
        if self.memory_kib == 0
            || self.memory_kib > MAX_KDF_MEMORY_KIB
            || self.time_cost == 0
            || self.time_cost > MAX_KDF_TIME_COST
            || self.parallelism == 0
            || self.parallelism > MAX_KDF_PARALLELISM
        {
            return Err(CryptoError::KdfParametersOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn random(len: usize) -> Result<Self, CryptoError> {
        if len == 0 || len > 4096 {
            return Err(CryptoError::InvalidSecretLength);
        }
        let mut bytes = Zeroizing::new(vec![0; len]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(CryptoError::InvalidSecretLength);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn expose_for_crypto(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeHeader {
    pub magic: [u8; 8],
    pub envelope_version: u16,
    pub profile: String,
    pub kdf: KdfParameters,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
}

/// Authenticated envelope. The JSON representation of `ciphertext` is bound
/// to `header.envelope_version` (which is itself authenticated as AEAD
/// associated data): v1 is a numeric array, v2 a canonical base64 string. Any
/// other pairing is rejected while decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedEnvelope {
    pub header: EnvelopeHeader,
    pub ciphertext: Vec<u8>,
}

impl Serialize for EncryptedEnvelope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("EncryptedEnvelope", 2)?;
        state.serialize_field("header", &self.header)?;
        if self.header.envelope_version == ENVELOPE_VERSION_LEGACY_V1 {
            state.serialize_field("ciphertext", &self.ciphertext)?;
        } else {
            state.serialize_field("ciphertext", &BASE64_STANDARD.encode(&self.ciphertext))?;
        }
        state.end()
    }
}

enum RawCiphertext {
    NumericArray(Vec<u8>),
    Base64(String),
}

impl<'de> Deserialize<'de> for RawCiphertext {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RawCiphertextVisitor;

        impl<'de> Visitor<'de> for RawCiphertextVisitor {
            type Value = RawCiphertext;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a legacy byte array or a base64 ciphertext string")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(RawCiphertext::Base64(value.to_owned()))
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(RawCiphertext::Base64(value))
            }

            // Streams the legacy array element by element (never through an
            // untagged buffer) and refuses to grow beyond the legacy bound.
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(LEGACY_V1_MAX_ENVELOPE_BYTES),
                );
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() >= LEGACY_V1_MAX_ENVELOPE_BYTES + AEAD_TAG_BYTES {
                        return Err(de::Error::custom("legacy ciphertext exceeds its bound"));
                    }
                    bytes.push(byte);
                }
                Ok(RawCiphertext::NumericArray(bytes))
            }
        }

        deserializer.deserialize_any(RawCiphertextVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnvelope {
    header: EnvelopeHeader,
    ciphertext: RawCiphertext,
}

impl<'de> Deserialize<'de> for EncryptedEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawEnvelope::deserialize(deserializer)?;
        let ciphertext = match (raw.header.envelope_version, raw.ciphertext) {
            (ENVELOPE_VERSION_LEGACY_V1, RawCiphertext::NumericArray(bytes)) => bytes,
            (ENVELOPE_VERSION, RawCiphertext::Base64(text)) => {
                if text.len() > MAX_ENVELOPE_BYTES {
                    return Err(de::Error::custom("ciphertext exceeds its bound"));
                }
                BASE64_STANDARD
                    .decode(text.as_bytes())
                    .map_err(|_| de::Error::custom("ciphertext is not canonical base64"))?
            }
            (ENVELOPE_VERSION_LEGACY_V1 | ENVELOPE_VERSION, _) => {
                return Err(de::Error::custom(
                    "ciphertext representation does not match the envelope version",
                ))
            }
            // Unknown versions keep their bytes so header validation reports
            // a typed UnsupportedVersion instead of a generic parse failure.
            (_, RawCiphertext::NumericArray(bytes)) => bytes,
            (_, RawCiphertext::Base64(_)) => Vec::new(),
        };
        Ok(Self {
            header: raw.header,
            ciphertext,
        })
    }
}

/// Seal a plaintext into a current (v2, compact) envelope.
pub fn seal(
    plaintext: &[u8],
    password: &str,
    canonical_context: &[u8],
    kdf: KdfParameters,
) -> Result<EncryptedEnvelope, CryptoError> {
    seal_with_version(
        plaintext,
        password,
        canonical_context,
        kdf,
        ENVELOPE_VERSION,
    )
}

/// Seal a plaintext into the pre-v2 legacy envelope format with the exact
/// legacy bounds. Compiled only for tests and the `legacy-writer` feature
/// (compatibility fixtures and regression tests); normal writers use [`seal`].
#[cfg(any(test, feature = "legacy-writer"))]
pub fn seal_legacy_v1(
    plaintext: &[u8],
    password: &str,
    canonical_context: &[u8],
    kdf: KdfParameters,
) -> Result<EncryptedEnvelope, CryptoError> {
    seal_with_version(
        plaintext,
        password,
        canonical_context,
        kdf,
        ENVELOPE_VERSION_LEGACY_V1,
    )
}

/// Largest plaintext accepted by an envelope of `version`.
pub fn max_plaintext_bytes(version: u16) -> usize {
    if version == ENVELOPE_VERSION_LEGACY_V1 {
        LEGACY_V1_MAX_ENVELOPE_BYTES
    } else {
        MAX_PLAINTEXT_BYTES
    }
}

/// Largest encoded envelope accepted for `version`.
pub fn max_encoded_bytes(version: u16) -> usize {
    if version == ENVELOPE_VERSION_LEGACY_V1 {
        LEGACY_V1_MAX_ENVELOPE_BYTES
    } else {
        MAX_ENVELOPE_BYTES
    }
}

fn seal_with_version(
    plaintext: &[u8],
    password: &str,
    canonical_context: &[u8],
    kdf: KdfParameters,
    envelope_version: u16,
) -> Result<EncryptedEnvelope, CryptoError> {
    if password.is_empty() || canonical_context.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    if plaintext.len() > max_plaintext_bytes(envelope_version) {
        return Err(CryptoError::PlaintextTooLarge);
    }
    kdf.validate()?;
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    let key = derive_key(password, &salt, kdf)?;
    let header = EnvelopeHeader {
        magic: ENVELOPE_MAGIC,
        envelope_version,
        profile: PROFILE_NAME.into(),
        kdf,
        salt,
        nonce,
    };
    let aad = envelope_aad(&header, canonical_context)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_for_crypto())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(EncryptedEnvelope { header, ciphertext })
}

pub fn open(
    envelope: &EncryptedEnvelope,
    password: &str,
    canonical_context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if password.is_empty() || canonical_context.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    validate_header(&envelope.header)?;
    let plaintext_bound = max_plaintext_bytes(envelope.header.envelope_version);
    if envelope.ciphertext.len() > plaintext_bound.saturating_add(AEAD_TAG_BYTES) {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    let key = derive_key(password, &envelope.header.salt, envelope.header.kdf)?;
    let aad = envelope_aad(&envelope.header, canonical_context)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_for_crypto())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope.header.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    if plaintext.len() > plaintext_bound {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    Ok(Zeroizing::new(plaintext))
}

/// Encode an envelope in the representation its header version requires,
/// enforcing that version's bound.
pub fn encode(envelope: &EncryptedEnvelope) -> Result<Vec<u8>, CryptoError> {
    let encoded = encode_unbounded(envelope)?;
    if encoded.len() > max_encoded_bytes(envelope.header.envelope_version) {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    Ok(encoded)
}

/// Size the encoded envelope would have, without applying the bound. Used to
/// report exact sizes when [`encode`] refuses an oversized envelope.
pub fn encoded_len(envelope: &EncryptedEnvelope) -> Result<usize, CryptoError> {
    encode_unbounded(envelope).map(|encoded| encoded.len())
}

fn encode_unbounded(envelope: &EncryptedEnvelope) -> Result<Vec<u8>, CryptoError> {
    validate_header(&envelope.header)?;
    serde_json::to_vec(envelope).map_err(|_| CryptoError::CanonicalEncoding)
}

/// Read and validate only the authenticated-envelope header version, skipping
/// the ciphertext without materializing it. Nothing is decrypted.
pub fn peek_envelope_version(encoded: &[u8]) -> Result<u16, CryptoError> {
    #[derive(Deserialize)]
    struct HeaderProbe {
        header: EnvelopeHeader,
        #[allow(dead_code)]
        ciphertext: de::IgnoredAny,
    }
    if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    let probe: HeaderProbe =
        serde_json::from_slice(encoded).map_err(|_| CryptoError::CanonicalEncoding)?;
    validate_header(&probe.header)?;
    if encoded.len() > max_encoded_bytes(probe.header.envelope_version) {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    Ok(probe.header.envelope_version)
}

pub fn decode(encoded: &[u8]) -> Result<EncryptedEnvelope, CryptoError> {
    if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(encoded).map_err(|_| CryptoError::CanonicalEncoding)?;
    validate_header(&envelope.header)?;
    if encoded.len() > max_encoded_bytes(envelope.header.envelope_version) {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    Ok(envelope)
}

fn validate_header(header: &EnvelopeHeader) -> Result<(), CryptoError> {
    if header.magic != ENVELOPE_MAGIC
        || !matches!(
            header.envelope_version,
            ENVELOPE_VERSION | ENVELOPE_VERSION_LEGACY_V1
        )
        || header.profile != PROFILE_NAME
    {
        return Err(CryptoError::UnsupportedVersion);
    }
    header.kdf.validate()
}

fn derive_key(
    password: &str,
    salt: &[u8; 32],
    parameters: KdfParameters,
) -> Result<SecretBytes, CryptoError> {
    parameters.validate()?;
    let params = Params::new(
        parameters.memory_kib,
        parameters.time_cost,
        parameters.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::KdfParametersOutOfBounds)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut password_material = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *password_material)
        .map_err(|_| CryptoError::KdfFailed)?;
    let expansion = Hkdf::<Sha256>::new(Some(salt), &password_material[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    expansion
        .expand(b"DOM-WALLET-V3-STATE-ENCRYPTION-V1", &mut *key)
        .map_err(|_| CryptoError::KdfFailed)?;
    SecretBytes::from_bytes(key.to_vec())
}

fn envelope_aad(header: &EnvelopeHeader, context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut digest = Sha256::new();
    digest.update(header.magic);
    digest.update(header.envelope_version.to_le_bytes());
    digest.update(header.profile.as_bytes());
    digest.update(header.salt);
    digest.update(context);
    Ok(digest.finalize().to_vec())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("invalid secret length")]
    InvalidSecretLength,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid cryptographic input")]
    InvalidInput,
    #[error("KDF parameters are out of bounds")]
    KdfParametersOutOfBounds,
    #[error("key derivation failed")]
    KdfFailed,
    #[error("unsupported envelope or profile version")]
    UnsupportedVersion,
    #[error("canonical envelope encoding failed")]
    CanonicalEncoding,
    #[error("envelope exceeds bounded size")]
    EnvelopeTooLarge,
    #[error("plaintext exceeds the envelope bound")]
    PlaintextTooLarge,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("envelope authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_rejects_wrong_password_and_context() {
        let envelope = seal(b"state", "correct", b"wallet:one", KdfParameters::TEST).unwrap();
        assert_eq!(
            open(&envelope, "wrong", b"wallet:one"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            open(&envelope, "correct", b"wallet:two"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn envelope_rejects_excessive_parameters_and_unknown_version() {
        let bad = KdfParameters {
            memory_kib: MAX_KDF_MEMORY_KIB + 1,
            ..KdfParameters::TEST
        };
        assert_eq!(
            seal(b"state", "password", b"context", bad),
            Err(CryptoError::KdfParametersOutOfBounds)
        );
        let mut envelope = seal(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        envelope.header.envelope_version += 1;
        assert_eq!(
            open(&envelope, "password", b"context"),
            Err(CryptoError::UnsupportedVersion)
        );
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        bytes
    }

    #[test]
    fn current_envelope_is_version_two_base64_and_round_trips() {
        let envelope = seal(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        assert_eq!(envelope.header.envelope_version, ENVELOPE_VERSION);
        let encoded = encode(&envelope).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert!(
            json["ciphertext"].is_string(),
            "v2 ciphertext is one string"
        );
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(
            open(&decoded, "password", b"context").unwrap().as_slice(),
            b"state"
        );
    }

    #[test]
    fn legacy_v1_envelope_keeps_its_exact_numeric_array_representation() {
        let envelope =
            seal_legacy_v1(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        assert_eq!(envelope.header.envelope_version, ENVELOPE_VERSION_LEGACY_V1);
        let encoded = encode(&envelope).unwrap();
        // Byte-identical to the pre-v2 derived serializer.
        #[derive(Serialize)]
        struct PreV2<'a> {
            header: &'a EnvelopeHeader,
            ciphertext: &'a Vec<u8>,
        }
        let reference = serde_json::to_vec(&PreV2 {
            header: &envelope.header,
            ciphertext: &envelope.ciphertext,
        })
        .unwrap();
        assert_eq!(encoded, reference);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(
            open(&decoded, "password", b"context").unwrap().as_slice(),
            b"state"
        );
    }

    #[test]
    fn representation_must_match_the_authenticated_version() {
        let v2 = seal(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        let mut as_v1_array: serde_json::Value =
            serde_json::from_slice(&encode(&v2).unwrap()).unwrap();
        as_v1_array["ciphertext"] = serde_json::to_value(&v2.ciphertext).unwrap();
        assert_eq!(
            decode(&serde_json::to_vec(&as_v1_array).unwrap()),
            Err(CryptoError::CanonicalEncoding)
        );
        let v1 = seal_legacy_v1(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        let mut as_v2_text: serde_json::Value =
            serde_json::from_slice(&encode(&v1).unwrap()).unwrap();
        as_v2_text["ciphertext"] =
            serde_json::Value::String(BASE64_STANDARD.encode(&v1.ciphertext));
        assert_eq!(
            decode(&serde_json::to_vec(&as_v2_text).unwrap()),
            Err(CryptoError::CanonicalEncoding)
        );
        // Relabelling the version cannot bypass authentication either.
        let mut relabelled = v1.clone();
        relabelled.header.envelope_version = ENVELOPE_VERSION;
        assert_eq!(
            open(&relabelled, "password", b"context"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn corrupted_or_noncanonical_base64_is_rejected() {
        let envelope = seal(b"state bytes", "password", b"context", KdfParameters::TEST).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&encode(&envelope).unwrap()).unwrap();
        let text = json["ciphertext"].as_str().unwrap().to_owned();
        json["ciphertext"] = serde_json::Value::String(format!("{text}!"));
        assert_eq!(
            decode(&serde_json::to_vec(&json).unwrap()),
            Err(CryptoError::CanonicalEncoding)
        );
        let mut flipped = envelope.clone();
        flipped.ciphertext[0] ^= 1;
        let reencoded = encode(&flipped).unwrap();
        assert_eq!(
            open(&decode(&reencoded).unwrap(), "password", b"context"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn size_bounds_are_version_specific() {
        let big = random_bytes(LEGACY_V1_MAX_ENVELOPE_BYTES / 3);
        // Five MiB of ciphertext overflows the legacy array encoding ...
        let legacy = seal_legacy_v1(&big, "password", b"context", KdfParameters::TEST).unwrap();
        assert_eq!(encode(&legacy), Err(CryptoError::EnvelopeTooLarge));
        assert!(encoded_len(&legacy).unwrap() > LEGACY_V1_MAX_ENVELOPE_BYTES);
        // ... but is comfortably inside the compact bound.
        let compact = seal(&big, "password", b"context", KdfParameters::TEST).unwrap();
        let encoded = encode(&compact).unwrap();
        assert!(encoded.len() < big.len() * 4 / 3 + 1024);
        assert_eq!(
            seal_legacy_v1(
                &vec![0u8; LEGACY_V1_MAX_ENVELOPE_BYTES + 1],
                "password",
                b"context",
                KdfParameters::TEST
            ),
            Err(CryptoError::PlaintextTooLarge)
        );
        assert_eq!(
            decode(&vec![b' '; MAX_ENVELOPE_BYTES + 1]),
            Err(CryptoError::EnvelopeTooLarge)
        );
        assert_eq!(decode(&[]), Err(CryptoError::EnvelopeTooLarge));
    }

    #[test]
    fn unknown_envelope_version_is_rejected_on_decode() {
        let envelope = seal(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&encode(&envelope).unwrap()).unwrap();
        json["header"]["envelope_version"] = serde_json::Value::from(3);
        assert_eq!(
            decode(&serde_json::to_vec(&json).unwrap()),
            Err(CryptoError::UnsupportedVersion)
        );
    }

    fn padded_to(envelope: &EncryptedEnvelope, total: usize) -> Vec<u8> {
        let mut encoded = serde_json::to_vec(envelope).unwrap();
        assert!(encoded.len() <= total);
        encoded.resize(total, b' '); // trailing JSON whitespace
        encoded
    }

    #[test]
    fn plaintext_bounds_below_at_and_above_for_both_versions() {
        let at_legacy = vec![7u8; LEGACY_V1_MAX_ENVELOPE_BYTES];
        seal_legacy_v1(&at_legacy, "password", b"context", KdfParameters::TEST)
            .expect("exactly at the legacy bound");
        seal_legacy_v1(&at_legacy[1..], "password", b"context", KdfParameters::TEST)
            .expect("below the legacy bound");
        let mut above_legacy = at_legacy;
        above_legacy.push(7);
        assert_eq!(
            seal_legacy_v1(&above_legacy, "password", b"context", KdfParameters::TEST),
            Err(CryptoError::PlaintextTooLarge)
        );
        drop(above_legacy);

        // v2: the maximal plaintext seals, encodes within the envelope bound
        // (the bounds are derived consistently), decodes and opens.
        let mut at_limit = vec![0x41u8; MAX_PLAINTEXT_BYTES];
        let envelope = seal(&at_limit, "password", b"context", KdfParameters::TEST)
            .expect("exactly at the plaintext bound");
        let encoded = encode(&envelope).expect("maximal envelope encodes");
        assert!(encoded.len() <= MAX_ENVELOPE_BYTES);
        drop(envelope);
        let opened = open(&decode(&encoded).unwrap(), "password", b"context").unwrap();
        assert_eq!(opened.len(), MAX_PLAINTEXT_BYTES);
        drop((opened, encoded));
        at_limit.push(0x41);
        assert_eq!(
            seal(&at_limit, "password", b"context", KdfParameters::TEST),
            Err(CryptoError::PlaintextTooLarge),
            "rejected before any KDF or encryption work"
        );
    }

    #[test]
    fn encoded_bounds_below_at_and_above_for_both_versions() {
        let v2 = seal(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        for total in [MAX_ENVELOPE_BYTES - 1, MAX_ENVELOPE_BYTES] {
            assert_eq!(decode(&padded_to(&v2, total)).unwrap(), v2);
        }
        assert_eq!(
            decode(&padded_to(&v2, MAX_ENVELOPE_BYTES + 1)),
            Err(CryptoError::EnvelopeTooLarge)
        );
        let v1 = seal_legacy_v1(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        for total in [
            LEGACY_V1_MAX_ENVELOPE_BYTES - 1,
            LEGACY_V1_MAX_ENVELOPE_BYTES,
        ] {
            assert_eq!(decode(&padded_to(&v1, total)).unwrap(), v1);
            assert_eq!(peek_envelope_version(&padded_to(&v1, total)).unwrap(), 1);
        }
        assert_eq!(
            decode(&padded_to(&v1, LEGACY_V1_MAX_ENVELOPE_BYTES + 1)),
            Err(CryptoError::EnvelopeTooLarge),
            "a v1 file larger than any released writer produced is rejected"
        );
    }

    #[test]
    fn every_authenticated_field_is_tamper_evident() {
        let envelope = seal(b"wallet state", "password", b"context", KdfParameters::TEST).unwrap();
        let fails = |candidate: &EncryptedEnvelope, context: &[u8]| {
            let reencoded = encode(candidate).unwrap();
            assert_eq!(
                open(&decode(&reencoded).unwrap(), "password", context),
                Err(CryptoError::AuthenticationFailed)
            );
        };
        fails(&envelope, b"other context");
        let mut nonce = envelope.clone();
        nonce.header.nonce[0] ^= 1;
        fails(&nonce, b"context");
        let mut salt = envelope.clone();
        salt.header.salt[0] ^= 1;
        fails(&salt, b"context");
        let mut ciphertext = envelope.clone();
        let last = ciphertext.ciphertext.len() - 1;
        ciphertext.ciphertext[last] ^= 0x80; // authentication tag
        fails(&ciphertext, b"context");
        // Version downgrade with a consistent v1 representation: the version
        // is associated data, so a v2 ciphertext never opens as v1.
        let mut downgraded = envelope.clone();
        downgraded.header.envelope_version = ENVELOPE_VERSION_LEGACY_V1;
        fails(&downgraded, b"context");
        // KDF parameters are validated before any derivation.
        let mut json: serde_json::Value =
            serde_json::from_slice(&encode(&envelope).unwrap()).unwrap();
        json["header"]["kdf"]["memory_kib"] = serde_json::Value::from(MAX_KDF_MEMORY_KIB + 1);
        assert_eq!(
            decode(&serde_json::to_vec(&json).unwrap()),
            Err(CryptoError::KdfParametersOutOfBounds)
        );
        let mut profile = envelope.clone();
        profile.header.profile = "OTHER".into();
        assert_eq!(
            open(&profile, "password", b"context"),
            Err(CryptoError::UnsupportedVersion)
        );
    }

    #[test]
    fn every_seal_uses_fresh_salt_and_nonce() {
        let first = seal(b"same", "password", b"context", KdfParameters::TEST).unwrap();
        let second = seal(b"same", "password", b"context", KdfParameters::TEST).unwrap();
        assert_ne!(first.header.salt, second.header.salt);
        assert_ne!(first.header.nonce, second.header.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn migration_reencrypts_instead_of_relabelling() {
        // Open the legacy envelope, then seal the recovered plaintext anew.
        let legacy = seal_legacy_v1(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        let plaintext = open(&legacy, "password", b"context").unwrap();
        let current = seal(&plaintext, "password", b"context", KdfParameters::TEST).unwrap();
        assert_ne!(current.header.salt, legacy.header.salt);
        assert_ne!(current.ciphertext, legacy.ciphertext);
        assert_eq!(
            open(&current, "password", b"context").unwrap().as_slice(),
            b"state"
        );
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretBytes::from_bytes(vec![1, 2, 3]).unwrap();
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    }
}
