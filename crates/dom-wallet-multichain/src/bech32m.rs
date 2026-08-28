//! Minimal bech32m encoder (BIP-350), sufficient for taproot addresses.
//!
//! Encoding only: the wallet renders its own receive addresses; it never
//! parses foreign ones here. Pinned to the BIP-350 published test vectors.

/// Bech32 character set.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32m final constant (BIP-350).
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*value);
        for (i, generator) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hrp.len() * 2 + 1);
    for c in hrp.bytes() {
        out.push(c >> 5);
    }
    out.push(0);
    for c in hrp.bytes() {
        out.push(c & 0x1f);
    }
    out
}

/// Convert 8-bit bytes into 5-bit groups, padding the tail (BIP-173 rules).
fn to_five_bit(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len() * 8 / 5 + 1);
    for byte in data {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 0x1f) as u8);
    }
    out
}

/// Encode a segwit-v1 (taproot) program as a bech32m address.
pub(crate) fn encode_segwit_v1(hrp: &str, program: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(1 + 52);
    data.push(1u8); // witness version 1
    data.extend(to_five_bit(program));

    let mut values = hrp_expand(hrp);
    values.extend(&data);
    values.extend([0u8; 6]);
    let checksum = polymod(&values) ^ BECH32M_CONST;

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for value in &data {
        out.push(char::from(CHARSET[usize::from(*value)]));
    }
    for i in 0..6 {
        let idx = ((checksum >> (5 * (5 - i))) & 0x1f) as usize;
        out.push(char::from(CHARSET[idx]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-350 test vector: the segwit v1 program of 32 one-filled... no —
    /// use the published address vector for witness v1 with a known program.
    /// From BIP-350: `bc1p...` for program 000...0 is not listed; the listed
    /// valid checksummed string with hrp `bc`, version 1 and a 32-byte
    /// program is exercised through the BIP-86 address vectors in
    /// `bitcoin.rs`, which pin the full pipeline. Here we pin the checksum
    /// algebra itself with the BIP-350 example `abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx`.
    #[test]
    fn bech32m_checksum_matches_the_bip350_example() {
        // "abcdef", data = [31,30,...,0] (32 values), bech32m.
        let hrp = "abcdef";
        let data: Vec<u8> = (0..32).rev().collect();
        let mut values = hrp_expand(hrp);
        values.extend(&data);
        values.extend([0u8; 6]);
        let checksum = polymod(&values) ^ BECH32M_CONST;
        let mut out = String::new();
        out.push_str(hrp);
        out.push('1');
        for value in &data {
            out.push(char::from(CHARSET[usize::from(*value)]));
        }
        for i in 0..6 {
            let idx = ((checksum >> (5 * (5 - i))) & 0x1f) as usize;
            out.push(char::from(CHARSET[idx]));
        }
        assert_eq!(out, "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx");
    }
}
