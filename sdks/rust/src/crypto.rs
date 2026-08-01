//! HSM Crypto Utilities

use crate::error::{HsmError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

/// Encode bytes to base64.
pub fn to_base64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Decode base64 to bytes.
pub fn from_base64(data: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(data)
        .map_err(|e| HsmError::crypto(format!("Invalid base64: {}", e)))
}

/// Check if string is valid base64.
pub fn is_base64(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if !s.len().is_multiple_of(4) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Encode bytes to hex.
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hex to bytes.
pub fn from_hex(data: &str) -> Result<Vec<u8>> {
    let data = data.strip_prefix("0x").unwrap_or(data);
    hex::decode(data).map_err(|e| HsmError::crypto(format!("Invalid hex: {}", e)))
}

/// Normalize data to base64 for API requests.
pub fn normalize_to_base64(data: &[u8]) -> String {
    to_base64(data)
}

/// Normalize string to base64.
pub fn normalize_string_to_base64(data: &str) -> String {
    if is_base64(data) {
        data.to_string()
    } else {
        to_base64(data.as_bytes())
    }
}

/// Hash data using SHA-256.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-384.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-512.
pub fn sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Compute HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Compare two byte slices in constant time.
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate cryptographically secure random bytes.
///
/// Bytes come from the operating system CSPRNG (`getrandom(2)` / `getentropy(2)` /
/// `BCryptGenRandom`), matching the Go (`crypto/rand`), Python (`os.urandom`) and
/// TypeScript (`crypto.getRandomValues`) SDKs.
///
/// # Panics
///
/// Panics if the operating system entropy source is unavailable. On the platforms
/// this SDK targets that is not a recoverable condition, so it is surfaced as a
/// panic rather than silently degrading to predictable output.
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; n];
    getrandom::fill(&mut bytes).expect("OS entropy source unavailable");
    bytes
}

/// Concatenate multiple byte slices.
pub fn concat_bytes(slices: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// Byte width of one ECDSA signature component (R or S) for each NIST curve the
/// HSM can produce signatures on: P-256 (32), P-384 (48), P-521 (66).
const ECDSA_COMPONENT_WIDTHS: [usize; 3] = [32, 48, 66];

/// Pick the fixed-width encoding that a component of `len` bytes belongs to.
fn ecdsa_component_width(len: usize) -> Result<usize> {
    ECDSA_COMPONENT_WIDTHS
        .into_iter()
        .find(|w| *w >= len)
        .ok_or_else(|| {
            HsmError::crypto(format!(
                "Invalid ECDSA signature: component of {} bytes exceeds the largest supported curve (P-521)",
                len
            ))
        })
}

/// Read a BER/DER length at `offset`, returning `(length, offset_after_length)`.
fn read_der_length(bytes: &[u8], offset: usize) -> Result<(usize, usize)> {
    let first = *bytes
        .get(offset)
        .ok_or_else(|| HsmError::crypto("Invalid DER signature: truncated length"))?;

    if first < 0x80 {
        return Ok((first as usize, offset + 1));
    }

    // Long form: low 7 bits give the number of subsequent length bytes.
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 2 {
        // n == 0 is the indefinite form (not valid in DER); n > 2 would describe a
        // signature of at least 64 KiB, which no supported curve produces.
        return Err(HsmError::crypto(
            "Invalid DER signature: unsupported length encoding",
        ));
    }
    let end = offset + 1 + n;
    let raw = bytes
        .get(offset + 1..end)
        .ok_or_else(|| HsmError::crypto("Invalid DER signature: truncated length"))?;
    let len = raw.iter().fold(0usize, |acc, b| (acc << 8) | (*b as usize));
    Ok((len, end))
}

/// Read a DER INTEGER at `*offset`, advancing it past the element and returning
/// the magnitude with any leading zero padding removed.
fn read_der_integer(bytes: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if bytes.get(*offset) != Some(&0x02) {
        return Err(HsmError::crypto(
            "Invalid DER signature: expected INTEGER tag",
        ));
    }
    let (len, value_start) = read_der_length(bytes, *offset + 1)?;
    let value = bytes
        .get(value_start..value_start + len)
        .ok_or_else(|| HsmError::crypto("Invalid DER signature: truncated INTEGER"))?;
    if value.is_empty() {
        return Err(HsmError::crypto("Invalid DER signature: empty INTEGER"));
    }
    if value[0] & 0x80 != 0 {
        return Err(HsmError::crypto(
            "Invalid DER signature: negative INTEGER component",
        ));
    }
    *offset = value_start + len;

    // Strip the leading zero padding DER adds to keep the value non-negative.
    let magnitude = value.iter().position(|b| *b != 0x00).unwrap_or(len - 1);
    Ok(value[magnitude..].to_vec())
}

/// Encode a component magnitude as a DER INTEGER element (tag + length + value).
fn write_der_integer(component: &[u8], out: &mut Vec<u8>) {
    let start = component
        .iter()
        .position(|b| *b != 0x00)
        .unwrap_or(component.len().saturating_sub(1));
    let magnitude = &component[start..];

    out.push(0x02);
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        // High bit set: prepend 0x00 so the INTEGER stays positive.
        out.push(magnitude.len() as u8 + 1);
        out.push(0x00);
    } else {
        out.push(magnitude.len() as u8);
    }
    out.extend_from_slice(magnitude);
}

/// Convert an ECDSA signature from DER (`SEQUENCE { INTEGER r, INTEGER s }`) to
/// raw fixed-width `R || S`.
///
/// The component width is inferred from the larger of the two components and is
/// one of 32 (P-256), 48 (P-384) or 66 (P-521) bytes. Input that does not begin
/// with a SEQUENCE tag is assumed to already be raw and is returned unchanged.
///
/// Malformed input yields [`HsmError::Crypto`]; it never panics.
pub fn der_to_raw(der_signature: &[u8]) -> Result<Vec<u8>> {
    if der_signature.is_empty() || der_signature[0] != 0x30 {
        // Already in raw format, or not DER at all.
        return Ok(der_signature.to_vec());
    }

    let (seq_len, mut offset) = read_der_length(der_signature, 1)?;
    let seq_end = offset
        .checked_add(seq_len)
        .ok_or_else(|| HsmError::crypto("Invalid DER signature: length overflow"))?;
    if seq_end != der_signature.len() {
        return Err(HsmError::crypto(
            "Invalid DER signature: SEQUENCE length does not match input",
        ));
    }

    let r = read_der_integer(der_signature, &mut offset)?;
    let s = read_der_integer(der_signature, &mut offset)?;
    if offset != seq_end {
        return Err(HsmError::crypto(
            "Invalid DER signature: trailing data after S",
        ));
    }

    let width = ecdsa_component_width(r.len().max(s.len()))?;
    let mut result = vec![0u8; width * 2];
    result[width - r.len()..width].copy_from_slice(&r);
    result[width * 2 - s.len()..].copy_from_slice(&s);
    Ok(result)
}

/// Convert an ECDSA signature from raw fixed-width `R || S` to DER.
///
/// Recognises the raw widths of P-256 (64 bytes), P-384 (96) and P-521 (132).
/// Anything else is assumed to already be DER and is returned unchanged.
pub fn raw_to_der(raw_signature: &[u8]) -> Result<Vec<u8>> {
    let half = raw_signature.len() / 2;
    if !raw_signature.len().is_multiple_of(2) || !ECDSA_COMPONENT_WIDTHS.contains(&half) {
        // Might already be DER, or a signature scheme without an R/S pair.
        return Ok(raw_signature.to_vec());
    }

    let mut content = Vec::with_capacity(raw_signature.len() + 8);
    write_der_integer(&raw_signature[..half], &mut content);
    write_der_integer(&raw_signature[half..], &mut content);

    let mut result = Vec::with_capacity(content.len() + 4);
    result.push(0x30);
    if content.len() < 0x80 {
        result.push(content.len() as u8);
    } else {
        // P-521 signatures exceed 127 content bytes and need the long form.
        result.push(0x81);
        result.push(content.len() as u8);
    }
    result.extend_from_slice(&content);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_base64() {
        assert_eq!(to_base64(b"Hello"), "SGVsbG8=");
    }

    #[test]
    fn test_from_base64() {
        assert_eq!(from_base64("SGVsbG8=").unwrap(), b"Hello");
    }

    #[test]
    fn test_is_base64() {
        assert!(is_base64("SGVsbG8="));
        assert!(is_base64(""));
        assert!(!is_base64("Hello"));
    }

    #[test]
    fn test_sha256() {
        let hash = sha256(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_constant_time_equal() {
        assert!(constant_time_equal(b"test", b"test"));
        assert!(!constant_time_equal(b"test", b"test2"));
    }

    #[test]
    fn random_bytes_are_not_clock_derived() {
        // The previous implementation derived every byte from the wall clock, so
        // two back-to-back calls produced near-identical output and most byte
        // values never appeared at all.
        let a = random_bytes(64);
        let b = random_bytes(64);
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);

        // Over 4 KiB from a real CSPRNG, essentially every byte value shows up.
        let bulk = random_bytes(4096);
        let distinct = bulk.iter().collect::<std::collections::HashSet<_>>().len();
        assert!(distinct > 200, "only {} distinct byte values", distinct);

        assert!(random_bytes(0).is_empty());
    }

    /// A P-256 sized (R, S) pair in which *both* components have their high bit
    /// set, so canonical DER must prefix each INTEGER with a 0x00 pad byte.
    const P256_R: [u8; 32] = [
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81,
        0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF,
        0x37, 0x16,
    ];
    const P256_S: [u8; 32] = [
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F,
        0x65, 0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06, 0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A,
        0xCD, 0xA8,
    ];

    #[test]
    fn raw_to_der_p256_matches_expected_encoding() {
        let raw = concat_bytes(&[&P256_R, &P256_S]);
        let der = raw_to_der(&raw).unwrap();

        // SEQUENCE(0x30) len=0x46 { INTEGER len=0x21 00||R, INTEGER len=0x21 00||S }
        // Structure independently confirmed with `openssl asn1parse`.
        assert_eq!(der.len(), 0x48);
        assert_eq!(&der[..5], &[0x30, 0x46, 0x02, 0x21, 0x00]);
        assert_eq!(&der[5..37], &P256_R);
        assert_eq!(&der[37..40], &[0x02, 0x21, 0x00]);
        assert_eq!(&der[40..], &P256_S);

        assert_eq!(der_to_raw(&der).unwrap(), raw);
    }

    #[test]
    fn der_raw_round_trip_for_every_supported_curve() {
        for width in [32usize, 48, 66] {
            // R starts high-bit-set (forces a DER pad byte), S starts below 0x80.
            // No component byte is zero, so no magnitude is shortened by stripping.
            let mut raw: Vec<u8> = (0..width * 2).map(|i| (i % 251 + 1) as u8).collect();
            raw[0] = 0xF1;
            raw[width] = 0x01;

            let der = raw_to_der(&raw).unwrap();
            assert_eq!(der[0], 0x30, "width {} is not a SEQUENCE", width);
            assert_eq!(
                der_to_raw(&der).unwrap(),
                raw,
                "round trip failed for {}-byte components",
                width
            );
        }
    }

    #[test]
    fn raw_to_der_uses_long_form_length_for_p521() {
        // P-521 content is 2 + 66 + 2 + 66 = 136 bytes, past the 127-byte short form.
        let raw = vec![0x7Fu8; 132];
        let der = raw_to_der(&raw).unwrap();
        assert_eq!(&der[..3], &[0x30, 0x81, 0x88]);
        assert_eq!(der.len(), 3 + 0x88);
        assert_eq!(der_to_raw(&der).unwrap(), raw);
    }

    #[test]
    fn der_to_raw_left_pads_short_components() {
        // R = 0x01 (1 byte), S = 0x02 (1 byte) must widen to 32 bytes each.
        let der = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let raw = der_to_raw(&der).unwrap();
        assert_eq!(raw.len(), 64);
        assert_eq!(raw[31], 0x01);
        assert_eq!(raw[63], 0x02);
        assert!(raw[..31].iter().all(|b| *b == 0));
        assert!(raw[32..63].iter().all(|b| *b == 0));
    }

    #[test]
    fn der_to_raw_rejects_malformed_input_without_panicking() {
        let cases: &[(&str, &[u8])] = &[
            ("truncated sequence", &[0x30]),
            ("truncated R length", &[0x30, 0x04, 0x02]),
            ("R runs past the buffer", &[0x30, 0x24, 0x02, 0x21, 0x00]),
            ("missing S", &[0x30, 0x03, 0x02, 0x01, 0x01]),
            (
                "trailing data after S",
                &[0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0xFF],
            ),
            ("indefinite length", &[0x30, 0x80, 0x02, 0x01, 0x01]),
            (
                "negative R",
                &[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01],
            ),
        ];
        for (name, input) in cases {
            assert!(
                der_to_raw(input).is_err(),
                "{} should be rejected, got {:?}",
                name,
                der_to_raw(input)
            );
        }
    }

    #[test]
    fn der_to_raw_rejects_components_wider_than_any_supported_curve() {
        // A 67-byte R exceeds P-521; the old code computed `32 - 67` and panicked.
        let mut der = vec![0x30, 0x47, 0x02, 0x43];
        der.extend(std::iter::repeat_n(0x11u8, 67));
        der.extend([0x02, 0x01, 0x01]);
        der[1] = (der.len() - 2) as u8;
        assert!(der_to_raw(&der).is_err());
    }

    #[test]
    fn non_der_and_non_raw_inputs_pass_through() {
        assert_eq!(der_to_raw(&[]).unwrap(), Vec::<u8>::new());
        // Ed25519 raw signature: 64 bytes, no leading 0x30 -> unchanged by der_to_raw.
        let ed = vec![0xAAu8; 64];
        assert_eq!(der_to_raw(&ed).unwrap(), ed);
        // Odd length is neither raw R||S nor something we re-encode.
        let odd = vec![0xAAu8; 65];
        assert_eq!(raw_to_der(&odd).unwrap(), odd);
    }

    #[test]
    fn normalize_string_to_base64_passes_through_base64() {
        assert_eq!(normalize_string_to_base64("SGVsbG8="), "SGVsbG8=");
        assert_eq!(normalize_string_to_base64("Hello"), "SGVsbG8=");
    }
}
