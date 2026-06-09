//! AES Key Wrap (RFC 3394) for protecting the Stream Encrypting Key (spec
//! §6.1.5, §6.2.1).
//!
//! The initiator wraps the SEK with the KEK and puts the result in the Key
//! Material message; the responder unwraps it with its own KEK. The wrap carries
//! a 64-bit Integrity Check Vector, so unwrapping with the wrong KEK (i.e. a
//! wrong passphrase) fails the integrity check rather than silently producing
//! garbage — this is how a peer learns the passphrase did not match.

use aes::{Aes128, Aes192, Aes256};
use aes_kw::Kek;

use crate::error::CryptoError;

/// Bytes the wrap adds over the plaintext key (the RFC 3394 ICV).
pub(crate) const WRAP_OVERHEAD: usize = 8;

/// Wraps `sek` (16/24/32 bytes) with `kek` (matching AES key size), returning
/// `sek.len() + WRAP_OVERHEAD` bytes.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if `kek` is not a valid AES key
/// size or `sek` is not a multiple of 8 bytes.
pub(crate) fn wrap_key(kek: &[u8], sek: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; sek.len() + WRAP_OVERHEAD];
    let ok = match kek.len() {
        16 => Kek::<Aes128>::try_from(kek)
            .ok()
            .and_then(|k| k.wrap(sek, &mut out).ok()),
        24 => Kek::<Aes192>::try_from(kek)
            .ok()
            .and_then(|k| k.wrap(sek, &mut out).ok()),
        32 => Kek::<Aes256>::try_from(kek)
            .ok()
            .and_then(|k| k.wrap(sek, &mut out).ok()),
        _ => None,
    };
    ok.map(|()| out)
        .ok_or(CryptoError::InvalidKeyLength(kek.len()))
}

/// Unwraps a `wrapped` key with `kek`, validating the integrity check vector.
///
/// # Errors
///
/// Returns [`CryptoError::IntegrityCheckFailed`] if the ICV does not validate —
/// the KEK (passphrase) is wrong — or the inputs are malformed.
pub(crate) fn unwrap_key(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let out_len = wrapped
        .len()
        .checked_sub(WRAP_OVERHEAD)
        .ok_or(CryptoError::IntegrityCheckFailed)?;
    let mut out = vec![0u8; out_len];
    let ok = match kek.len() {
        16 => Kek::<Aes128>::try_from(kek)
            .ok()
            .and_then(|k| k.unwrap(wrapped, &mut out).ok()),
        24 => Kek::<Aes192>::try_from(kek)
            .ok()
            .and_then(|k| k.unwrap(wrapped, &mut out).ok()),
        32 => Kek::<Aes256>::try_from(kek)
            .ok()
            .and_then(|k| k.unwrap(wrapped, &mut out).ok()),
        _ => None,
    };
    // A failed unwrap means the ICV did not validate: the KEK (passphrase) is
    // wrong, or the wrap was malformed/tampered.
    ok.map(|()| out).ok_or(CryptoError::IntegrityCheckFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc3394_128bit_vector() {
        // RFC 3394 §4.1: wrap 128-bit key data with a 128-bit KEK.
        let kek: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let key_data: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected: [u8; 24] = [
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        assert_eq!(wrap_key(&kek, &key_data).unwrap(), expected);
        assert_eq!(unwrap_key(&kek, &expected).unwrap(), key_data);
    }

    #[test]
    fn round_trips_each_key_size() {
        for klen in [16usize, 24, 32] {
            let kek = vec![0x42u8; klen];
            let sek = vec![0x37u8; klen];
            let wrapped = wrap_key(&kek, &sek).unwrap();
            assert_eq!(wrapped.len(), klen + WRAP_OVERHEAD);
            assert_eq!(unwrap_key(&kek, &wrapped).unwrap(), sek);
        }
    }

    #[test]
    fn wrong_kek_fails_the_integrity_check() {
        let sek = [0x37u8; 16];
        let wrapped = wrap_key(&[0x42u8; 16], &sek).unwrap();
        let mut wrong_kek = [0x42u8; 16];
        wrong_kek[0] ^= 0x01;
        assert_eq!(
            unwrap_key(&wrong_kek, &wrapped),
            Err(CryptoError::IntegrityCheckFailed)
        );
    }

    #[test]
    fn tampered_wrap_fails_the_integrity_check() {
        let wrapped = wrap_key(&[0x42u8; 16], &[0x37u8; 16]).unwrap();
        let mut tampered = wrapped.clone();
        tampered[10] ^= 0x80;
        assert_eq!(
            unwrap_key(&[0x42u8; 16], &tampered),
            Err(CryptoError::IntegrityCheckFailed)
        );
    }
}
