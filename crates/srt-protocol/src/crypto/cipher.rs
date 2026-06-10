//! AES-CTR payload cipher and counter construction (spec §6.1.2, §6.2.2).
//!
//! SRT encrypts only the data-packet payload with AES in counter mode. The
//! 128-bit counter is built from the salt and the packet sequence number, so the
//! same counter is reproduced on the receiver from the unencrypted header — which
//! is why AES-CTR tolerates loss and allows decryption from any point.
//!
//! Counter-mode encryption is its own inverse (the keystream is XOR'd in), so
//! [`apply_ctr`] both encrypts and decrypts.
//!
//! Counter layout (cross-checked against `srtgo`, v1.5.4+):
//!
//! ```text
//! ctr[0..10]  = salt[0..10]
//! ctr[10..14] = salt[10..14] XOR PktSeqNo (big-endian)
//! ctr[14..16] = 0            (block counter within the packet)
//! ```

use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{AesGcm, Nonce};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::error::CryptoError;

/// AES-GCM over AES-192 with the standard 96-bit nonce (the one key size the
/// `aes-gcm` crate lacks a ready-made alias for).
type Aes192Gcm = AesGcm<Aes192, <aes_gcm::Aes128Gcm as AeadCore>::NonceSize>;

/// Builds the 96-bit AES-GCM nonce for a packet (cross-checked against `srtgo`'s
/// `buildGCMNonce`, libsrt v1.5.4 format): the sequence number, big-endian, in the
/// low 4 bytes, the whole thing `XOR`ed with the first 12 salt bytes.
///
/// ```text
/// nonce[0..8]  = salt[0..8]
/// nonce[8..12] = salt[8..12] XOR PktSeqNo (big-endian)
/// ```
fn gcm_nonce(salt: &[u8; 16], seq: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[8..12].copy_from_slice(&seq.to_be_bytes());
    for (slot, salt_byte) in nonce.iter_mut().zip(&salt[..12]) {
        *slot ^= salt_byte;
    }
    nonce
}

/// Encrypts `plaintext` with AES-GCM, authenticating `aad` (the packet header,
/// matching libsrt), and returns ciphertext with the 16-byte tag appended.
///
/// The nonce matches libsrt v1.5.4 (`salt[0..12]` XOR sequence). Because the AAD
/// is the header — which carries a fresh timestamp and the retransmit flag on a
/// resend — GCM packets must be (re-)encrypted per send, not stored as ciphertext.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if `sek` is not 16, 24, or 32 bytes.
pub(crate) fn gcm_encrypt(
    sek: &[u8],
    salt: &[u8; 16],
    seq: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = gcm_nonce(salt, seq);
    let nonce = Nonce::<<aes_gcm::Aes128Gcm as AeadCore>::NonceSize>::from_slice(&nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let result = match sek.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(sek)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .encrypt(nonce, payload),
        24 => Aes192Gcm::new_from_slice(sek)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .encrypt(nonce, payload),
        32 => aes_gcm::Aes256Gcm::new_from_slice(sek)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .encrypt(nonce, payload),
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    result.map_err(|_| CryptoError::AuthFailed)
}

/// Decrypts AES-GCM `data` (ciphertext with the trailing 16-byte tag), verifying
/// authenticity against `aad` (the packet header). Returns the plaintext, or
/// [`CryptoError::AuthFailed`] if the tag does not verify.
///
/// # Errors
///
/// [`CryptoError::InvalidKeyLength`] for a bad key size; [`CryptoError::AuthFailed`]
/// if authentication fails.
pub(crate) fn gcm_decrypt(
    sek: &[u8],
    salt: &[u8; 16],
    seq: u32,
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = gcm_nonce(salt, seq);
    let nonce = Nonce::<<aes_gcm::Aes128Gcm as AeadCore>::NonceSize>::from_slice(&nonce);
    let payload = Payload { msg: data, aad };
    let result = match sek.len() {
        16 => aes_gcm::Aes128Gcm::new_from_slice(sek)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .decrypt(nonce, payload),
        24 => Aes192Gcm::new_from_slice(sek)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .decrypt(nonce, payload),
        32 => aes_gcm::Aes256Gcm::new_from_slice(sek)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .decrypt(nonce, payload),
        n => return Err(CryptoError::InvalidKeyLength(n)),
    };
    result.map_err(|_| CryptoError::AuthFailed)
}

/// Builds the 128-bit AES-CTR counter for a packet with sequence number `seq`
/// (spec §6.1.2): the most-significant 112 bits of the salt, with the sequence
/// number mixed (by XOR) into the four bytes above the 16-bit block counter.
fn counter_block(salt: &[u8; 16], seq: u32) -> [u8; 16] {
    let mut ctr = [0u8; 16];
    // The MSB 112 bits of the salt; the low 16 bits stay zero (the block counter).
    ctr[..14].copy_from_slice(&salt[..14]);
    // XOR the 32-bit sequence number into the four bytes above the block counter.
    for (slot, seq_byte) in ctr[10..14].iter_mut().zip(seq.to_be_bytes()) {
        *slot ^= seq_byte;
    }
    ctr
}

/// Encrypts or decrypts `data` in place with AES-CTR under key `sek` (16/24/32
/// bytes), salt, and packet sequence number `seq`. Because CTR is its own
/// inverse, the same call decrypts what it encrypted.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if `sek` is not 16, 24, or 32 bytes.
pub(crate) fn apply_ctr(
    sek: &[u8],
    salt: &[u8; 16],
    seq: u32,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let iv = counter_block(salt, seq);
    match sek.len() {
        16 => Ctr128BE::<Aes128>::new_from_slices(sek, &iv)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .apply_keystream(data),
        24 => Ctr128BE::<Aes192>::new_from_slices(sek, &iv)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .apply_keystream(data),
        32 => Ctr128BE::<Aes256>::new_from_slices(sek, &iv)
            .map_err(|_| CryptoError::InvalidKeyLength(sek.len()))?
            .apply_keystream(data),
        n => return Err(CryptoError::InvalidKeyLength(n)),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_aes128_ctr_vector() {
        // NIST SP 800-38A F.5.1 CTR-AES128 first block — proves we drive the
        // ctr+aes dependencies correctly (raw cipher, bypassing counter_block).
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
            0xfe, 0xff,
        ];
        let mut block: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected: [u8; 16] = [
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d,
            0xb6, 0xce,
        ];
        let mut cipher = Ctr128BE::<Aes128>::new_from_slices(&key, &iv).unwrap();
        cipher.apply_keystream(&mut block);
        assert_eq!(block, expected);
    }

    #[test]
    fn counter_block_layout() {
        let salt: [u8; 16] = core::array::from_fn(|i| u8::try_from(i + 1).unwrap()); // 1..=16
        let ctr = counter_block(&salt, 0x1234_5678);
        let mut expected = salt;
        // Sequence number XORed into bytes 10..14 (big-endian); the rest is salt
        // except the final two block-counter bytes, which are zeroed.
        expected[10] ^= 0x12;
        expected[11] ^= 0x34;
        expected[12] ^= 0x56;
        expected[13] ^= 0x78;
        expected[14] = 0;
        expected[15] = 0;
        assert_eq!(ctr, expected);
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_each_key_size() {
        let salt = [0xA5u8; 16];
        for klen in [16usize, 24, 32] {
            let sek = vec![0x3Cu8; klen];
            let plain = b"the quick brown fox jumps".to_vec();
            let mut buf = plain.clone();
            apply_ctr(&sek, &salt, 42, &mut buf).unwrap();
            assert_ne!(buf, plain, "payload is actually encrypted");
            apply_ctr(&sek, &salt, 42, &mut buf).unwrap();
            assert_eq!(buf, plain, "CTR is its own inverse");
        }
    }

    #[test]
    fn different_sequence_numbers_produce_different_ciphertext() {
        let sek = [0x11u8; 16];
        let salt = [0x22u8; 16];
        let plain = [0u8; 32];
        let mut a = plain;
        let mut b = plain;
        apply_ctr(&sek, &salt, 1, &mut a).unwrap();
        apply_ctr(&sek, &salt, 2, &mut b).unwrap();
        assert_ne!(a, b, "the counter changes with the sequence number");
    }

    #[test]
    fn rejects_an_invalid_key_length() {
        assert_eq!(
            apply_ctr(&[0u8; 20], &[0u8; 16], 0, &mut [0u8; 8]),
            Err(CryptoError::InvalidKeyLength(20))
        );
    }
}

#[cfg(test)]
mod speed_probe {
    use super::*;

    /// Raw cipher throughput probe; ignored in normal runs (the software
    /// fallback makes it crawl in debug builds). Run with:
    /// `cargo test --release -p srt-protocol cipher_throughput_probe -- --ignored --nocapture`
    #[test]
    #[ignore = "throughput probe; run explicitly with --release"]
    fn cipher_throughput_probe() {
        let key = [0x11u8; 16];
        let salt = [0x22u8; 16];
        let payload = vec![0xABu8; 1316];
        let n = 100_000u32;

        let start = std::time::Instant::now();
        let mut buf = payload.clone();
        for seq in 0..n {
            buf.copy_from_slice(&payload);
            apply_ctr(&key, &salt, seq, &mut buf).unwrap();
        }
        let e = start.elapsed().as_secs_f64();
        eprintln!(
            "CTR encrypt: {:.0} Mbps ({:.1} us/pkt)",
            f64::from(n) * 1316.0 * 8.0 / 1e6 / e,
            e * 1e6 / f64::from(n)
        );

        let aad = [0x33u8; 16];
        let start = std::time::Instant::now();
        for seq in 0..n {
            let _ = gcm_encrypt(&key, &salt, seq, &aad, &payload).unwrap();
        }
        let e = start.elapsed().as_secs_f64();
        eprintln!(
            "GCM encrypt: {:.0} Mbps ({:.1} us/pkt)",
            f64::from(n) * 1316.0 * 8.0 / 1e6 / e,
            e * 1e6 / f64::from(n)
        );
    }
}
