//! Key Encrypting Key (KEK) derivation (spec §6.1.4, §6.2.1).
//!
//! The KEK is derived from the shared passphrase with PBKDF2-HMAC-SHA1, using the
//! low 64 bits of the Key Material salt and 2048 iterations:
//!
//! ```text
//! KEK = PBKDF2(passphrase, LSB(64, Salt), Iter = 2048, KLen)
//! ```
//!
//! Both peers compute the same KEK from the same passphrase; the responder learns
//! `KLen` from the initiator's Key Material message. Cross-checked against
//! `srtgo` (`calculateKEK`: `salt[8:]`, 2048 rounds, HMAC-SHA1).

use sha1::Sha1;

/// PBKDF2 iteration count (spec §6.1.4: 2048).
const ITERATIONS: u32 = 2048;

/// Derives the KEK from `passphrase` and the 128-bit `salt`, producing
/// `key_length` bytes (16, 24, or 32). Uses only the low 64 bits of the salt
/// (`salt[8..16]`), per the spec's `LSB(64, Salt)`.
pub(crate) fn derive_kek(passphrase: &[u8], salt: &[u8; 16], key_length: usize) -> Vec<u8> {
    let mut kek = vec![0u8; key_length];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase, &salt[8..], ITERATIONS, &mut kek);
    kek
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_primitive_matches_rfc6070() {
        // RFC 6070 PBKDF2-HMAC-SHA1 test vector (P="password", S="salt", c=1,
        // dkLen=20) — confirms we drive the dependency correctly.
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            [
                0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
                0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
            ]
        );
    }

    #[test]
    fn produces_the_requested_key_length() {
        let salt = [0x11u8; 16];
        for klen in [16usize, 24, 32] {
            assert_eq!(derive_kek(b"secret", &salt, klen).len(), klen);
        }
    }

    #[test]
    fn is_deterministic() {
        let salt = [0x22u8; 16];
        assert_eq!(
            derive_kek(b"secret", &salt, 16),
            derive_kek(b"secret", &salt, 16)
        );
    }

    #[test]
    fn depends_only_on_the_low_64_bits_of_salt() {
        let mut salt_a = [0u8; 16];
        let mut salt_b = [0u8; 16];
        // Differ only in the high 8 bytes (salt[0..8]) — the KDF ignores them.
        salt_a[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        salt_b[0..8].copy_from_slice(&[9, 9, 9, 9, 9, 9, 9, 9]);
        assert_eq!(
            derive_kek(b"pass", &salt_a, 16),
            derive_kek(b"pass", &salt_b, 16),
            "high salt bytes must not affect the KEK"
        );
        // Differ in the low 8 bytes (salt[8..16]) — the KDF uses them.
        salt_b = salt_a;
        salt_b[8] ^= 0xFF;
        assert_ne!(
            derive_kek(b"pass", &salt_a, 16),
            derive_kek(b"pass", &salt_b, 16),
            "low salt bytes must change the KEK"
        );
    }

    #[test]
    fn different_passphrases_yield_different_keks() {
        let salt = [0x33u8; 16];
        assert_ne!(
            derive_kek(b"alice", &salt, 16),
            derive_kek(b"bob", &salt, 16)
        );
    }
}
