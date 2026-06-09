//! Key Material message codec (spec §3.2.2, Figure 10).
//!
//! The Key Material (KM) message carries the wrapped Stream Encrypting Key(s),
//! the salt, and the cipher parameters between peers — either as a handshake
//! extension (KMREQ/KMRSP) or as a stand-alone control packet during rekeying.
//! This module is just the wire codec; the actual key derivation, wrapping, and
//! encryption live in sibling modules.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::CryptoError;

/// Fixed Key Material header length, before the salt and wrapped keys (§3.2.2).
const HEADER_LEN: usize = 16;
/// The salt length in 4-byte words (the wire `SLen/4` field value).
const SALT_WORDS: u8 = 4;
/// The only supported salt length, 128 bits (spec §3.2.2: "The only valid length
/// of salt defined is 128 bits"). `u8 as usize` is a widening, lint-free cast.
pub(crate) const SALT_LEN: usize = SALT_WORDS as usize * 4;
/// The AES key-wrap integrity check vector size, prepended to the wrapped keys.
pub(crate) const ICV_LEN: usize = 8;

/// KM version (spec §3.2.2: V = 1).
const VERSION: u8 = 1;
/// KM packet type for a Keying Material Message (spec §3.2.2: PT = 2).
const PT_KEYING_MATERIAL: u8 = 2;
/// KM signature 'HAI' as a `PnP` Vendor ID (spec §3.2.2: Sign = 0x2029).
const SIGN: u16 = 0x2029;
/// Cipher value for AES-CTR (spec §3.2.2: Cipher = 2).
const CIPHER_AES_CTR: u8 = 2;
/// Cipher value for AES-GCM (libsrt `HCRYPT_CIPHER_AES_GCM`, cross-checked vs
/// srtgo). GCM is a post-spec libsrt extension.
const CIPHER_AES_GCM: u8 = 4;
/// Stream encapsulation MPEG-TS/SRT (spec §3.2.2: SE = 2).
const SE_MPEGTS_SRT: u8 = 2;

/// The payload cipher a Key Material message negotiates (spec §3.2.2 Cipher
/// field). AES-CTR is the original; AES-GCM is libsrt's authenticated extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherMode {
    /// AES in counter mode (no authentication) — the spec default.
    #[default]
    Ctr,
    /// AES-GCM authenticated encryption (libsrt extension).
    Gcm,
}

impl CipherMode {
    /// The wire Cipher value.
    fn to_wire(self) -> u8 {
        match self {
            CipherMode::Ctr => CIPHER_AES_CTR,
            CipherMode::Gcm => CIPHER_AES_GCM,
        }
    }

    /// Parses the wire Cipher value.
    fn from_wire(cipher: u8) -> Result<Self, CryptoError> {
        match cipher {
            CIPHER_AES_CTR => Ok(CipherMode::Ctr),
            CIPHER_AES_GCM => Ok(CipherMode::Gcm),
            other => Err(CryptoError::UnsupportedCipher(other)),
        }
    }
}

/// Which Stream Encrypting Keys a Key Material message carries — the KK field
/// (spec §3.2.2). `00` (no key) is not representable: it is an invalid message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyFlags {
    /// Only the even key (`01`).
    Even,
    /// Only the odd key (`10`).
    Odd,
    /// Both even and odd keys (`11`).
    Both,
}

impl KeyFlags {
    /// The 2-bit KK wire value.
    fn to_kk(self) -> u8 {
        match self {
            KeyFlags::Even => 0b01,
            KeyFlags::Odd => 0b10,
            KeyFlags::Both => 0b11,
        }
    }

    /// Parses the 2-bit KK field.
    fn from_kk(kk: u8) -> Result<Self, CryptoError> {
        match kk {
            0b01 => Ok(KeyFlags::Even),
            0b10 => Ok(KeyFlags::Odd),
            0b11 => Ok(KeyFlags::Both),
            other => Err(CryptoError::InvalidKeyFlags(other)),
        }
    }

    /// How many keys are wrapped: 2 for [`KeyFlags::Both`], otherwise 1.
    pub(crate) fn key_count(self) -> usize {
        match self {
            KeyFlags::Both => 2,
            KeyFlags::Even | KeyFlags::Odd => 1,
        }
    }
}

/// A decoded Key Material message (spec §3.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyMaterial {
    /// Which SEK(s) the message carries.
    pub(crate) key_flags: KeyFlags,
    /// The payload cipher these keys are for (AES-CTR or AES-GCM).
    pub(crate) cipher: CipherMode,
    /// The SEK length in bytes (16, 24, or 32 — AES-128/192/256).
    pub(crate) key_length: u8,
    /// The 128-bit salt.
    pub(crate) salt: [u8; SALT_LEN],
    /// The wrapped key(s): `key_count * key_length + ICV_LEN` bytes.
    pub(crate) wrapped: Bytes,
}

impl KeyMaterial {
    /// Encodes the message into `out` (spec §3.2.2, Figure 10).
    pub(crate) fn encode(&self, out: &mut BytesMut) {
        // Word 0: S=0 | V=1 | PT=2 in the first byte, then the signature.
        out.put_u8((VERSION << 4) | PT_KEYING_MATERIAL);
        out.put_u16(SIGN);
        out.put_u8(self.key_flags.to_kk()); // Resv1=0 | KK
        out.put_u32(0); // KEKI = default stream key
        out.put_u8(self.cipher.to_wire());
        // Auth: 1 (GCM) signals AEAD, 0 for plain AES-CTR (cross-checked vs srtgo).
        out.put_u8(u8::from(matches!(self.cipher, CipherMode::Gcm)));
        out.put_u8(SE_MPEGTS_SRT);
        out.put_u8(0); // Resv2
        out.put_u16(0); // Resv3
        out.put_u8(SALT_WORDS); // SLen/4
        out.put_u8(self.key_length / 4); // KLen/4
        out.put_slice(&self.salt);
        out.put_slice(&self.wrapped);
    }

    /// Decodes a Key Material message from `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] for a short buffer or any malformed fixed field
    /// (version, packet type, signature, key flags, cipher, salt/key length).
    pub(crate) fn decode(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() < HEADER_LEN {
            return Err(CryptoError::TooShort {
                need: HEADER_LEN,
                got: buf.len(),
            });
        }
        let mut cur = buf;

        let b0 = cur.get_u8();
        let version = (b0 >> 4) & 0x07;
        let packet_type = b0 & 0x0F;
        if version != VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        if packet_type != PT_KEYING_MATERIAL {
            return Err(CryptoError::InvalidPacketType(packet_type));
        }

        let sign = cur.get_u16();
        if sign != SIGN {
            return Err(CryptoError::InvalidSignature(sign));
        }

        let key_flags = KeyFlags::from_kk(cur.get_u8() & 0b11)?;
        let _keki = cur.get_u32();
        let cipher = CipherMode::from_wire(cur.get_u8())?;
        let _auth = cur.get_u8();
        let _se = cur.get_u8();
        let _resv2 = cur.get_u8();
        let _resv3 = cur.get_u16();

        let salt_len = usize::from(cur.get_u8()) * 4;
        let key_length = usize::from(cur.get_u8()) * 4;
        if salt_len != SALT_LEN {
            return Err(CryptoError::InvalidSaltLength(salt_len));
        }
        if !matches!(key_length, 16 | 24 | 32) {
            return Err(CryptoError::InvalidKeyLength(key_length));
        }

        let wrapped_len = key_flags.key_count() * key_length + ICV_LEN;
        if cur.remaining() < SALT_LEN + wrapped_len {
            return Err(CryptoError::TooShort {
                need: HEADER_LEN + SALT_LEN + wrapped_len,
                got: buf.len(),
            });
        }
        let mut salt = [0u8; SALT_LEN];
        cur.copy_to_slice(&mut salt);
        let wrapped = cur.copy_to_bytes(wrapped_len);

        Ok(KeyMaterial {
            key_flags,
            cipher,
            // `key_length` was validated to be 16/24/32, so it fits in a `u8`.
            key_length: u8::try_from(key_length).expect("validated 16/24/32"),
            salt,
            wrapped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key_flags: KeyFlags, key_length: u8) -> KeyMaterial {
        sample_cipher(key_flags, CipherMode::Ctr, key_length)
    }

    fn sample_cipher(key_flags: KeyFlags, cipher: CipherMode, key_length: u8) -> KeyMaterial {
        let n = key_flags.key_count();
        let wrapped_len = n * usize::from(key_length) + ICV_LEN;
        KeyMaterial {
            key_flags,
            cipher,
            key_length,
            salt: [0xAB; SALT_LEN],
            wrapped: Bytes::from(vec![0xCD; wrapped_len]),
        }
    }

    #[test]
    fn round_trips_a_gcm_key() {
        round_trip(&sample_cipher(KeyFlags::Even, CipherMode::Gcm, 16));
    }

    fn round_trip(km: &KeyMaterial) {
        let mut buf = BytesMut::new();
        km.encode(&mut buf);
        assert_eq!(buf.len() % 4, 0, "KM message is word-aligned");
        assert_eq!(&KeyMaterial::decode(&buf).unwrap(), km);
    }

    #[test]
    fn round_trips_one_even_key() {
        round_trip(&sample(KeyFlags::Even, 16));
    }

    #[test]
    fn round_trips_both_keys_aes256() {
        round_trip(&sample(KeyFlags::Both, 32));
    }

    #[test]
    fn encodes_the_fixed_header_fields() {
        let mut buf = BytesMut::new();
        sample(KeyFlags::Odd, 24).encode(&mut buf);
        assert_eq!(buf[0], 0x12, "S=0, V=1, PT=2");
        assert_eq!(u16::from_be_bytes([buf[1], buf[2]]), SIGN);
        assert_eq!(buf[3] & 0b11, 0b10, "KK = odd");
        assert_eq!(buf[8], CIPHER_AES_CTR);
        assert_eq!(buf[10], SE_MPEGTS_SRT);
        assert_eq!(buf[14], SALT_WORDS, "SLen/4");
        assert_eq!(buf[15], 24 / 4, "KLen/4");
    }

    #[test]
    fn rejects_a_bad_signature() {
        let mut buf = BytesMut::new();
        sample(KeyFlags::Even, 16).encode(&mut buf);
        buf[1] = 0xFF;
        assert_eq!(
            KeyMaterial::decode(&buf),
            Err(CryptoError::InvalidSignature(0xFF29))
        );
    }

    #[test]
    fn rejects_an_invalid_key_length() {
        let mut buf = BytesMut::new();
        sample(KeyFlags::Even, 16).encode(&mut buf);
        buf[15] = 5; // 5*4 = 20, not a valid AES key length
        assert_eq!(
            KeyMaterial::decode(&buf),
            Err(CryptoError::InvalidKeyLength(20))
        );
    }

    #[test]
    fn rejects_zero_key_flags() {
        let mut buf = BytesMut::new();
        sample(KeyFlags::Even, 16).encode(&mut buf);
        buf[3] = 0; // KK = 00 (no key)
        assert_eq!(
            KeyMaterial::decode(&buf),
            Err(CryptoError::InvalidKeyFlags(0))
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_key_flags() -> impl Strategy<Value = KeyFlags> {
        prop_oneof![
            Just(KeyFlags::Even),
            Just(KeyFlags::Odd),
            Just(KeyFlags::Both),
        ]
    }

    prop_compose! {
        fn any_key_material()(
            key_flags in any_key_flags(),
            gcm in any::<bool>(),
            key_length in prop_oneof![Just(16u8), Just(24u8), Just(32u8)],
            salt in any::<[u8; SALT_LEN]>(),
            fill in any::<u8>(),
        ) -> KeyMaterial {
            let wrapped_len = key_flags.key_count() * usize::from(key_length) + ICV_LEN;
            KeyMaterial {
                key_flags,
                cipher: if gcm { CipherMode::Gcm } else { CipherMode::Ctr },
                key_length,
                salt,
                wrapped: Bytes::from(vec![fill; wrapped_len]),
            }
        }
    }

    proptest! {
        #[test]
        fn round_trips(km in any_key_material()) {
            let mut buf = BytesMut::new();
            km.encode(&mut buf);
            let decoded = KeyMaterial::decode(&buf).expect("our own encoding decodes");
            let mut reencoded = BytesMut::new();
            decoded.encode(&mut reencoded);
            prop_assert_eq!(&buf[..], &reencoded[..]);
            prop_assert_eq!(decoded, km);
        }

        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..128)) {
            let _ = KeyMaterial::decode(&bytes);
        }
    }
}
