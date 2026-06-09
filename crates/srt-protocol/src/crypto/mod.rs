//! Encryption support (spec §3.2.2, §6): Key Material messaging, key derivation,
//! key wrapping, and the AES-CTR payload cipher.
//!
//! Everything here is pure and dependency-injected per the project's rules: the
//! random Stream Encrypting Key and salt are supplied by the embedder (the core
//! never generates randomness), and all crypto primitives are pure-Rust
//! `RustCrypto` crates so `#![forbid(unsafe_code)]` holds.

pub(crate) mod cipher;
pub(crate) mod kek;
pub(crate) mod key_material;
pub(crate) mod wrap;

use bytes::Bytes;

use crate::error::CryptoError;
use crate::packet::Encryption;
pub use key_material::CipherMode;
use key_material::{KeyFlags, KeyMaterial, SALT_LEN};

/// The connection's live encryption state: the even and odd key slots and which
/// one new outgoing data packets use (spec §6.1.6). SRT rotates the Stream
/// Encrypting Key periodically, alternating the slot; a data packet's even/odd
/// flag selects the key, so the receiver must keep **both** slots and decrypt by
/// the flag — using the wrong key would silently corrupt the stream.
#[derive(Debug, Clone)]
pub(crate) struct SessionCrypto {
    even: Option<SessionKeys>,
    odd: Option<SessionKeys>,
    /// Which slot new outgoing packets are encrypted with (`Even` or `Odd`).
    active: Encryption,
}

impl SessionCrypto {
    /// A connection starting on the even key (the handshake key).
    pub(crate) fn even(keys: SessionKeys) -> Self {
        SessionCrypto {
            even: Some(keys),
            odd: None,
            active: Encryption::Even,
        }
    }

    /// A connection starting from whatever slots the peer's handshake Key
    /// Material delivered (the active slot prefers even, matching libsrt's
    /// initial key).
    pub(crate) fn from_initial(km: UnwrappedKm) -> Self {
        let active = if km.even.is_some() {
            Encryption::Even
        } else {
            Encryption::Odd
        };
        SessionCrypto {
            even: km.even,
            odd: km.odd,
            active,
        }
    }

    /// Installs every slot a Key Material message delivered. A libsrt rekey
    /// announces **both** keys; a slot the message did not carry is untouched.
    pub(crate) fn install_unwrapped(&mut self, km: UnwrappedKm) {
        if let Some(keys) = km.even {
            self.even = Some(keys);
        }
        if let Some(keys) = km.odd {
            self.odd = Some(keys);
        }
    }

    /// Installs (or replaces) the keys for one slot — used when *we* stage our
    /// own next key for a rotation (srtrust announces one key per message; a
    /// received KM, which may carry both, goes through
    /// [`install_unwrapped`](SessionCrypto::install_unwrapped)).
    pub(crate) fn install(&mut self, flags: KeyFlags, keys: SessionKeys) {
        match flags {
            KeyFlags::Odd => self.odd = Some(keys),
            KeyFlags::Even | KeyFlags::Both => self.even = Some(keys),
        }
    }

    /// The slot a rotation would switch *to* (the opposite of the active one).
    pub(crate) fn next_flags(&self) -> KeyFlags {
        match self.active {
            Encryption::Odd => KeyFlags::Even,
            _ => KeyFlags::Odd,
        }
    }

    /// The connection salt (shared by both key slots).
    pub(crate) fn salt(&self) -> Option<[u8; SALT_LEN]> {
        self.even
            .as_ref()
            .or(self.odd.as_ref())
            .map(SessionKeys::salt)
    }

    /// Switches new outgoing packets to the other slot (the rotation flip). The
    /// caller must have [`install`](SessionCrypto::install)ed that slot's key.
    pub(crate) fn activate(&mut self, flags: KeyFlags) {
        self.active = match flags {
            KeyFlags::Odd => Encryption::Odd,
            KeyFlags::Even | KeyFlags::Both => Encryption::Even,
        };
    }

    /// Encrypts an outgoing payload with the active key, returning the ciphertext
    /// and the even/odd flag to stamp on the packet.
    pub(crate) fn encrypt(&self, seq: u32, aad: &[u8], payload: &[u8]) -> (Bytes, Encryption) {
        let keys = match self.active {
            Encryption::Odd => self.odd.as_ref(),
            _ => self.even.as_ref(),
        }
        .expect("active key slot is always populated");
        (keys.encrypt(seq, aad, payload), self.active)
    }

    /// The slot new outgoing packets use, as an [`Encryption`] flag.
    pub(crate) fn active_encryption(&self) -> Encryption {
        self.active
    }

    /// Whether the active cipher is an authenticated AEAD (AES-GCM) — read by
    /// the payload-size budget (GCM appends a 16-byte tag).
    pub(crate) fn is_aead(&self) -> bool {
        let keys = match self.active {
            Encryption::Odd => self.odd.as_ref(),
            _ => self.even.as_ref(),
        };
        keys.is_some_and(SessionKeys::is_aead)
    }

    /// Decrypts a received payload using the slot its `flag` selects. Returns
    /// `None` if we hold no key for that slot (a packet from a rotation we have
    /// not yet been told about): the packet is dropped rather than decrypted with
    /// the wrong key, so loss — not corruption — is what reaches the application.
    pub(crate) fn decrypt(
        &self,
        seq: u32,
        flag: Encryption,
        aad: &[u8],
        payload: &[u8],
    ) -> Option<Bytes> {
        let keys = match flag {
            Encryption::Even => self.even.as_ref(),
            Encryption::Odd => self.odd.as_ref(),
            Encryption::None => return None,
        }?;
        // `None` here means a key we lack OR a GCM auth failure — both drop.
        keys.decrypt(seq, aad, payload)
    }
}

/// The session keys recovered from one Key Material message — one or both
/// slots, depending on the message's `KK` flags (spec §6.1).
#[derive(Debug)]
pub(crate) struct UnwrappedKm {
    pub(crate) even: Option<SessionKeys>,
    pub(crate) odd: Option<SessionKeys>,
}

/// The negotiated per-connection encryption keys (single-key / even, spec §6).
///
/// Both peers end up holding the same Stream Encrypting Key and salt: the
/// initiator generates them and wraps the SEK into a Key Material message; the
/// responder unwraps it with the KEK derived from the shared passphrase.
#[derive(Debug, Clone)]
pub(crate) struct SessionKeys {
    salt: [u8; SALT_LEN],
    sek: Vec<u8>,
    /// The cipher these keys drive (AES-CTR or AES-GCM).
    mode: CipherMode,
}

impl SessionKeys {
    /// Initiator side: generate the SEK and salt from the embedder's injected
    /// randomness, returning the keys and the [`KeyMaterial`] to advertise.
    pub(crate) fn generate(
        passphrase: &[u8],
        key_size: usize,
        mode: CipherMode,
        mut rng: impl FnMut(&mut [u8]),
    ) -> (Self, KeyMaterial) {
        let mut salt = [0u8; SALT_LEN];
        let mut sek = vec![0u8; key_size];
        rng(&mut salt);
        rng(&mut sek);
        let km = build_key_material(passphrase, mode, &salt, &sek);
        (SessionKeys { salt, sek, mode }, km)
    }

    /// Responder side: recover the key (or **keys**) from a received Key
    /// Material message and the shared passphrase.
    ///
    /// A KM may announce one slot or both (spec §6.1; the `KK` flags): libsrt
    /// wraps *both* SEKs into every rekey KM, even key first
    /// (`hcrypt_ctx_rx.c`: "First SEK in `KMmsg` is eSEK if both SEK present").
    /// The wrapped blob is `key_length` bytes per announced key; treating a
    /// two-key blob as one double-length key would corrupt both slots.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::IntegrityCheckFailed`] if the passphrase is wrong
    /// (the unwrap integrity check fails), or
    /// [`CryptoError::InvalidKeyLength`] if the unwrapped material does not
    /// match the announced slot count.
    pub(crate) fn from_key_material(
        km: &KeyMaterial,
        passphrase: &[u8],
    ) -> Result<UnwrappedKm, CryptoError> {
        let kek = kek::derive_kek(passphrase, &km.salt, usize::from(km.key_length));
        let sek = wrap::unwrap_key(&kek, &km.wrapped)?;
        let klen = usize::from(km.key_length);
        if sek.len() != klen * km.key_flags.key_count() {
            return Err(CryptoError::InvalidKeyLength(sek.len()));
        }
        let make = |bytes: &[u8]| SessionKeys {
            salt: km.salt,
            sek: bytes.to_vec(),
            // Adopt the cipher the initiator chose (CryptoModeAuto).
            mode: km.cipher,
        };
        Ok(match km.key_flags {
            KeyFlags::Even => UnwrappedKm {
                even: Some(make(&sek)),
                odd: None,
            },
            KeyFlags::Odd => UnwrappedKm {
                even: None,
                odd: Some(make(&sek)),
            },
            // Even key first in a two-key blob (libsrt `hcrypt_ctx_rx.c`).
            KeyFlags::Both => UnwrappedKm {
                even: Some(make(&sek[..klen])),
                odd: Some(make(&sek[klen..])),
            },
        })
    }

    /// This connection's salt (fixed for the connection; rekeying reuses it).
    pub(crate) fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }

    /// Whether this key drives an authenticated AEAD cipher (AES-GCM).
    pub(crate) fn is_aead(&self) -> bool {
        matches!(self.mode, CipherMode::Gcm)
    }

    /// Builds keys for a rekey from embedder-supplied SEK bytes (the core stays
    /// RNG-free: randomness arrives via [`Connection::provide_rekey`]), reusing
    /// `salt`, and returns the keys plus the [`KeyMaterial`] to announce at slot
    /// `flags`.
    pub(crate) fn from_raw(
        passphrase: &[u8],
        flags: KeyFlags,
        mode: CipherMode,
        salt: [u8; SALT_LEN],
        sek: &[u8],
    ) -> (Self, KeyMaterial) {
        let km = build_key_material_for(passphrase, flags, mode, &salt, sek);
        (
            SessionKeys {
                salt,
                sek: sek.to_vec(),
                mode,
            },
            km,
        )
    }

    /// Encrypts `plaintext` for packet `seq`. AES-CTR returns same-length
    /// ciphertext (and ignores `aad`); AES-GCM authenticates `aad` (the packet
    /// header) and appends a 16-byte tag.
    pub(crate) fn encrypt(&self, seq: u32, aad: &[u8], plaintext: &[u8]) -> Bytes {
        match self.mode {
            CipherMode::Ctr => {
                let mut buf = plaintext.to_vec();
                cipher::apply_ctr(&self.sek, &self.salt, seq, &mut buf)
                    .expect("session key length was validated at setup");
                Bytes::from(buf)
            }
            CipherMode::Gcm => Bytes::from(
                cipher::gcm_encrypt(&self.sek, &self.salt, seq, aad, plaintext)
                    .expect("session key length was validated at setup"),
            ),
        }
    }

    /// Decrypts `data` for packet `seq`. AES-CTR always succeeds (it cannot detect
    /// corruption, and ignores `aad`); AES-GCM verifies the tag against `aad` and
    /// returns `None` on a failure (tampered, corrupt, wrong key, or wrong header).
    pub(crate) fn decrypt(&self, seq: u32, aad: &[u8], data: &[u8]) -> Option<Bytes> {
        match self.mode {
            CipherMode::Ctr => {
                let mut buf = data.to_vec();
                cipher::apply_ctr(&self.sek, &self.salt, seq, &mut buf)
                    .expect("session key length was validated at setup");
                Some(Bytes::from(buf))
            }
            CipherMode::Gcm => cipher::gcm_decrypt(&self.sek, &self.salt, seq, aad, data)
                .ok()
                .map(Bytes::from),
        }
    }
}

/// Builds the Key Material message advertising a freshly-generated SEK at the
/// given slot: derive the KEK from the passphrase, wrap the SEK, and assemble it.
fn build_key_material_for(
    passphrase: &[u8],
    flags: KeyFlags,
    cipher: CipherMode,
    salt: &[u8; SALT_LEN],
    sek: &[u8],
) -> KeyMaterial {
    let kek = kek::derive_kek(passphrase, salt, sek.len());
    let wrapped = wrap::wrap_key(&kek, sek).expect("valid SEK length");
    KeyMaterial {
        key_flags: flags,
        cipher,
        key_length: u8::try_from(sek.len()).expect("SEK length is 16/24/32"),
        salt: *salt,
        wrapped: Bytes::from(wrapped),
    }
}

/// Builds the Key Material message advertising a freshly-generated SEK at the
/// even slot (the handshake key).
fn build_key_material(
    passphrase: &[u8],
    cipher: CipherMode,
    salt: &[u8; SALT_LEN],
    sek: &[u8],
) -> KeyMaterial {
    build_key_material_for(passphrase, KeyFlags::Even, cipher, salt, sek)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed AAD for the unit tests (CTR ignores it; GCM authenticates it, so
    /// the same value must be used to encrypt and decrypt).
    const AAD: &[u8] = b"test-header-aad!";

    /// Deterministic test keys: fills the SEK/salt with a seeded ramp.
    fn keys(seed: u8) -> SessionKeys {
        keys_mode(seed, CipherMode::Ctr)
    }

    fn keys_mode(seed: u8, mode: CipherMode) -> SessionKeys {
        let mut n = seed;
        SessionKeys::generate(b"passphrase", 16, mode, |b| {
            for x in b.iter_mut() {
                *x = n;
                n = n.wrapping_add(1);
            }
        })
        .0
    }

    #[test]
    fn decrypt_by_flag_round_trips_the_active_key() {
        let crypto = SessionCrypto::even(keys(1));
        let (ciphertext, flag) = crypto.encrypt(5, AAD, b"hello world");
        assert_eq!(flag, Encryption::Even);
        let plaintext = crypto
            .decrypt(5, Encryption::Even, AAD, &ciphertext)
            .unwrap();
        assert_eq!(&plaintext[..], b"hello world");
    }

    #[test]
    fn missing_key_slot_drops_instead_of_corrupting() {
        let crypto = SessionCrypto::even(keys(1)); // only the even slot is set
        // A packet flagged odd (the peer rotated, we have not installed the odd
        // key yet) must NOT be decrypted with the even key — drop it.
        assert!(
            crypto
                .decrypt(5, Encryption::Odd, AAD, b"\x00\x01\x02\x03")
                .is_none()
        );
        assert!(crypto.decrypt(5, Encryption::None, AAD, b"x").is_none());
    }

    #[test]
    fn install_then_activate_rotates_to_the_odd_key() {
        let mut crypto = SessionCrypto::even(keys(1));
        // Before install, an odd-flagged packet can't be decrypted (no odd key).
        assert!(crypto.decrypt(7, Encryption::Odd, AAD, b"xxxx").is_none());
        crypto.install(KeyFlags::Odd, keys(99));
        crypto.activate(KeyFlags::Odd);

        let (ciphertext, flag) = crypto.encrypt(7, AAD, b"after rotation");
        assert_eq!(flag, Encryption::Odd, "new packets use the odd slot");
        assert_eq!(
            &crypto
                .decrypt(7, Encryption::Odd, AAD, &ciphertext)
                .unwrap()[..],
            b"after rotation"
        );
        // The even key would produce garbage for an odd packet — never a silent match.
        let wrong = crypto
            .decrypt(7, Encryption::Even, AAD, &ciphertext)
            .unwrap();
        assert_ne!(&wrong[..], b"after rotation");
    }

    #[test]
    fn a_rekey_material_unwraps_back_to_the_new_key() {
        let salt = keys(1).salt();
        let sek = [0x5Au8; 16];
        let (new_keys, km) =
            SessionKeys::from_raw(b"passphrase", KeyFlags::Odd, CipherMode::Ctr, salt, &sek);
        assert_eq!(km.key_flags, KeyFlags::Odd);
        // The peer recovers the same SEK, in the announced (odd) slot only.
        let recovered = SessionKeys::from_key_material(&km, b"passphrase").unwrap();
        assert!(recovered.even.is_none(), "only the odd slot was announced");
        let odd = recovered.odd.expect("the announced odd key");
        let ct = new_keys.encrypt(3, AAD, b"payload");
        assert_eq!(&odd.decrypt(3, AAD, &ct).unwrap()[..], b"payload");
    }

    /// libsrt wraps **both** SEKs into every rekey Key Material message (even
    /// key first in the blob — `hcrypt_ctx_rx.c`). Treating the two-key blob as
    /// one double-length key corrupts both slots; found live against libsrt
    /// 1.5.5 (every post-rotation packet undecryptable).
    #[test]
    fn a_both_key_material_recovers_both_slots() {
        let salt = [0x33u8; SALT_LEN];
        let even_sek = [0x11u8; 16];
        let odd_sek = [0x22u8; 16];
        let kek = kek::derive_kek(b"passphrase", &salt, 16);
        let both = [even_sek, odd_sek].concat();
        let wrapped = wrap::wrap_key(&kek, &both).expect("wrap two keys");
        let km = KeyMaterial {
            key_flags: KeyFlags::Both,
            cipher: CipherMode::Ctr,
            key_length: 16,
            salt,
            wrapped: Bytes::from(wrapped),
        };

        let recovered = SessionKeys::from_key_material(&km, b"passphrase").unwrap();
        let even = recovered.even.expect("even slot present");
        let odd = recovered.odd.expect("odd slot present");

        // Each slot must hold exactly the key wrapped for it (even first).
        let reference_even = SessionKeys::from_raw(
            b"passphrase",
            KeyFlags::Even,
            CipherMode::Ctr,
            salt,
            &even_sek,
        )
        .0;
        let ct = reference_even.encrypt(7, AAD, b"even payload");
        assert_eq!(&even.decrypt(7, AAD, &ct).unwrap()[..], b"even payload");
        let reference_odd = SessionKeys::from_raw(
            b"passphrase",
            KeyFlags::Odd,
            CipherMode::Ctr,
            salt,
            &odd_sek,
        )
        .0;
        let ct = reference_odd.encrypt(9, AAD, b"odd payload");
        assert_eq!(&odd.decrypt(9, AAD, &ct).unwrap()[..], b"odd payload");
    }

    /// A wrapped blob whose length disagrees with the announced slot count is
    /// rejected, never misinterpreted.
    #[test]
    fn a_key_material_with_mismatched_length_is_rejected() {
        let salt = [0x44u8; SALT_LEN];
        let kek = kek::derive_kek(b"passphrase", &salt, 16);
        // Two keys' worth of material, but flagged as a single even key.
        let wrapped = wrap::wrap_key(&kek, &[0x55u8; 32]).expect("wrap");
        let km = KeyMaterial {
            key_flags: KeyFlags::Even,
            cipher: CipherMode::Ctr,
            key_length: 16,
            salt,
            wrapped: Bytes::from(wrapped),
        };
        assert!(SessionKeys::from_key_material(&km, b"passphrase").is_err());
    }

    #[test]
    fn gcm_round_trips_and_detects_tampering() {
        // GCM encrypt → decrypt round-trips, and a flipped byte fails the tag.
        let crypto = SessionCrypto::even(keys_mode(7, CipherMode::Gcm));
        let (ciphertext, flag) = crypto.encrypt(5, AAD, b"authenticated payload");
        assert_eq!(flag, Encryption::Even);
        assert_eq!(
            ciphertext.len(),
            b"authenticated payload".len() + 16,
            "GCM appends a 16-byte tag"
        );
        assert_eq!(
            &crypto
                .decrypt(5, Encryption::Even, AAD, &ciphertext)
                .unwrap()[..],
            b"authenticated payload"
        );
        // Tamper one byte → authentication fails → dropped (None), not corrupted.
        let mut tampered = ciphertext.to_vec();
        tampered[0] ^= 0x01;
        assert!(
            crypto
                .decrypt(5, Encryption::Even, AAD, &tampered)
                .is_none()
        );
    }
}
