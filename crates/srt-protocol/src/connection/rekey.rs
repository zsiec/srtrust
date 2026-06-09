//! Stream Encrypting Key rotation (spec §6.1.6).
//!
//! A long-lived encrypted stream periodically rotates its SEK so no single key
//! ever protects too much data. The core drives the schedule — counting packets,
//! pre-announcing the next key, and switching at the refresh point — but never
//! generates the key bytes: it raises [`Event::KeyRefreshNeeded`] and the embedder
//! supplies fresh randomness via [`Connection::provide_rekey`], keeping the state
//! machine deterministic.
//!
//! A child module of `connection`, reaching the private connection state via
//! `self` (like `connection::arq` and `connection::setup`).

use std::time::Instant;

use bytes::{Bytes, BytesMut};

use super::{Connection, EXT_KMREQ, EXT_KMRSP, Event, KM_REFRESH_DEFAULT, encode_control};
use crate::control::{ControlBody, ControlType};
use crate::crypto::SessionKeys;
use crate::crypto::key_material::KeyMaterial;

impl Connection {
    /// Packets sent under one key before rotating (resolved default).
    fn km_refresh(&self) -> u32 {
        if self.config.km_refresh_rate == 0 {
            KM_REFRESH_DEFAULT
        } else {
            self.config.km_refresh_rate
        }
    }

    /// How far ahead of the refresh point the next key is announced, so the peer
    /// installs it before the switch (a quarter of the refresh window).
    fn km_preannounce(&self) -> u32 {
        (self.km_refresh() / 4).max(1)
    }

    /// Accounts one encrypted data send and drives rotation: switch to the
    /// freshly-installed key at the refresh point, and pre-announce the next key
    /// (via [`Event::KeyRefreshNeeded`]) a quarter-window earlier.
    pub(super) fn account_key_and_maybe_rotate(&mut self) {
        if self.crypto.is_none() {
            return;
        }
        let refresh = self.km_refresh();
        // Switch first so packets at/after the refresh point use the new key.
        if self.next_key_ready && self.packets_on_key >= refresh {
            if let Some(crypto) = &mut self.crypto {
                let next = crypto.next_flags();
                crypto.activate(next);
            }
            self.packets_on_key = 0;
            self.next_key_ready = false;
        }
        self.packets_on_key = self.packets_on_key.saturating_add(1);
        let announce_at = refresh.saturating_sub(self.km_preannounce());
        if !self.rekey_pending
            && !self.next_key_ready
            && self.packets_on_key >= announce_at
            && let Some(enc) = &self.config.encryption
        {
            self.rekey_pending = true;
            self.events.push_back(Event::KeyRefreshNeeded {
                key_size: enc.key_size.bytes(),
            });
        }
    }

    /// Installs the embedder's freshly-generated SEK as the next key and announces
    /// it to the peer (KMREQ), in response to [`Event::KeyRefreshNeeded`]. The core
    /// never generates randomness; `sek` is the embedder-supplied key material.
    pub fn provide_rekey(&mut self, sek: &[u8], now: Instant) {
        if !self.rekey_pending {
            return; // unsolicited or already handled
        }
        let Some((passphrase, cipher)) = self
            .config
            .encryption
            .as_ref()
            .map(|e| (e.passphrase.clone(), e.cipher))
        else {
            return;
        };
        let km_bytes = {
            let Some(crypto) = self.crypto.as_mut() else {
                return;
            };
            let Some(salt) = crypto.salt() else {
                return;
            };
            let next = crypto.next_flags();
            let (keys, km) = SessionKeys::from_raw(&passphrase, next, cipher, salt, sek);
            crypto.install(next, keys);
            let mut buf = BytesMut::new();
            km.encode(&mut buf);
            buf.freeze()
        };
        let bytes = self.km_control(EXT_KMREQ, km_bytes, now);
        self.emit(bytes, now);
        self.rekey_pending = false;
        self.next_key_ready = true;
    }

    /// Handles an incoming rekey KMREQ: install the announced key in its slot
    /// (the peer is about to switch to it) and echo a KMRSP to confirm.
    pub(super) fn on_km_req(&mut self, cif: &[u8], now: Instant) {
        let Some(passphrase) = self
            .config
            .encryption
            .as_ref()
            .map(|e| e.passphrase.clone())
        else {
            return;
        };
        let Ok(km) = KeyMaterial::decode(cif) else {
            return; // malformed: drop
        };
        let installed = {
            let Some(crypto) = self.crypto.as_mut() else {
                return;
            };
            let Ok(keys) = SessionKeys::from_key_material(&km, &passphrase) else {
                return; // wrong passphrase / undecryptable: ignore
            };
            crypto.install(km.key_flags, keys);
            true
        };
        if installed {
            let echo = Bytes::copy_from_slice(cif);
            let bytes = self.km_control(EXT_KMRSP, echo, now);
            self.emit(bytes, now);
        }
    }

    /// Wraps an encoded Key Material message in a `UMSG_EXT` control packet at the
    /// given SRT command subtype (KMREQ / KMRSP).
    fn km_control(&self, subtype: u16, cif: Bytes, now: Instant) -> Bytes {
        encode_control(
            self.peer_socket_id,
            self.wire_ts(now),
            ControlBody::Raw {
                control_type: ControlType::UserDefined,
                subtype,
                type_specific: 0,
                cif,
            },
        )
    }
}
