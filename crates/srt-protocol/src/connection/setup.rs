//! Caller-side handshake: the induction → conclusion exchange that establishes a
//! connection (spec §4.3.1), plus the helpers that compute negotiated parameters
//! and build the SRT handshake extensions.
//!
//! A child module of `connection`, so these `impl Connection` methods reach the
//! private connection state directly via `self` (the same arrangement as
//! `connection::arq`). The general wire helpers they lean on — `wire_ts`,
//! `encode_control`, `enter_connected` — stay in the parent.

use std::time::{Duration, Instant};

use bytes::Bytes;

use super::{
    Connection, EXT_FLAG_CONFIG, EXT_FLAG_HSREQ, EXT_FLAG_KMREQ, EXT_KMREQ, HS_VERSION_SRT,
    HS_VERSION_UDT, INDUCTION_EXT_FIELD, Negotiated, Output, SRT_LIBRARY_VERSION, SRT_MAGIC,
    SYN_INTERVAL, State, TimerId, encode_control,
};
use crate::control::ControlBody;
use crate::crypto::key_material::KeyMaterial;
use crate::crypto::{SessionKeys, UnwrappedKm};
use crate::error::{ConnectionError, CryptoError};
use crate::handshake::{
    EncryptionField, Handshake, HandshakeExtension, HandshakeType, SrtFlags, SrtHandshake,
};
use crate::packet::SocketId;

use super::EncryptionSettings;

impl Connection {
    /// Sends the Caller's INDUCTION handshake (spec §4.3.1.1): version 4, no
    /// encryption, extension field 2, addressed to socket id 0.
    pub(super) fn send_induction(&mut self, now: Instant) {
        let hs = Handshake {
            version: HS_VERSION_UDT,
            encryption: EncryptionField::None,
            extension_field: INDUCTION_EXT_FIELD,
            initial_seq: self.initial_seq,
            mtu: self.config.mtu,
            max_flow_window: self.config.flow_window,
            handshake_type: HandshakeType::INDUCTION,
            srt_socket_id: self.local_socket_id,
            syn_cookie: 0,
            peer_ip: [0u8; 16],
            extensions: Vec::new(),
        };
        self.emit_handshake(SocketId::new(0), hs, now);
    }

    /// Handles the Listener's induction response and advances to the conclusion
    /// phase (spec §4.3.1.1 → §4.3.1.2). Non-conforming responses are ignored.
    pub(super) fn on_induction_response(&mut self, hs: &Handshake, now: Instant) {
        if hs.version != HS_VERSION_SRT
            || hs.extension_field != SRT_MAGIC
            || hs.handshake_type != HandshakeType::INDUCTION
        {
            return;
        }
        self.peer_socket_id = hs.srt_socket_id;
        self.syn_cookie = hs.syn_cookie;
        self.state = State::Conclusion;
        self.send_conclusion(now);
    }

    /// Sends the Caller's CONCLUSION handshake (spec §4.3.1.2): version 5, the
    /// echoed cookie, an HSREQ extension, and — if configured — a Stream ID.
    fn send_conclusion(&mut self, now: Instant) {
        let mut extensions = vec![HandshakeExtension::HsReq(srt_handshake_ext(
            self.latency_ms(),
        ))];
        let mut extension_field = EXT_FLAG_HSREQ;
        if let Some(stream_id) = &self.config.stream_id {
            extensions.push(HandshakeExtension::StreamId(stream_id.clone()));
            extension_field |= EXT_FLAG_CONFIG;
        }
        // KMREQ: advertise the wrapped Stream Encrypting Key (spec §4.3.1.2).
        let mut encryption = EncryptionField::None;
        if let (Some(km), Some(enc)) = (&self.key_material, &self.config.encryption) {
            extensions.push(HandshakeExtension::Raw {
                ext_type: EXT_KMREQ,
                content: km.clone(),
            });
            extension_field |= EXT_FLAG_KMREQ;
            encryption = enc.key_size.to_field();
        }
        let hs = Handshake {
            version: HS_VERSION_SRT,
            encryption,
            extension_field,
            initial_seq: self.initial_seq,
            mtu: self.config.mtu,
            max_flow_window: self.config.flow_window,
            handshake_type: HandshakeType::CONCLUSION,
            srt_socket_id: self.local_socket_id,
            syn_cookie: self.syn_cookie,
            peer_ip: [0u8; 16],
            extensions,
        };
        // Address the conclusion to socket id 0, like the induction. The spec
        // (§4.3.1.2) says to use the listener's socket id from the induction
        // response, but libsrt's receive queue only routes a *zero* destination
        // id to the listener (a non-zero id is looked up as an established
        // socket, which does not exist yet, so the conclusion is dropped). The
        // connection is not established until the conclusion response arrives, so
        // both handshake phases stay addressed to 0. Verified against libsrt 1.5.5.
        self.emit_handshake(SocketId::new(0), hs, now);
    }

    /// Handles the Listener's conclusion response: the handshake is complete
    /// (spec §4.3.1.2). Clears the retransmit timer and enters the ARQ phase.
    pub(super) fn on_conclusion_response(&mut self, hs: &Handshake, now: Instant) {
        if hs.handshake_type != HandshakeType::CONCLUSION || hs.version != HS_VERSION_SRT {
            return;
        }
        let negotiated = negotiate(self.config.latency, hs);
        self.outputs.push_back(Output::ClearTimer {
            id: TimerId::Handshake,
        });
        self.enter_connected(negotiated, now);
    }

    /// Encodes `hs`, caches it for retransmission, and queues the datagram plus a
    /// fresh retransmit timer.
    fn emit_handshake(&mut self, dest: SocketId, hs: Handshake, now: Instant) {
        let bytes = encode_control(dest, self.wire_ts(now), ControlBody::Handshake(hs));
        self.last_handshake = Some(bytes.clone());
        self.outputs.push_back(Output::SendDatagram(bytes));
        self.outputs.push_back(Output::SetTimer {
            id: TimerId::Handshake,
            after: SYN_INTERVAL,
        });
    }

    /// Our configured TSBPD latency in whole milliseconds (the wire unit).
    fn latency_ms(&self) -> u16 {
        millis_u16(self.config.latency)
    }
}

/// Computes the negotiated parameters from the peer's handshake (spec §4.3.1.2):
/// the agreed latency is the greater of the two reported TSBPD delays.
pub(super) fn negotiate(local_latency: Duration, peer_hs: &Handshake) -> Negotiated {
    let peer_latency_ms = peer_hs
        .extensions
        .iter()
        .find_map(|ext| match ext {
            HandshakeExtension::HsReq(s) | HandshakeExtension::HsRsp(s) => {
                Some(u64::from(s.recv_tsbpd_delay))
            }
            _ => None,
        })
        .unwrap_or(0);
    Negotiated {
        peer_socket_id: peer_hs.srt_socket_id,
        peer_initial_seq: peer_hs.initial_seq,
        latency: local_latency.max(Duration::from_millis(peer_latency_ms)),
        encryption: peer_hs.encryption,
    }
}

/// Sets up the acceptor's session keys from the caller's conclusion (spec §6),
/// returning the recovered key slot(s) and the Key Material bytes to echo as
/// KMRSP. An unencrypted connection yields `(None, None)`.
pub(super) fn accept_crypto(
    encryption: Option<&EncryptionSettings>,
    caller_hs: &Handshake,
) -> Result<(Option<UnwrappedKm>, Option<Bytes>), ConnectionError> {
    let Some(enc) = encryption else {
        return Ok((None, None));
    };
    let km_bytes = caller_hs
        .extensions
        .iter()
        .find_map(|ext| match ext {
            HandshakeExtension::Raw {
                ext_type: EXT_KMREQ,
                content,
            } => Some(content),
            _ => None,
        })
        .ok_or(ConnectionError::Crypto(CryptoError::MissingKeyMaterial))?;
    let km = KeyMaterial::decode(km_bytes).map_err(ConnectionError::Crypto)?;
    let keys =
        SessionKeys::from_key_material(&km, &enc.passphrase).map_err(ConnectionError::Crypto)?;
    Ok((Some(keys), Some(km_bytes.clone())))
}

/// Builds the live-mode HSREQ/HSRSP extension we always advertise.
///
/// `PERIODIC_NAK` matters for interop: without it, libsrt assumes the peer
/// sends no loss reports and falls back to blind timeout-based retransmission
/// (LATEREXMIT), producing un-NAK'd duplicate traffic toward a receiver that
/// does NAK. srtrust implements periodic NAK reports, so it says so.
pub(super) fn srt_handshake_ext(latency_ms: u16) -> SrtHandshake {
    SrtHandshake {
        srt_version: SRT_LIBRARY_VERSION,
        flags: SrtFlags::from_bits(
            SrtFlags::TSBPD_SND
                | SrtFlags::TSBPD_RCV
                | SrtFlags::TLPKTDROP
                | SrtFlags::PERIODIC_NAK
                | SrtFlags::REXMIT,
        ),
        recv_tsbpd_delay: latency_ms,
        send_tsbpd_delay: latency_ms,
    }
}

/// A [`Duration`] as whole milliseconds clamped to `u16` (the wire field width).
pub(super) fn millis_u16(d: Duration) -> u16 {
    u16::try_from(d.as_millis()).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::SrtFlags;

    /// The HSREQ/HSRSP extension must advertise every capability srtrust
    /// actually implements. `PERIODIC_NAK` (libsrt `SRT_OPT_NAKREPORT`) in
    /// particular: without it, libsrt assumes the peer never sends loss
    /// reports and falls back to blind timeout-based retransmission
    /// (LATEREXMIT) — wasteful duplicates for a receiver that *does* NAK.
    /// Found live against libsrt 1.5.5 (un-NAK'd retransmissions on the wire).
    #[test]
    fn the_handshake_advertises_every_implemented_capability() {
        let hs = srt_handshake_ext(120);
        for (flag, name) in [
            (SrtFlags::TSBPD_SND, "TSBPD_SND"),
            (SrtFlags::TSBPD_RCV, "TSBPD_RCV"),
            (SrtFlags::TLPKTDROP, "TLPKTDROP"),
            (SrtFlags::PERIODIC_NAK, "PERIODIC_NAK"),
            (SrtFlags::REXMIT, "REXMIT"),
        ] {
            assert!(hs.flags.contains(flag), "{name} must be advertised");
        }
        assert_eq!(hs.recv_tsbpd_delay, 120);
        assert_eq!(hs.send_tsbpd_delay, 120);
    }
}
