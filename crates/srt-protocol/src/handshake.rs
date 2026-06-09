//! Handshake control body and its extensions (spec §3.2.1, §4.3).
//!
//! The handshake CIF is a fixed 48-byte header followed by zero or more
//! extension TLVs (type, length-in-4-byte-words, content). For live caller↔
//! listener we parse the SRT handshake extensions (HSREQ/HSRSP) and the Stream
//! ID; Key Material (KMREQ/KMRSP) and other config extensions are carried as
//! [`HandshakeExtension::Raw`] until the crypto module gives them types.
//!
//! The Stream ID has a notorious wire quirk (spec §3.2.1.3): the UTF-8 string is
//! zero-padded to a multiple of four bytes and the byte order is reversed within
//! each 4-byte block. [`encode_stream_id`]/[`decode_stream_id`] handle it.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::HandshakeError;
use crate::packet::SocketId;
use crate::seq::SeqNumber;

/// Fixed size of the handshake CIF before any extensions (spec §3.2.1).
const BASE_LEN: usize = 48;

/// Extension type values (spec §3.2.1.1, Table 5).
const EXT_HSREQ: u16 = 1;
const EXT_HSRSP: u16 = 2;
const EXT_SID: u16 = 5;

/// Byte length of an HSREQ/HSRSP extension content (3 words).
const SRT_HS_LEN: usize = 12;

/// The advertised encryption (spec §3.2.1, Table 2). The value is the key length
/// in bytes divided by eight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionField {
    /// No encryption advertised (`0`).
    None,
    /// AES-128 (`2`).
    Aes128,
    /// AES-192 (`3`).
    Aes192,
    /// AES-256 (`4`).
    Aes256,
}

impl EncryptionField {
    pub(crate) const fn to_raw(self) -> u16 {
        match self {
            EncryptionField::None => 0,
            EncryptionField::Aes128 => 2,
            EncryptionField::Aes192 => 3,
            EncryptionField::Aes256 => 4,
        }
    }

    pub(crate) fn from_raw(raw: u16) -> Result<Self, HandshakeError> {
        match raw {
            0 => Ok(EncryptionField::None),
            2 => Ok(EncryptionField::Aes128),
            3 => Ok(EncryptionField::Aes192),
            4 => Ok(EncryptionField::Aes256),
            other => Err(HandshakeError::InvalidEncryptionField(other)),
        }
    }
}

/// The handshake type (spec §3.2.1, Table 4). A newtype over the raw `u32` so
/// the well-known values are named constants while reject codes and any future
/// values still round-trip exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeType(u32);

impl HandshakeType {
    /// Rendezvous "wavehand" (`0`).
    pub const WAVEHAND: HandshakeType = HandshakeType(0x0000_0000);
    /// Induction — the first phase of the caller-listener handshake (`1`).
    pub const INDUCTION: HandshakeType = HandshakeType(0x0000_0001);
    /// Conclusion — the second phase (`0xFFFFFFFF`).
    pub const CONCLUSION: HandshakeType = HandshakeType(0xFFFF_FFFF);
    /// Rendezvous agreement (`0xFFFFFFFE`).
    pub const AGREEMENT: HandshakeType = HandshakeType(0xFFFF_FFFE);
    /// Rendezvous done (`0xFFFFFFFD`).
    pub const DONE: HandshakeType = HandshakeType(0xFFFF_FFFD);

    /// Wraps a raw handshake-type value.
    #[must_use]
    pub const fn from_raw(value: u32) -> Self {
        HandshakeType(value)
    }

    /// The raw handshake-type value.
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        self.0
    }
}

/// SRT handshake flags (spec §3.2.1.1, Table 6). A `u32` newtype that preserves
/// unknown bits so it round-trips even as the flag set grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrtFlags(u32);

impl SrtFlags {
    /// The sender supports TSBPD.
    pub const TSBPD_SND: u32 = 0x0000_0001;
    /// The receiver supports TSBPD.
    pub const TSBPD_RCV: u32 = 0x0000_0002;
    /// Encryption is in use.
    pub const CRYPT: u32 = 0x0000_0004;
    /// Too-late packet drop is enabled.
    pub const TLPKTDROP: u32 = 0x0000_0008;
    /// Periodic NAK reports are enabled.
    pub const PERIODIC_NAK: u32 = 0x0000_0010;
    /// The retransmission flag in data packets is meaningful.
    pub const REXMIT: u32 = 0x0000_0020;
    /// Stream (buffer) mode rather than message mode.
    pub const STREAM: u32 = 0x0000_0040;
    /// A packet filter (e.g. FEC) is configured.
    pub const PACKET_FILTER: u32 = 0x0000_0080;

    /// Wraps a raw flags word.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        SrtFlags(bits)
    }

    /// The raw flags word.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether all bits in `flag` are set.
    #[must_use]
    pub const fn contains(self, flag: u32) -> bool {
        self.0 & flag == flag
    }
}

/// An SRT handshake extension payload (HSREQ/HSRSP, spec §3.2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrtHandshake {
    /// SRT version (`major * 0x10000 + minor * 0x100 + patch`).
    pub srt_version: u32,
    /// Capability flags.
    pub flags: SrtFlags,
    /// Receiver TSBPD delay, milliseconds.
    pub recv_tsbpd_delay: u16,
    /// Sender TSBPD delay, milliseconds.
    pub send_tsbpd_delay: u16,
}

impl SrtHandshake {
    fn encode(&self, out: &mut BytesMut) {
        out.put_u32(self.srt_version);
        out.put_u32(self.flags.bits());
        out.put_u16(self.recv_tsbpd_delay);
        out.put_u16(self.send_tsbpd_delay);
    }

    /// Decodes from exactly [`SRT_HS_LEN`] bytes (the caller guarantees length).
    fn decode(content: &[u8]) -> Self {
        let mut r = content;
        SrtHandshake {
            srt_version: r.get_u32(),
            flags: SrtFlags::from_bits(r.get_u32()),
            recv_tsbpd_delay: r.get_u16(),
            send_tsbpd_delay: r.get_u16(),
        }
    }
}

/// A handshake extension (spec §3.2.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeExtension {
    /// SRT handshake request (HSREQ).
    HsReq(SrtHandshake),
    /// SRT handshake response (HSRSP).
    HsRsp(SrtHandshake),
    /// Stream ID (SID).
    StreamId(String),
    /// Any other extension, kept raw (KMREQ/KMRSP, congestion, filter, group).
    Raw {
        /// The extension type.
        ext_type: u16,
        /// The raw, already-padded content (a multiple of 4 bytes).
        content: Bytes,
    },
}

impl HandshakeExtension {
    fn encode(&self, out: &mut BytesMut) {
        match self {
            HandshakeExtension::HsReq(hs) => {
                put_ext_header(out, EXT_HSREQ, SRT_HS_LEN);
                hs.encode(out);
            }
            HandshakeExtension::HsRsp(hs) => {
                put_ext_header(out, EXT_HSRSP, SRT_HS_LEN);
                hs.encode(out);
            }
            HandshakeExtension::StreamId(s) => {
                let mut content = BytesMut::new();
                encode_stream_id(s, &mut content);
                put_ext_header(out, EXT_SID, content.len());
                out.put_slice(&content);
            }
            HandshakeExtension::Raw { ext_type, content } => {
                put_ext_header(out, *ext_type, content.len());
                out.put_slice(content);
            }
        }
    }

    fn decode(ext_type: u16, content: &[u8]) -> Result<Self, HandshakeError> {
        match ext_type {
            EXT_HSREQ | EXT_HSRSP if content.len() != SRT_HS_LEN => {
                Err(HandshakeError::ExtensionContent {
                    ext_type,
                    len: content.len(),
                })
            }
            EXT_HSREQ => Ok(HandshakeExtension::HsReq(SrtHandshake::decode(content))),
            EXT_HSRSP => Ok(HandshakeExtension::HsRsp(SrtHandshake::decode(content))),
            EXT_SID => Ok(HandshakeExtension::StreamId(decode_stream_id(content)?)),
            other => Ok(HandshakeExtension::Raw {
                ext_type: other,
                content: Bytes::copy_from_slice(content),
            }),
        }
    }
}

/// A parsed handshake control body (spec §3.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// Protocol version (4 = HSv4/UDT, 5 = HSv5/SRT).
    pub version: u32,
    /// Advertised encryption.
    pub encryption: EncryptionField,
    /// Extension field: the SRT magic during induction, or extension flags during
    /// conclusion. Kept raw; the connection logic interprets it.
    pub extension_field: u16,
    /// Initial packet sequence number.
    pub initial_seq: SeqNumber,
    /// Maximum transmission unit, bytes.
    pub mtu: u32,
    /// Maximum flow window size, packets.
    pub max_flow_window: u32,
    /// Handshake type / phase.
    pub handshake_type: HandshakeType,
    /// The sender's SRT socket id.
    pub srt_socket_id: SocketId,
    /// SYN cookie.
    pub syn_cookie: u32,
    /// Peer IP address (16 bytes; IPv4 occupies the first word).
    pub peer_ip: [u8; 16],
    /// Handshake extensions, in order.
    pub extensions: Vec<HandshakeExtension>,
}

impl Handshake {
    pub(crate) fn encode(&self, out: &mut BytesMut) {
        out.put_u32(self.version);
        out.put_u16(self.encryption.to_raw());
        out.put_u16(self.extension_field);
        out.put_u32(self.initial_seq.value());
        out.put_u32(self.mtu);
        out.put_u32(self.max_flow_window);
        out.put_u32(self.handshake_type.to_raw());
        out.put_u32(self.srt_socket_id.value());
        out.put_u32(self.syn_cookie);
        out.put_slice(&self.peer_ip);
        for ext in &self.extensions {
            ext.encode(out);
        }
    }

    /// Decodes a handshake body from a control packet CIF.
    pub(crate) fn decode(cif: &[u8]) -> Result<Self, HandshakeError> {
        if cif.len() < BASE_LEN {
            return Err(HandshakeError::TooShort {
                need: BASE_LEN,
                got: cif.len(),
            });
        }

        let mut cur = cif;
        let version = cur.get_u32();
        let encryption = EncryptionField::from_raw(cur.get_u16())?;
        let extension_field = cur.get_u16();
        let initial_seq = SeqNumber::new(cur.get_u32());
        let mtu = cur.get_u32();
        let max_flow_window = cur.get_u32();
        let handshake_type = HandshakeType::from_raw(cur.get_u32());
        let srt_socket_id = SocketId::new(cur.get_u32());
        let syn_cookie = cur.get_u32();
        let mut peer_ip = [0u8; 16];
        cur.copy_to_slice(&mut peer_ip);

        let mut extensions = Vec::new();
        while cur.remaining() >= 4 {
            let ext_type = cur.get_u16();
            let content_len = usize::from(cur.get_u16()) * 4;
            if cur.remaining() < content_len {
                return Err(HandshakeError::ExtensionLength {
                    ext_type,
                    claimed: content_len,
                    available: cur.remaining(),
                });
            }
            let content = cur.copy_to_bytes(content_len);
            extensions.push(HandshakeExtension::decode(ext_type, &content)?);
        }

        Ok(Handshake {
            version,
            encryption,
            extension_field,
            initial_seq,
            mtu,
            max_flow_window,
            handshake_type,
            srt_socket_id,
            syn_cookie,
            peer_ip,
            extensions,
        })
    }
}

/// Writes an extension TLV header: type, then length expressed in 4-byte words.
fn put_ext_header(out: &mut BytesMut, ext_type: u16, content_len: usize) {
    let words = u16::try_from(content_len / 4).expect("extension fits in 16-bit word count");
    out.put_u16(ext_type);
    out.put_u16(words);
}

/// Encodes a Stream ID into `out`: zero-padded to a multiple of four bytes, with
/// the bytes reversed within each 4-byte block (spec §3.2.1.3).
pub fn encode_stream_id(stream_id: &str, out: &mut BytesMut) {
    let bytes = stream_id.as_bytes();
    let padded_len = bytes.len().div_ceil(4) * 4;
    let mut padded = vec![0u8; padded_len];
    padded[..bytes.len()].copy_from_slice(bytes);
    for chunk in padded.chunks_exact(4) {
        out.put_u8(chunk[3]);
        out.put_u8(chunk[2]);
        out.put_u8(chunk[1]);
        out.put_u8(chunk[0]);
    }
}

/// Decodes a Stream ID: reverses each 4-byte block and trims the zero padding.
///
/// # Errors
///
/// Returns [`HandshakeError::InvalidStreamId`] if the result is not valid UTF-8.
pub fn decode_stream_id(content: &[u8]) -> Result<String, HandshakeError> {
    let mut bytes = Vec::with_capacity(content.len());
    for chunk in content.chunks_exact(4) {
        bytes.extend(chunk.iter().rev());
    }
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    bytes.truncate(end);
    String::from_utf8(bytes).map_err(|_| HandshakeError::InvalidStreamId)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Handshake {
        Handshake {
            version: 5,
            encryption: EncryptionField::None,
            extension_field: 0x4A17,
            initial_seq: SeqNumber::new(1000),
            mtu: 1500,
            max_flow_window: 8192,
            handshake_type: HandshakeType::INDUCTION,
            srt_socket_id: SocketId::new(0x1234_5678),
            syn_cookie: 0,
            peer_ip: [0; 16],
            extensions: Vec::new(),
        }
    }

    fn round_trip(hs: &Handshake) {
        let mut buf = BytesMut::new();
        hs.encode(&mut buf);
        assert_eq!(buf.len() % 4, 0);
        assert_eq!(&Handshake::decode(&buf).unwrap(), hs);
    }

    #[test]
    fn induction_round_trips() {
        round_trip(&sample());
    }

    #[test]
    fn conclusion_with_extensions_round_trips() {
        let mut hs = sample();
        hs.handshake_type = HandshakeType::CONCLUSION;
        hs.extensions = vec![
            HandshakeExtension::HsReq(SrtHandshake {
                srt_version: 0x0001_0501,
                flags: SrtFlags::from_bits(
                    SrtFlags::TSBPD_SND | SrtFlags::TSBPD_RCV | SrtFlags::TLPKTDROP,
                ),
                recv_tsbpd_delay: 120,
                send_tsbpd_delay: 120,
            }),
            HandshakeExtension::StreamId("#!::u=alice,r=live".to_owned()),
            HandshakeExtension::Raw {
                ext_type: 3, // KMREQ, kept raw for now
                content: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
            },
        ];
        round_trip(&hs);
    }

    #[test]
    fn stream_id_reverses_bytes_within_each_word() {
        let mut buf = BytesMut::new();
        encode_stream_id("ABCD", &mut buf);
        // Bytes are reversed within the 4-byte block.
        assert_eq!(&buf[..], b"DCBA");
        assert_eq!(decode_stream_id(&buf).unwrap(), "ABCD");
    }

    #[test]
    fn stream_id_round_trips_non_word_aligned() {
        for s in ["", "A", "AB", "ABC", "ABCDE", "a-longer-stream-id-value"] {
            let mut buf = BytesMut::new();
            encode_stream_id(s, &mut buf);
            assert_eq!(buf.len() % 4, 0);
            assert_eq!(decode_stream_id(&buf).unwrap(), s);
        }
    }

    #[test]
    fn decode_rejects_short_cif() {
        assert_eq!(
            Handshake::decode(&[0u8; 16]),
            Err(HandshakeError::TooShort { need: 48, got: 16 })
        );
    }

    #[test]
    fn decode_rejects_unknown_encryption_field() {
        let mut buf = BytesMut::new();
        sample().encode(&mut buf);
        // Overwrite the encryption field (bytes 4..6) with an invalid value.
        buf[4] = 0;
        buf[5] = 7;
        assert_eq!(
            Handshake::decode(&buf),
            Err(HandshakeError::InvalidEncryptionField(7))
        );
    }

    #[test]
    fn decode_rejects_extension_running_past_buffer() {
        let mut buf = BytesMut::new();
        sample().encode(&mut buf);
        // Append an extension header claiming 4 words (16 bytes) with none present.
        buf.put_u16(EXT_HSREQ);
        buf.put_u16(4);
        assert_eq!(
            Handshake::decode(&buf),
            Err(HandshakeError::ExtensionLength {
                ext_type: EXT_HSREQ,
                claimed: 16,
                available: 0
            })
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_encryption() -> impl Strategy<Value = EncryptionField> {
        prop_oneof![
            Just(EncryptionField::None),
            Just(EncryptionField::Aes128),
            Just(EncryptionField::Aes192),
            Just(EncryptionField::Aes256),
        ]
    }

    fn any_srt_handshake() -> impl Strategy<Value = SrtHandshake> {
        (any::<u32>(), any::<u32>(), any::<u16>(), any::<u16>()).prop_map(
            |(srt_version, flags, recv_tsbpd_delay, send_tsbpd_delay)| SrtHandshake {
                srt_version,
                flags: SrtFlags::from_bits(flags),
                recv_tsbpd_delay,
                send_tsbpd_delay,
            },
        )
    }

    fn any_extension() -> impl Strategy<Value = HandshakeExtension> {
        prop_oneof![
            any_srt_handshake().prop_map(HandshakeExtension::HsReq),
            any_srt_handshake().prop_map(HandshakeExtension::HsRsp),
            "[ -~]{0,40}".prop_map(HandshakeExtension::StreamId),
            // Raw extension types that we don't parse, content a multiple of 4.
            (
                prop_oneof![Just(3u16), Just(4u16), Just(6u16), Just(7u16), Just(8u16)],
                prop::collection::vec(any::<u8>(), 0..16).prop_map(|mut v| {
                    while v.len() % 4 != 0 {
                        v.push(0);
                    }
                    v
                }),
            )
                .prop_map(|(ext_type, content)| HandshakeExtension::Raw {
                    ext_type,
                    content: Bytes::from(content),
                }),
        ]
    }

    prop_compose! {
        fn any_handshake()(
            version in any::<u32>(),
            encryption in any_encryption(),
            extension_field in any::<u16>(),
            initial_seq in 0u32..=0x7FFF_FFFF,
            mtu in any::<u32>(),
            max_flow_window in any::<u32>(),
            handshake_type in any::<u32>(),
            srt_socket_id in any::<u32>(),
            syn_cookie in any::<u32>(),
            peer_ip in any::<[u8; 16]>(),
            extensions in prop::collection::vec(any_extension(), 0..6),
        ) -> Handshake {
            Handshake {
                version,
                encryption,
                extension_field,
                initial_seq: SeqNumber::new(initial_seq),
                mtu,
                max_flow_window,
                handshake_type: HandshakeType::from_raw(handshake_type),
                srt_socket_id: SocketId::new(srt_socket_id),
                syn_cookie,
                peer_ip,
                extensions,
            }
        }
    }

    proptest! {
        #[test]
        fn handshake_round_trips(hs in any_handshake()) {
            let mut buf = BytesMut::new();
            hs.encode(&mut buf);
            let decoded = Handshake::decode(&buf).expect("decoding our own encoding must succeed");
            let mut reencoded = BytesMut::new();
            decoded.encode(&mut reencoded);
            prop_assert_eq!(&buf[..], &reencoded[..]);
            prop_assert_eq!(decoded, hs);
        }
    }
}
