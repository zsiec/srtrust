//! SRT packet wire format (spec §3).
//!
//! Every SRT packet begins with a 16-byte common header of four big-endian
//! 32-bit words. The most significant bit of the first word — the **F**
//! (packet-type) flag — selects the layout: `0` = [`DataPacket`] (§3.1),
//! `1` = [`ControlPacket`] (§3.2).
//!
//! ```text
//! Data (§3.1)                         Control (§3.2)
//! 0                   1               0                   1
//! 0 1 2 ...        3 0 1             0 1 2 ...          3 0 1
//! +-+-----------------+             +-+-----------------+
//! |0| Sequence Number |             |1|  Control Type   |  Subtype
//! +-+-----------------+             +-+-----------------+
//! |PP|O|KK|R| Msg No  |             | Type-specific Information |
//! +-------------------+             +--------------------------+
//! |     Timestamp     |             |        Timestamp         |
//! +-------------------+             +--------------------------+
//! | Destination Sock  |             |   Destination Socket ID  |
//! +-------------------+             +--------------------------+
//! |     Payload...    |             |          CIF...          |
//! ```
//!
//! For now a control packet keeps its Control Information Field as raw bytes;
//! typed CIFs (ACK/NAK/handshake/…) are parsed in later modules.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::control::ControlBody;
use crate::error::PacketError;
use crate::seq::SeqNumber;
use crate::timestamp::Timestamp;

/// Size of the common header (spec §3): four 32-bit words.
const HEADER_LEN: usize = 16;

/// Bit mask for the F (packet-type) flag in the first header word.
const FLAG_CONTROL: u32 = 0x8000_0000;

/// A 32-bit SRT socket identifier (the destination socket id in the header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketId(u32);

impl SocketId {
    /// Wraps a raw socket id.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        SocketId(value)
    }

    /// The raw socket id.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// A 26-bit message number (spec §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsgNumber(u32);

impl MsgNumber {
    const MASK: u32 = 0x03FF_FFFF;

    /// Wraps a raw value, keeping only the low 26 bits (the wire field width).
    #[must_use]
    pub const fn new(value: u32) -> Self {
        MsgNumber(value & Self::MASK)
    }

    /// The raw 26-bit value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Position of a packet within a message (spec §3.1, the `PP` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketPosition {
    /// First packet of a multi-packet message (`0b10`).
    First,
    /// A middle packet of a multi-packet message (`0b00`).
    Middle,
    /// Last packet of a multi-packet message (`0b01`).
    Last,
    /// A complete message in a single packet (`0b11`).
    Single,
}

impl PacketPosition {
    const fn to_bits(self) -> u8 {
        match self {
            PacketPosition::First => 0b10,
            PacketPosition::Middle => 0b00,
            PacketPosition::Last => 0b01,
            PacketPosition::Single => 0b11,
        }
    }

    const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b10 => PacketPosition::First,
            0b01 => PacketPosition::Last,
            0b11 => PacketPosition::Single,
            // 0b00 and any masked-away bits.
            _ => PacketPosition::Middle,
        }
    }
}

/// Which encryption key (if any) protects a data packet's payload
/// (spec §3.1, the `KK` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encryption {
    /// Unencrypted (`0b00`).
    None,
    /// Encrypted with the even key (`0b01`).
    Even,
    /// Encrypted with the odd key (`0b10`).
    Odd,
}

impl Encryption {
    /// The 2-bit `KK` wire pattern for this key selection. `pub(crate)` so the FEC
    /// engine can clip and rebuild the encryption flag (spec §3.1).
    pub(crate) const fn to_bits(self) -> u8 {
        match self {
            Encryption::None => 0b00,
            Encryption::Even => 0b01,
            Encryption::Odd => 0b10,
        }
    }

    /// Parses a 2-bit `KK` wire pattern. `pub(crate)` so the FEC engine can turn a
    /// rebuilt flag byte back into a key selection (rejecting the invalid `0b11`).
    pub(crate) fn from_bits(bits: u8) -> Result<Self, PacketError> {
        match bits & 0b11 {
            0b00 => Ok(Encryption::None),
            0b01 => Ok(Encryption::Even),
            0b10 => Ok(Encryption::Odd),
            // 0b11 ("both keys") is only valid in a Key Material message.
            other => Err(PacketError::InvalidKeyFlag(other)),
        }
    }
}

/// A data packet carrying application payload (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    /// Packet sequence number (31-bit, §3.1).
    pub seq: SeqNumber,
    /// Position within the application message.
    pub position: PacketPosition,
    /// Whether in-order delivery is required (the `O` flag).
    pub in_order: bool,
    /// Which key encrypts the payload, if any.
    pub encryption: Encryption,
    /// Whether this is a retransmission (the `R` flag).
    pub retransmitted: bool,
    /// Message number (26-bit).
    pub message_number: MsgNumber,
    /// Sender timestamp.
    pub timestamp: Timestamp,
    /// Destination socket id.
    pub dest_socket_id: SocketId,
    /// Application payload (possibly encrypted).
    pub payload: Bytes,
}

impl DataPacket {
    /// The packet's 16-byte wire header (the four header words, big-endian) —
    /// used as the AES-GCM Additional Authenticated Data (libsrt authenticates the
    /// header). Identical to the first 16 bytes [`Packet::encode`] produces.
    #[must_use]
    pub fn header_aad(&self) -> [u8; 16] {
        let w1 = (u32::from(self.position.to_bits()) << 30)
            | (u32::from(self.in_order) << 29)
            | (u32::from(self.encryption.to_bits()) << 27)
            | (u32::from(self.retransmitted) << 26)
            | self.message_number.value();
        let mut aad = [0u8; 16];
        aad[0..4].copy_from_slice(&self.seq.value().to_be_bytes());
        aad[4..8].copy_from_slice(&w1.to_be_bytes());
        aad[8..12].copy_from_slice(&self.timestamp.as_micros().to_be_bytes());
        aad[12..16].copy_from_slice(&self.dest_socket_id.value().to_be_bytes());
        aad
    }
}

/// A control packet (spec §3.2). The control type, subtype, type-specific
/// field, and CIF are all captured by the typed [`ControlBody`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    /// Sender timestamp.
    pub timestamp: Timestamp,
    /// Destination socket id.
    pub dest_socket_id: SocketId,
    /// The typed control body.
    pub body: ControlBody,
}

/// An SRT packet: either a [`DataPacket`] or a [`ControlPacket`] (spec §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// A data packet (§3.1).
    Data(DataPacket),
    /// A control packet (§3.2).
    Control(ControlPacket),
}

impl Packet {
    /// Encodes this packet into `out` (appending to whatever is already there).
    pub fn encode(&self, out: &mut BytesMut) {
        match self {
            Packet::Data(d) => {
                // Word 0: F=0, then the 31-bit sequence number.
                out.put_u32(d.seq.value());
                // Word 1: PP(2) | O(1) | KK(2) | R(1) | message number(26).
                let w1 = (u32::from(d.position.to_bits()) << 30)
                    | (u32::from(d.in_order) << 29)
                    | (u32::from(d.encryption.to_bits()) << 27)
                    | (u32::from(d.retransmitted) << 26)
                    | d.message_number.value();
                out.put_u32(w1);
                out.put_u32(d.timestamp.as_micros());
                out.put_u32(d.dest_socket_id.value());
                out.put_slice(&d.payload);
            }
            Packet::Control(c) => {
                // Word 0: F=1, control type(15), subtype(16).
                let (control_type, subtype, type_specific) = c.body.to_wire();
                let w0 = FLAG_CONTROL | (u32::from(control_type) << 16) | u32::from(subtype);
                out.put_u32(w0);
                out.put_u32(type_specific);
                out.put_u32(c.timestamp.as_micros());
                out.put_u32(c.dest_socket_id.value());
                c.body.encode_cif(out);
            }
        }
    }

    /// Decodes a packet from `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::TooShort`] if `buf` is smaller than the 16-byte
    /// common header, [`PacketError::InvalidKeyFlag`] for the reserved `0b11` key
    /// flag on a data packet, or [`PacketError::Control`] if a control body fails
    /// to decode. An unrecognised control *type* is not an error — it is preserved
    /// as [`ControlBody::Raw`] so the packet
    /// round-trips.
    // The `as u16`/`as u8` casts below all follow a bit-mask that guarantees the
    // value fits the narrower type, so the truncation is intentional and safe.
    #[allow(clippy::cast_possible_truncation)]
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < HEADER_LEN {
            return Err(PacketError::TooShort {
                need: HEADER_LEN,
                got: buf.len(),
            });
        }

        let mut cur = buf;
        let w0 = cur.get_u32();
        let w1 = cur.get_u32();
        let timestamp = Timestamp::from_micros(cur.get_u32());
        let dest_socket_id = SocketId::new(cur.get_u32());

        if w0 & FLAG_CONTROL != 0 {
            let body = ControlBody::decode((w0 >> 16) as u16 & 0x7FFF, w0 as u16, w1, cur)?;
            Ok(Packet::Control(ControlPacket {
                timestamp,
                dest_socket_id,
                body,
            }))
        } else {
            let encryption = Encryption::from_bits(((w1 >> 27) & 0b11) as u8)?;
            Ok(Packet::Data(DataPacket {
                seq: SeqNumber::new(w0),
                position: PacketPosition::from_bits((w1 >> 30) as u8),
                in_order: w1 & (1 << 29) != 0,
                encryption,
                retransmitted: w1 & (1 << 26) != 0,
                message_number: MsgNumber::new(w1),
                timestamp,
                dest_socket_id,
                payload: Bytes::copy_from_slice(cur),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> Packet {
        Packet::Data(DataPacket {
            seq: SeqNumber::new(12_345),
            position: PacketPosition::Single,
            in_order: true,
            encryption: Encryption::Even,
            retransmitted: false,
            message_number: MsgNumber::new(7),
            timestamp: Timestamp::from_micros(1_000_000),
            dest_socket_id: SocketId::new(0xDEAD_BEEF),
            payload: Bytes::from_static(b"hello srt"),
        })
    }

    fn sample_control() -> Packet {
        // A light ACK: its CIF is the single 4-byte acknowledged sequence number.
        Packet::Control(ControlPacket {
            timestamp: Timestamp::from_micros(500),
            dest_socket_id: SocketId::new(1),
            body: ControlBody::Ack(crate::control::Ack {
                ack_number: 42,
                last_ack_seq: SeqNumber::new(1000),
                cif: crate::control::AckCif::Light,
            }),
        })
    }

    #[test]
    fn data_packet_round_trip() {
        let pkt = sample_data();
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN + 9);
        assert_eq!(Packet::decode(&buf).unwrap(), pkt);
    }

    #[test]
    fn control_packet_round_trip() {
        let pkt = sample_control();
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN + 4);
        assert_eq!(Packet::decode(&buf).unwrap(), pkt);
    }

    #[test]
    fn data_packet_has_clear_flag_bit() {
        let mut buf = BytesMut::new();
        sample_data().encode(&mut buf);
        // First word, MSB clear => data packet.
        assert_eq!(buf[0] & 0x80, 0);
    }

    #[test]
    fn control_packet_has_set_flag_bit() {
        let mut buf = BytesMut::new();
        sample_control().encode(&mut buf);
        assert_eq!(buf[0] & 0x80, 0x80);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        assert_eq!(
            Packet::decode(&[0u8; 4]),
            Err(PacketError::TooShort { need: 16, got: 4 })
        );
    }

    #[test]
    fn decode_rejects_unknown_control_type() {
        let mut buf = BytesMut::new();
        buf.put_u32(FLAG_CONTROL | (0x00FF << 16));
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_u32(0);
        assert_eq!(
            Packet::decode(&buf),
            Err(PacketError::Control(
                crate::error::ControlError::UnknownType(0x00FF)
            ))
        );
    }

    #[test]
    fn decode_rejects_both_keys_on_data_packet() {
        let mut buf = BytesMut::new();
        buf.put_u32(0); // data packet, seq 0
        buf.put_u32(0b11 << 27); // KK = 0b11
        buf.put_u32(0);
        buf.put_u32(0);
        assert_eq!(Packet::decode(&buf), Err(PacketError::InvalidKeyFlag(0b11)));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn any_position() -> impl Strategy<Value = PacketPosition> {
        prop_oneof![
            Just(PacketPosition::First),
            Just(PacketPosition::Middle),
            Just(PacketPosition::Last),
            Just(PacketPosition::Single),
        ]
    }

    fn any_encryption() -> impl Strategy<Value = Encryption> {
        prop_oneof![
            Just(Encryption::None),
            Just(Encryption::Even),
            Just(Encryption::Odd),
        ]
    }

    prop_compose! {
        fn any_data_packet()(
            seq in 0u32..=0x7FFF_FFFF,
            position in any_position(),
            in_order in any::<bool>(),
            encryption in any_encryption(),
            retransmitted in any::<bool>(),
            msg in 0u32..=0x03FF_FFFF,
            ts in any::<u32>(),
            dest in any::<u32>(),
            payload in prop::collection::vec(any::<u8>(), 0..1456),
        ) -> Packet {
            Packet::Data(DataPacket {
                seq: SeqNumber::new(seq),
                position,
                in_order,
                encryption,
                retransmitted,
                message_number: MsgNumber::new(msg),
                timestamp: Timestamp::from_micros(ts),
                dest_socket_id: SocketId::new(dest),
                payload: Bytes::from(payload),
            })
        }
    }

    proptest! {
        // Encoding then decoding yields the original data packet, and re-encoding
        // the decoded packet is byte-for-byte identical. (Control packets are
        // round-tripped in the `control` module.)
        #[test]
        fn round_trip(pkt in any_data_packet()) {
            let mut buf = BytesMut::new();
            pkt.encode(&mut buf);
            let decoded = Packet::decode(&buf).expect("decoding our own encoding must succeed");
            let mut reencoded = BytesMut::new();
            decoded.encode(&mut reencoded);
            prop_assert_eq!(&buf[..], &reencoded[..]);
            prop_assert_eq!(decoded, pkt);
        }
    }

    proptest! {
        // Decoding arbitrary bytes must never panic — it returns Ok or Err.
        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2000)) {
            let _ = Packet::decode(&bytes);
        }
    }
}
