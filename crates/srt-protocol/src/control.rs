//! Typed control packet bodies (spec §3.2).
//!
//! A control packet's meaning lives in three header places — the 15-bit control
//! type, the 16-bit subtype, and the 32-bit type-specific field — plus the CIF
//! (Control Information Field) that follows the common header. [`ControlBody`]
//! folds all of that into one typed value per control type, so the rest of the
//! protocol never juggles raw words.
//!
//! The handshake body (§3.2.1) is large enough to live in its own module
//! ([`crate::handshake`]) and is carried here as the typed
//! [`ControlBody::Handshake`] variant. Control types we don't yet originate (e.g.
//! the UMSG_EXT key-material messages) are preserved losslessly as
//! [`ControlBody::Raw`] so a peer's packets always round-trip.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::ControlError;
use crate::handshake::Handshake;
use crate::loss_list::{self, LossRange};
use crate::seq::SeqNumber;

/// Control packet type, the 15-bit Control Type field (spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlType {
    /// Connection handshake (`0x0000`, §3.2.1).
    Handshake,
    /// Keep-alive (`0x0001`, §3.2.3).
    Keepalive,
    /// Acknowledgement (`0x0002`, §3.2.4).
    Ack,
    /// Loss report / negative acknowledgement (`0x0003`, §3.2.5).
    Nak,
    /// Congestion warning (`0x0004`, §3.2.6).
    CongestionWarning,
    /// Shutdown (`0x0005`, §3.2.7).
    Shutdown,
    /// Acknowledgement of an ACK (`0x0006`, §3.2.8).
    AckAck,
    /// Message drop request (`0x0007`, §3.2.9).
    DropReq,
    /// Peer error (`0x0008`, §3.2.10).
    PeerError,
    /// User-defined control packet (`0x7FFF`).
    UserDefined,
}

impl ControlType {
    const fn to_raw(self) -> u16 {
        match self {
            ControlType::Handshake => 0x0000,
            ControlType::Keepalive => 0x0001,
            ControlType::Ack => 0x0002,
            ControlType::Nak => 0x0003,
            ControlType::CongestionWarning => 0x0004,
            ControlType::Shutdown => 0x0005,
            ControlType::AckAck => 0x0006,
            ControlType::DropReq => 0x0007,
            ControlType::PeerError => 0x0008,
            ControlType::UserDefined => 0x7FFF,
        }
    }

    fn from_raw(raw: u16) -> Result<Self, ControlError> {
        match raw {
            0x0000 => Ok(ControlType::Handshake),
            0x0001 => Ok(ControlType::Keepalive),
            0x0002 => Ok(ControlType::Ack),
            0x0003 => Ok(ControlType::Nak),
            0x0004 => Ok(ControlType::CongestionWarning),
            0x0005 => Ok(ControlType::Shutdown),
            0x0006 => Ok(ControlType::AckAck),
            0x0007 => Ok(ControlType::DropReq),
            0x0008 => Ok(ControlType::PeerError),
            0x7FFF => Ok(ControlType::UserDefined),
            other => Err(ControlError::UnknownType(other)),
        }
    }
}

/// The metrics carried by an acknowledgement (spec §3.2.4). The variant records
/// how much of the ACK was sent: a *light* ACK carries only the acknowledged
/// sequence number, a *small* ACK adds RTT info, and a *full* ACK adds rate
/// estimates. Modeling it as an enum keeps impossible field combinations
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckCif {
    /// Light ACK: only the acknowledged sequence number (4-byte CIF).
    Light,
    /// Small ACK: RTT, RTT variance, and available buffer size (16-byte CIF).
    Small {
        /// Smoothed round-trip time, microseconds.
        rtt: u32,
        /// Round-trip time variance, microseconds.
        rtt_variance: u32,
        /// Available receive buffer size, packets.
        avail_buffer_size: u32,
    },
    /// Full ACK: the small-ACK fields plus rate estimates (28-byte CIF).
    Full {
        /// Smoothed round-trip time, microseconds.
        rtt: u32,
        /// Round-trip time variance, microseconds.
        rtt_variance: u32,
        /// Available receive buffer size, packets.
        avail_buffer_size: u32,
        /// Packet receiving rate, packets/second.
        packets_recv_rate: u32,
        /// Estimated link capacity, packets/second.
        estimated_link_capacity: u32,
        /// Receiving rate, bytes/second.
        receiving_rate: u32,
    },
}

/// An acknowledgement control packet (spec §3.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// Acknowledgement number (the ACK's type-specific field); echoed in ACKACK.
    pub ack_number: u32,
    /// The sequence number one past the last contiguously received packet.
    pub last_ack_seq: SeqNumber,
    /// How much detail this ACK carries.
    pub cif: AckCif,
}

/// A typed control packet body (spec §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlBody {
    /// Keep-alive (§3.2.3): no CIF.
    Keepalive,
    /// Shutdown (§3.2.7): no CIF.
    Shutdown,
    /// Congestion warning (§3.2.6): reserved, no active CIF.
    CongestionWarning,
    /// Acknowledgement of a full ACK (§3.2.8); carries the ACK number.
    AckAck {
        /// The acknowledgement number being confirmed.
        ack_number: u32,
    },
    /// Message drop request (§3.2.9).
    DropReq {
        /// The message number being dropped (type-specific field).
        message_number: u32,
        /// First dropped sequence number (inclusive).
        first: SeqNumber,
        /// Last dropped sequence number (inclusive).
        last: SeqNumber,
    },
    /// Peer error (§3.2.10); carries the error code.
    PeerError {
        /// Implementation-defined error code (type-specific field).
        error_code: u32,
    },
    /// Acknowledgement (§3.2.4).
    Ack(Ack),
    /// Loss report (§3.2.5); the compressed loss list.
    Nak {
        /// The lost sequence numbers, as inclusive ranges.
        loss: Vec<LossRange>,
    },
    /// Connection handshake (§3.2.1).
    Handshake(Handshake),
    /// A control packet whose body we don't yet parse (user-defined).
    /// Keeps the raw fields so it round-trips exactly.
    Raw {
        /// The control type.
        control_type: ControlType,
        /// The 16-bit subtype.
        subtype: u16,
        /// The 32-bit type-specific field.
        type_specific: u32,
        /// The raw CIF bytes.
        cif: Bytes,
    },
}

impl ControlBody {
    /// The control-type, subtype, and type-specific header words for this body.
    pub(crate) fn to_wire(&self) -> (u16, u16, u32) {
        match self {
            ControlBody::Keepalive => (ControlType::Keepalive.to_raw(), 0, 0),
            ControlBody::Shutdown => (ControlType::Shutdown.to_raw(), 0, 0),
            ControlBody::CongestionWarning => (ControlType::CongestionWarning.to_raw(), 0, 0),
            ControlBody::AckAck { ack_number } => (ControlType::AckAck.to_raw(), 0, *ack_number),
            ControlBody::DropReq { message_number, .. } => {
                (ControlType::DropReq.to_raw(), 0, *message_number)
            }
            ControlBody::PeerError { error_code } => {
                (ControlType::PeerError.to_raw(), 0, *error_code)
            }
            ControlBody::Ack(ack) => (ControlType::Ack.to_raw(), 0, ack.ack_number),
            ControlBody::Nak { .. } => (ControlType::Nak.to_raw(), 0, 0),
            ControlBody::Handshake(_) => (ControlType::Handshake.to_raw(), 0, 0),
            ControlBody::Raw {
                control_type,
                subtype,
                type_specific,
                ..
            } => (control_type.to_raw(), *subtype, *type_specific),
        }
    }

    /// Appends this body's CIF to `out`.
    pub(crate) fn encode_cif(&self, out: &mut BytesMut) {
        match self {
            // No CIF (the type-specific field carries any payload).
            ControlBody::Keepalive
            | ControlBody::Shutdown
            | ControlBody::CongestionWarning
            | ControlBody::AckAck { .. }
            | ControlBody::PeerError { .. } => {}
            ControlBody::DropReq { first, last, .. } => {
                out.put_u32(first.value());
                out.put_u32(last.value());
            }
            ControlBody::Ack(ack) => {
                out.put_u32(ack.last_ack_seq.value());
                match ack.cif {
                    AckCif::Light => {}
                    AckCif::Small {
                        rtt,
                        rtt_variance,
                        avail_buffer_size,
                    } => {
                        out.put_u32(rtt);
                        out.put_u32(rtt_variance);
                        out.put_u32(avail_buffer_size);
                    }
                    AckCif::Full {
                        rtt,
                        rtt_variance,
                        avail_buffer_size,
                        packets_recv_rate,
                        estimated_link_capacity,
                        receiving_rate,
                    } => {
                        out.put_u32(rtt);
                        out.put_u32(rtt_variance);
                        out.put_u32(avail_buffer_size);
                        out.put_u32(packets_recv_rate);
                        out.put_u32(estimated_link_capacity);
                        out.put_u32(receiving_rate);
                    }
                }
            }
            ControlBody::Nak { loss } => loss_list::encode(loss, out),
            ControlBody::Handshake(hs) => hs.encode(out),
            ControlBody::Raw { cif, .. } => out.put_slice(cif),
        }
    }

    /// Decodes a control body from its header words and CIF bytes.
    pub(crate) fn decode(
        raw_type: u16,
        subtype: u16,
        type_specific: u32,
        cif: &[u8],
    ) -> Result<Self, ControlError> {
        let control_type = ControlType::from_raw(raw_type)?;
        match control_type {
            // No-CIF types: any trailing bytes (e.g. libsrt's zero padding) are
            // ignored.
            ControlType::Keepalive => Ok(ControlBody::Keepalive),
            ControlType::Shutdown => Ok(ControlBody::Shutdown),
            ControlType::CongestionWarning => Ok(ControlBody::CongestionWarning),
            ControlType::AckAck => Ok(ControlBody::AckAck {
                ack_number: type_specific,
            }),
            ControlType::PeerError => Ok(ControlBody::PeerError {
                error_code: type_specific,
            }),
            ControlType::DropReq => {
                let mut r = cif;
                if r.remaining() != 8 {
                    return Err(ControlError::InvalidCifLength {
                        kind: "drop request",
                        len: cif.len(),
                    });
                }
                Ok(ControlBody::DropReq {
                    message_number: type_specific,
                    first: SeqNumber::new(r.get_u32()),
                    last: SeqNumber::new(r.get_u32()),
                })
            }
            ControlType::Ack => decode_ack(type_specific, cif),
            ControlType::Nak => Ok(ControlBody::Nak {
                loss: loss_list::decode(cif)?,
            }),
            ControlType::Handshake => Ok(ControlBody::Handshake(Handshake::decode(cif)?)),
            ControlType::UserDefined => Ok(ControlBody::Raw {
                control_type,
                subtype,
                type_specific,
                cif: Bytes::copy_from_slice(cif),
            }),
        }
    }
}

/// Decodes an ACK CIF, choosing light/small/full by its length (spec §3.2.4).
fn decode_ack(ack_number: u32, cif: &[u8]) -> Result<ControlBody, ControlError> {
    let mut r = cif;
    let make = |last_ack_seq, cif| {
        ControlBody::Ack(Ack {
            ack_number,
            last_ack_seq,
            cif,
        })
    };
    match cif.len() {
        4 => Ok(make(SeqNumber::new(r.get_u32()), AckCif::Light)),
        16 => Ok(make(
            SeqNumber::new(r.get_u32()),
            AckCif::Small {
                rtt: r.get_u32(),
                rtt_variance: r.get_u32(),
                avail_buffer_size: r.get_u32(),
            },
        )),
        28 => Ok(make(
            SeqNumber::new(r.get_u32()),
            AckCif::Full {
                rtt: r.get_u32(),
                rtt_variance: r.get_u32(),
                avail_buffer_size: r.get_u32(),
                packets_recv_rate: r.get_u32(),
                estimated_link_capacity: r.get_u32(),
                receiving_rate: r.get_u32(),
            },
        )),
        len => Err(ControlError::InvalidCifLength { kind: "ACK", len }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{ControlPacket, Packet, SocketId};
    use crate::timestamp::Timestamp;

    const FLAG_CONTROL: u32 = 0x8000_0000;

    fn round_trip(body: ControlBody) {
        let pkt = Packet::Control(ControlPacket {
            timestamp: Timestamp::from_micros(123),
            dest_socket_id: SocketId::new(7),
            body,
        });
        let mut buf = BytesMut::new();
        pkt.encode(&mut buf);
        assert_eq!(Packet::decode(&buf).unwrap(), pkt);
    }

    fn seq(v: u32) -> SeqNumber {
        SeqNumber::new(v)
    }

    #[test]
    fn keepalive_round_trips() {
        round_trip(ControlBody::Keepalive);
    }

    #[test]
    fn shutdown_round_trips() {
        round_trip(ControlBody::Shutdown);
    }

    #[test]
    fn congestion_warning_round_trips() {
        round_trip(ControlBody::CongestionWarning);
    }

    #[test]
    fn ackack_round_trips() {
        round_trip(ControlBody::AckAck { ack_number: 99 });
    }

    #[test]
    fn drop_req_round_trips() {
        round_trip(ControlBody::DropReq {
            message_number: 5,
            first: seq(100),
            last: seq(110),
        });
    }

    #[test]
    fn peer_error_round_trips() {
        round_trip(ControlBody::PeerError { error_code: 0xDEAD });
    }

    #[test]
    fn light_ack_round_trips() {
        round_trip(ControlBody::Ack(Ack {
            ack_number: 0,
            last_ack_seq: seq(42),
            cif: AckCif::Light,
        }));
    }

    #[test]
    fn small_ack_round_trips() {
        round_trip(ControlBody::Ack(Ack {
            ack_number: 1,
            last_ack_seq: seq(42),
            cif: AckCif::Small {
                rtt: 100_000,
                rtt_variance: 25_000,
                avail_buffer_size: 8192,
            },
        }));
    }

    #[test]
    fn full_ack_round_trips() {
        round_trip(ControlBody::Ack(Ack {
            ack_number: 7,
            last_ack_seq: seq(1000),
            cif: AckCif::Full {
                rtt: 100_000,
                rtt_variance: 25_000,
                avail_buffer_size: 8192,
                packets_recv_rate: 5000,
                estimated_link_capacity: 6000,
                receiving_rate: 7_000_000,
            },
        }));
    }

    #[test]
    fn empty_nak_round_trips() {
        round_trip(ControlBody::Nak { loss: Vec::new() });
    }

    #[test]
    fn nak_with_ranges_round_trips() {
        round_trip(ControlBody::Nak {
            loss: vec![LossRange::single(seq(3)), LossRange::new(seq(10), seq(20))],
        });
    }

    #[test]
    fn raw_user_defined_round_trips() {
        round_trip(ControlBody::Raw {
            control_type: ControlType::UserDefined,
            subtype: 9,
            type_specific: 0,
            cif: Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]),
        });
    }

    #[test]
    fn handshake_round_trips_through_packet() {
        use crate::handshake::{EncryptionField, Handshake, HandshakeType};

        round_trip(ControlBody::Handshake(Handshake {
            version: 5,
            encryption: EncryptionField::None,
            extension_field: 0x4A17,
            initial_seq: seq(1000),
            mtu: 1500,
            max_flow_window: 8192,
            handshake_type: HandshakeType::INDUCTION,
            srt_socket_id: SocketId::new(0x1234_5678),
            syn_cookie: 0xABCD,
            peer_ip: [0; 16],
            extensions: Vec::new(),
        }));
    }

    #[test]
    fn decode_rejects_ack_with_bad_cif_length() {
        let mut buf = BytesMut::new();
        buf.put_u32(FLAG_CONTROL | (0x0002 << 16)); // ACK
        buf.put_u32(0); // type-specific
        buf.put_u32(0); // timestamp
        buf.put_u32(0); // dest socket id
        buf.put_u32(0); // 8-byte CIF — not a valid ACK length
        buf.put_u32(0);
        assert_eq!(
            Packet::decode(&buf),
            Err(crate::error::PacketError::Control(
                ControlError::InvalidCifLength {
                    kind: "ACK",
                    len: 8
                }
            ))
        );
    }

    #[test]
    fn decode_rejects_drop_req_with_bad_cif_length() {
        let mut buf = BytesMut::new();
        buf.put_u32(FLAG_CONTROL | (0x0007 << 16)); // DROPREQ
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_u32(0);
        buf.put_u32(0); // 4-byte CIF — DROPREQ needs 8
        assert_eq!(
            Packet::decode(&buf),
            Err(crate::error::PacketError::Control(
                ControlError::InvalidCifLength {
                    kind: "drop request",
                    len: 4
                }
            ))
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::packet::{ControlPacket, Packet, SocketId};
    use crate::timestamp::Timestamp;
    use proptest::prelude::*;

    fn any_seq() -> impl Strategy<Value = SeqNumber> {
        (0u32..=0x7FFF_FFFF).prop_map(SeqNumber::new)
    }

    fn any_ack_cif() -> impl Strategy<Value = AckCif> {
        prop_oneof![
            Just(AckCif::Light),
            (any::<u32>(), any::<u32>(), any::<u32>()).prop_map(
                |(rtt, rtt_variance, avail_buffer_size)| {
                    AckCif::Small {
                        rtt,
                        rtt_variance,
                        avail_buffer_size,
                    }
                }
            ),
            (
                any::<u32>(),
                any::<u32>(),
                any::<u32>(),
                any::<u32>(),
                any::<u32>(),
                any::<u32>()
            )
                .prop_map(
                    |(
                        rtt,
                        rtt_variance,
                        avail_buffer_size,
                        packets_recv_rate,
                        estimated_link_capacity,
                        receiving_rate,
                    )| AckCif::Full {
                        rtt,
                        rtt_variance,
                        avail_buffer_size,
                        packets_recv_rate,
                        estimated_link_capacity,
                        receiving_rate,
                    }
                ),
        ]
    }

    fn any_control_body() -> impl Strategy<Value = ControlBody> {
        prop_oneof![
            Just(ControlBody::Keepalive),
            Just(ControlBody::Shutdown),
            Just(ControlBody::CongestionWarning),
            any::<u32>().prop_map(|ack_number| ControlBody::AckAck { ack_number }),
            (any::<u32>(), any_seq(), any_seq()).prop_map(|(message_number, first, last)| {
                ControlBody::DropReq {
                    message_number,
                    first,
                    last,
                }
            }),
            any::<u32>().prop_map(|error_code| ControlBody::PeerError { error_code }),
            (any::<u32>(), any_seq(), any_ack_cif()).prop_map(|(ack_number, last_ack_seq, cif)| {
                ControlBody::Ack(Ack {
                    ack_number,
                    last_ack_seq,
                    cif,
                })
            }),
            prop::collection::vec(
                prop_oneof![
                    any_seq().prop_map(LossRange::single),
                    (any_seq(), any_seq()).prop_map(|(a, b)| LossRange::new(a, b)),
                ],
                0..32,
            )
            .prop_map(|loss| ControlBody::Nak { loss }),
            (
                any::<u16>(),
                any::<u32>(),
                prop::collection::vec(any::<u8>(), 0..128)
            )
                .prop_map(|(subtype, type_specific, cif)| ControlBody::Raw {
                    control_type: ControlType::UserDefined,
                    subtype,
                    type_specific,
                    cif: Bytes::from(cif),
                },),
        ]
    }

    proptest! {
        #[test]
        fn control_body_round_trips(body in any_control_body()) {
            let pkt = Packet::Control(ControlPacket {
                timestamp: Timestamp::from_micros(1),
                dest_socket_id: SocketId::new(2),
                body,
            });
            let mut buf = BytesMut::new();
            pkt.encode(&mut buf);
            let decoded = Packet::decode(&buf).expect("decoding our own encoding must succeed");
            let mut reencoded = BytesMut::new();
            decoded.encode(&mut reencoded);
            prop_assert_eq!(&buf[..], &reencoded[..]);
            prop_assert_eq!(decoded, pkt);
        }
    }
}
