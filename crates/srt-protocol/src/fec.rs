//! Forward Error Correction — XOR packet filter (SMPTE 2022-1, libsrt's FEC).
//!
//! FEC trades bandwidth for latency: the sender groups data packets and emits a
//! **parity** packet that is the byte-wise XOR of the group (its lengths, flags,
//! timestamps, and zero-padded payloads, per `srtgo`/libsrt's *clip*
//! construction). If a single packet of a group is lost, the receiver rebuilds it
//! by XOR-ing the parity with the packets it *did* receive — no retransmission,
//! no round-trip.
//!
//! This module holds both the **recovery algorithm** — a row [`FecEncoder`] (one
//! parity per `group_size` consecutive packets) and [`recover_row`], which
//! rebuilds the one missing member of a group — and the **wire engine** that
//! drives it on the live data path: [`FecParity::encode`]/[`decode_parity`] for the
//! on-wire packet format and a stateful [`FecReceiver`] that observes incoming data
//! and parity packets and rebuilds losses. [`Connection`](crate::connection::Connection)
//! wires these in (sender emits parity packets, receiver re-injects recoveries).
//! Everything is pure and deterministic, unit-tested against the XOR invariants.
//!
//! **v1 scope:** *row* FEC only. Column/staircase layouts, handshake negotiation of
//! the filter config (both peers configure it out of band for now), and libsrt
//! interop are future work. FEC is incompatible with AES-GCM — the XOR clip breaks
//! the per-packet auth tag — so it pairs with plaintext or AES-CTR.
//!
//! Clip layout (cross-checked vs `srtgo` `fecGroup.clipData`): for each member the
//! accumulator XORs the 16-bit payload **length**, the 8-bit encryption **flags**,
//! the 32-bit **timestamp**, and the payload bytes (short payloads zero-padded to
//! `payload_size`).
//!
//! **Wire format** (libsrt-compatible, cross-checked vs `srtgo`
//! `FECSender.emitFEC` / `Conn.handleFECPacket`): a parity packet rides on the wire
//! as an ordinary SRT *data* packet, distinguished only by a **message number of
//! `0`** (real data starts at `1`). It *shares* the sequence number of the last
//! data packet in its group (consuming no new number), is never encrypted, and
//! carries `[index(1)][flag_clip(1)][length_clip(2, BE)][payload_clip…]` as its
//! payload — the `timestamp_clip` travels in the packet's own timestamp field. The
//! `index` byte is `-1` for a row group (the only layout built here).

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::seq::SeqNumber;

/// Row-group marker stored in the wire header's `index` byte (libsrt convention).
pub(crate) const ROW_INDEX: i8 = -1;

/// On-wire FEC payload header size: `index(1) + flag_clip(1) + length_clip(2)`.
pub(crate) const FEC_HEADER: usize = 4;

/// Retained groups of receive history: parities and data older than this many
/// groups behind the newest are evicted, bounding memory on a long stream.
const RCV_HISTORY_GROUPS: usize = 8;

/// One packet's FEC-relevant fields. `payload` is the (decrypted-length) payload;
/// it is zero-padded to the group's `payload_size` when clipped.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FecData<'a> {
    /// The payload length on the wire (clipped as a 16-bit value).
    pub(crate) length: u16,
    /// The packet's encryption key flags (even/odd/none).
    pub(crate) flags: u8,
    /// The packet's timestamp.
    pub(crate) timestamp: u32,
    /// The payload bytes.
    pub(crate) payload: &'a [u8],
}

/// A parity packet's clipped contents — the XOR of a group's members.
// The `_clip` suffix is the whole point (each field is a running XOR, a "clip"
// in libsrt's vocabulary), so the same-suffix lint is noise here.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FecParity {
    /// XOR of the members' payload lengths.
    pub(crate) length_clip: u16,
    /// XOR of the members' encryption flags.
    pub(crate) flag_clip: u8,
    /// XOR of the members' timestamps.
    pub(crate) timestamp_clip: u32,
    /// XOR of the members' zero-padded payloads (`payload_size` bytes).
    pub(crate) payload_clip: Vec<u8>,
}

/// A packet rebuilt from a parity and the surviving members of its group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Recovered {
    /// The recovered payload length.
    pub(crate) length: u16,
    /// The recovered encryption flags.
    pub(crate) flags: u8,
    /// The recovered timestamp.
    pub(crate) timestamp: u32,
    /// The recovered payload (trimmed to `length`).
    pub(crate) payload: Vec<u8>,
}

/// The running XOR accumulator for one FEC group.
#[derive(Debug, Clone)]
struct Clip {
    length: u16,
    flags: u8,
    timestamp: u32,
    payload: Vec<u8>,
}

impl Clip {
    fn new(payload_size: usize) -> Self {
        Clip {
            length: 0,
            flags: 0,
            timestamp: 0,
            payload: vec![0u8; payload_size],
        }
    }

    /// XORs one packet into the accumulator (short payloads zero-pad).
    fn add(&mut self, data: FecData<'_>) {
        self.length ^= data.length;
        self.flags ^= data.flags;
        self.timestamp ^= data.timestamp;
        for (slot, byte) in self.payload.iter_mut().zip(data.payload) {
            *slot ^= byte;
        }
    }

    fn parity(&self) -> FecParity {
        FecParity {
            length_clip: self.length,
            flag_clip: self.flags,
            timestamp_clip: self.timestamp,
            payload_clip: self.payload.clone(),
        }
    }

    fn reset(&mut self) {
        self.length = 0;
        self.flags = 0;
        self.timestamp = 0;
        self.payload.iter_mut().for_each(|b| *b = 0);
    }
}

/// Generates one row-parity packet per `group_size` consecutive data packets.
#[derive(Debug, Clone)]
pub(crate) struct FecEncoder {
    group_size: usize,
    clip: Clip,
    collected: usize,
}

impl FecEncoder {
    /// A row encoder grouping `group_size` packets, each clipped to `payload_size`
    /// bytes. `group_size` must be at least 2 for FEC to be meaningful.
    pub(crate) fn new(group_size: usize, payload_size: usize) -> Self {
        FecEncoder {
            group_size: group_size.max(2),
            clip: Clip::new(payload_size),
            collected: 0,
        }
    }

    /// Clips one data packet. Returns the group's parity once the group is full
    /// (after which the next packet starts a fresh group).
    pub(crate) fn feed(&mut self, data: FecData<'_>) -> Option<FecParity> {
        self.clip.add(data);
        self.collected += 1;
        if self.collected == self.group_size {
            let parity = self.clip.parity();
            self.clip.reset();
            self.collected = 0;
            Some(parity)
        } else {
            None
        }
    }
}

/// Recovers the single missing member of a completed row group from its parity
/// and the members that survived.
///
/// Returns `None` unless **exactly one** member is missing (`present.len() ==
/// group_size - 1`): XOR cannot rebuild two unknowns. The recovered payload is
/// trimmed to its recovered length.
pub(crate) fn recover_row(
    group_size: usize,
    payload_size: usize,
    parity: &FecParity,
    present: &[FecData<'_>],
) -> Option<Recovered> {
    if present.len() != group_size.saturating_sub(1) {
        return None; // zero or more than one missing: unrecoverable
    }
    // Start from the parity, XOR out every surviving member; the residual is the
    // missing packet.
    let mut clip = Clip {
        length: parity.length_clip,
        flags: parity.flag_clip,
        timestamp: parity.timestamp_clip,
        payload: {
            let mut p = parity.payload_clip.clone();
            p.resize(payload_size, 0);
            p
        },
    };
    for data in present {
        clip.add(*data);
    }
    let length = usize::from(clip.length).min(payload_size);
    clip.payload.truncate(length);
    Some(Recovered {
        length: clip.length,
        flags: clip.flags,
        timestamp: clip.timestamp,
        payload: clip.payload,
    })
}

impl FecParity {
    /// Encodes the parity's wire payload: `[index][flag_clip][length_clip BE]
    /// [payload_clip…]`. The `timestamp_clip` is *not* here — it rides in the FEC
    /// packet's own timestamp field (libsrt layout).
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // group_index is a small signed marker; the
    // byte is reinterpreted verbatim and read back via `as i8` on decode.
    pub(crate) fn encode(&self, group_index: i8) -> Vec<u8> {
        let mut out = Vec::with_capacity(FEC_HEADER + self.payload_clip.len());
        out.push(group_index as u8);
        out.push(self.flag_clip);
        out.extend_from_slice(&self.length_clip.to_be_bytes());
        out.extend_from_slice(&self.payload_clip);
        out
    }
}

/// Parses an FEC packet's wire payload into its group index and clipped contents,
/// pairing it with the `timestamp_clip` carried in the packet's timestamp field.
/// Returns `None` if the payload is too short to hold the 4-byte header.
#[must_use]
#[allow(clippy::cast_possible_wrap)] // index byte is a signed marker by design.
pub(crate) fn decode_parity(payload: &[u8], timestamp_clip: u32) -> Option<(i8, FecParity)> {
    if payload.len() < FEC_HEADER {
        return None;
    }
    let group_index = payload[0] as i8;
    let flag_clip = payload[1];
    let length_clip = u16::from_be_bytes([payload[2], payload[3]]);
    let payload_clip = payload[FEC_HEADER..].to_vec();
    Some((
        group_index,
        FecParity {
            length_clip,
            flag_clip,
            timestamp_clip,
            payload_clip,
        },
    ))
}

/// A packet rebuilt by the receiver's FEC engine, ready to be re-injected into the
/// receive path. Its `payload` is the *wire* (still-encrypted, if the stream is
/// encrypted) payload, and `flags`/`timestamp` are the recovered header fields —
/// exactly as the lost packet would have arrived. The message number and packet
/// position are *not* recoverable by XOR (they are not clipped), so the caller
/// reconstructs them as a solo message (matching libsrt; FEC targets live mode,
/// where each packet is one whole message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredPacket {
    /// The sequence number of the recovered (formerly missing) packet.
    pub(crate) seq: SeqNumber,
    /// The recovered timestamp.
    pub(crate) timestamp: u32,
    /// The recovered encryption key flag (`KK`), as a wire bit pattern.
    pub(crate) flags: u8,
    /// The recovered wire payload.
    pub(crate) payload: Bytes,
}

/// One stored data member of a group: the fields FEC clips, kept by sequence
/// number so a parity can rebuild a missing sibling.
#[derive(Debug, Clone)]
struct StoredData {
    length: u16,
    flags: u8,
    timestamp: u32,
    payload: Bytes,
}

/// The receiver-side row-FEC engine: it observes every incoming data packet and
/// every parity packet, and rebuilds the single missing member of any group as
/// soon as exactly one is outstanding and its parity has arrived.
///
/// **Alignment-free.** A row parity rides on the last data sequence number of its
/// group, so a parity at `fec_seq` covers exactly `[fec_seq - (G-1), fec_seq]` —
/// the engine never needs to know the sender's initial sequence number or any
/// matrix geometry, only the configured `group_size`. Recovery is attempted both
/// when a parity arrives (the common case) and when a late data packet arrives
/// after its parity (the reorder case).
#[derive(Debug)]
pub(crate) struct FecReceiver {
    group_size: usize,
    payload_size: usize,
    /// Recent data members, keyed by `SeqNumber::value()`.
    data: BTreeMap<u32, StoredData>,
    /// Parities awaiting recovery, keyed by their group's base `SeqNumber::value()`.
    parities: BTreeMap<u32, FecParity>,
}

impl FecReceiver {
    /// A row decoder for groups of `group_size` packets clipped to `payload_size`
    /// bytes. `group_size` is floored at 2 (a 1-packet group has no redundancy).
    #[must_use]
    pub(crate) fn new(group_size: usize, payload_size: usize) -> Self {
        FecReceiver {
            group_size: group_size.max(2),
            payload_size,
            data: BTreeMap::new(),
            parities: BTreeMap::new(),
        }
    }

    /// Observes a received data packet (its *wire* payload and clipped fields).
    /// Returns any packets this arrival lets the engine recover — normally none,
    /// but a data packet completing a group whose parity already arrived (reorder)
    /// can trigger a rebuild.
    pub(crate) fn observe_data(
        &mut self,
        seq: SeqNumber,
        length: u16,
        flags: u8,
        timestamp: u32,
        payload: Bytes,
    ) -> Vec<RecoveredPacket> {
        self.data.insert(
            seq.value(),
            StoredData {
                length,
                flags,
                timestamp,
                payload,
            },
        );
        // The groups that could contain `seq` are those based at `seq - off` for
        // `off` in `0..group_size`; retry each parity we already hold for one.
        let mut recovered = Vec::new();
        let mut base = seq;
        for _ in 0..self.group_size {
            self.try_group(base, &mut recovered);
            base = base.prev();
        }
        self.evict(seq);
        recovered
    }

    /// Observes a received parity packet: `fec_seq` is its (shared) sequence
    /// number, `payload` its wire payload, and `timestamp_clip` the packet's
    /// timestamp. Ignores non-row parities (only row FEC is built). Returns the
    /// recovered packet if this parity completes a group with one missing member.
    pub(crate) fn observe_parity(
        &mut self,
        fec_seq: SeqNumber,
        payload: &[u8],
        timestamp_clip: u32,
    ) -> Vec<RecoveredPacket> {
        let Some((index, parity)) = decode_parity(payload, timestamp_clip) else {
            return Vec::new();
        };
        if index != ROW_INDEX {
            return Vec::new(); // column/staircase parities: future work
        }
        // The group spans the G sequence numbers ending at this parity's own seq.
        let mut base = fec_seq;
        for _ in 0..self.group_size - 1 {
            base = base.prev();
        }
        self.parities.insert(base.value(), parity);
        let mut recovered = Vec::new();
        self.try_group(base, &mut recovered);
        self.evict(fec_seq);
        recovered
    }

    /// Attempts to rebuild the missing member of the group based at `base`, given a
    /// parity is held for it. On success, pushes the recovered packet, removes the
    /// consumed parity, and stores the rebuilt packet as a data member (so it can
    /// satisfy nothing twice but is visible to later bookkeeping).
    fn try_group(&mut self, base: SeqNumber, out: &mut Vec<RecoveredPacket>) {
        let Some(parity) = self.parities.get(&base.value()) else {
            return;
        };
        let mut present: Vec<FecData<'_>> = Vec::with_capacity(self.group_size - 1);
        let mut missing: Option<SeqNumber> = None;
        let mut seq = base;
        for _ in 0..self.group_size {
            if let Some(d) = self.data.get(&seq.value()) {
                present.push(FecData {
                    length: d.length,
                    flags: d.flags,
                    timestamp: d.timestamp,
                    payload: &d.payload,
                });
            } else if missing.replace(seq).is_some() {
                return; // two or more missing: XOR cannot solve it
            }
            seq = seq.next();
        }
        let Some(missing) = missing else {
            return; // nothing missing: parity is pure redundancy here
        };
        let Some(rec) = recover_row(self.group_size, self.payload_size, parity, &present) else {
            return;
        };
        let payload = Bytes::from(rec.payload);
        self.parities.remove(&base.value());
        self.data.insert(
            missing.value(),
            StoredData {
                length: rec.length,
                flags: rec.flags,
                timestamp: rec.timestamp,
                payload: payload.clone(),
            },
        );
        out.push(RecoveredPacket {
            seq: missing,
            timestamp: rec.timestamp,
            flags: rec.flags,
            payload,
        });
    }

    /// Drops data and parities more than [`RCV_HISTORY_GROUPS`] groups behind the
    /// newest sequence number seen, bounding memory on a long-running stream.
    fn evict(&mut self, newest: SeqNumber) {
        // `offset_from` is how far `newest` is ahead of an entry: positive for past
        // sequence numbers, negative (so always kept) for any that are still ahead.
        let window = i32::try_from(self.group_size * RCV_HISTORY_GROUPS).unwrap_or(i32::MAX);
        self.data
            .retain(|&seq, _| newest.offset_from(SeqNumber::new(seq)) < window);
        self.parities
            .retain(|&seq, _| newest.offset_from(SeqNumber::new(seq)) < window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(length: u16, flags: u8, timestamp: u32, payload: &[u8]) -> FecData<'_> {
        FecData {
            length,
            flags,
            timestamp,
            payload,
        }
    }

    #[test]
    fn encoder_emits_one_parity_per_group() {
        let mut enc = FecEncoder::new(3, 8);
        assert!(enc.feed(data(4, 0, 1, b"aaaa")).is_none());
        assert!(enc.feed(data(4, 0, 2, b"bbbb")).is_none());
        let parity = enc
            .feed(data(4, 0, 3, b"cccc"))
            .expect("group of 3 emits parity");
        // length_clip = 4^4^4 = 4; timestamp_clip = 1^2^3 = 0.
        assert_eq!(parity.length_clip, 4);
        assert_eq!(parity.timestamp_clip, 0);
        assert_eq!(parity.payload_clip.len(), 8, "padded to payload_size");
        // The next packet starts a fresh group (no immediate parity).
        assert!(enc.feed(data(4, 0, 4, b"dddd")).is_none());
    }

    #[test]
    fn recovers_a_single_lost_packet() {
        let payload_size = 8;
        let mut enc = FecEncoder::new(4, payload_size);
        let group = [
            (10u16, 1u8, 100u32, b"hello".as_slice()),
            (8, 1, 200, b"world!!!"),
            (3, 0, 300, b"hey"),
            (6, 2, 400, b"frame!"),
        ];
        let mut parity = None;
        for &(l, f, t, p) in &group {
            parity = enc.feed(data(l, f, t, p)).or(parity);
        }
        let parity = parity.expect("parity after the 4th packet");

        // Drop member index 2 ("hey"); the other three survive.
        let present: Vec<FecData> = [0usize, 1, 3]
            .iter()
            .map(|&i| {
                let (l, f, t, p) = group[i];
                data(l, f, t, p)
            })
            .collect();

        let recovered =
            recover_row(4, payload_size, &parity, &present).expect("one missing => recoverable");
        assert_eq!(recovered.length, 3);
        assert_eq!(recovered.flags, 0);
        assert_eq!(recovered.timestamp, 300);
        assert_eq!(&recovered.payload, b"hey", "exact payload rebuilt");
    }

    #[test]
    fn cannot_recover_two_losses() {
        let mut enc = FecEncoder::new(3, 8);
        let group = [
            (4u16, 0u8, 1u32, b"aaaa".as_slice()),
            (4, 0, 2, b"bbbb"),
            (4, 0, 3, b"cccc"),
        ];
        let mut parity = None;
        for &(l, f, t, p) in &group {
            parity = enc.feed(data(l, f, t, p)).or(parity);
        }
        let parity = parity.unwrap();
        // Only one survivor (two missing) — XOR cannot solve two unknowns.
        let present = [data(4, 0, 1, b"aaaa")];
        assert!(recover_row(3, 8, &parity, &present).is_none());
    }

    #[test]
    fn no_recovery_when_nothing_is_missing() {
        let mut enc = FecEncoder::new(2, 4);
        enc.feed(data(4, 0, 1, b"aaaa"));
        let parity = enc.feed(data(4, 0, 2, b"bbbb")).unwrap();
        let present = [data(4, 0, 1, b"aaaa"), data(4, 0, 2, b"bbbb")];
        assert!(
            recover_row(2, 4, &parity, &present).is_none(),
            "all present: nothing to rebuild"
        );
    }

    #[test]
    fn parity_round_trips_on_the_wire() {
        let mut enc = FecEncoder::new(3, 8);
        enc.feed(data(4, 1, 10, b"aaaa"));
        enc.feed(data(4, 1, 20, b"bbbb"));
        let parity = enc.feed(data(4, 1, 30, b"cccc")).unwrap();

        let wire = parity.encode(ROW_INDEX);
        assert_eq!(wire.len(), FEC_HEADER + 8, "header + padded payload clip");
        let (index, decoded) = decode_parity(&wire, parity.timestamp_clip).unwrap();
        assert_eq!(index, ROW_INDEX);
        assert_eq!(decoded, parity, "every clip field survives the round trip");
    }

    #[test]
    fn decode_parity_rejects_a_short_header() {
        assert!(decode_parity(&[0, 1, 2], 0).is_none(), "3 < FEC_HEADER");
    }

    /// Builds the wire parity for a row group of `members`, returning the bytes and
    /// the `timestamp_clip` that rides in the FEC packet's timestamp field.
    fn row_parity(members: &[(u16, u8, u32, &[u8])], payload_size: usize) -> (Vec<u8>, u32) {
        let mut enc = FecEncoder::new(members.len(), payload_size);
        let mut parity = None;
        for &(l, f, t, p) in members {
            parity = enc.feed(data(l, f, t, p)).or(parity);
        }
        let parity = parity.expect("a full group emits a parity");
        (parity.encode(ROW_INDEX), parity.timestamp_clip)
    }

    #[test]
    fn receiver_recovers_a_lost_packet_from_its_parity() {
        let psize = 8;
        let members: [(u16, u8, u32, &[u8]); 3] =
            [(4, 0, 10, b"aaaa"), (3, 0, 20, b"hey"), (4, 0, 30, b"cccc")];
        let (wire, ts_clip) = row_parity(&members, psize);

        let mut rx = FecReceiver::new(3, psize);
        // Data packets occupy seqs 100, 101, 102; #101 ("hey") is lost.
        let base = SeqNumber::new(100);
        for (i, &(l, f, t, p)) in members.iter().enumerate() {
            if i == 1 {
                continue; // dropped on the wire
            }
            let r = rx.observe_data(
                base + u32::try_from(i).unwrap(),
                l,
                f,
                t,
                Bytes::copy_from_slice(p),
            );
            assert!(r.is_empty(), "no recovery before the parity arrives");
        }
        // Parity rides on the last data seq (102).
        let recovered = rx.observe_parity(base + 2, &wire, ts_clip);
        assert_eq!(recovered.len(), 1, "the one lost packet is rebuilt");
        let rp = &recovered[0];
        assert_eq!(rp.seq, base + 1);
        assert_eq!(rp.timestamp, 20);
        assert_eq!(rp.flags, 0);
        assert_eq!(&rp.payload[..], b"hey", "exact wire payload rebuilt");
    }

    #[test]
    fn receiver_recovers_when_data_arrives_after_its_parity() {
        // Reorder: the parity is processed before the surviving members, so the
        // group is still incomplete when it lands; a later data packet completes it.
        let psize = 8;
        let members: [(u16, u8, u32, &[u8]); 3] = [
            (4, 0, 10, b"aaaa"),
            (4, 0, 20, b"bbbb"),
            (4, 0, 30, b"cccc"),
        ];
        let (wire, ts_clip) = row_parity(&members, psize);
        let base = SeqNumber::new(500);

        let mut rx = FecReceiver::new(3, psize);
        // #500 lost; parity arrives with only #501 seen so far -> 2 missing, no fix.
        let r = rx.observe_data(base + 1, 4, 0, 20, Bytes::from_static(b"bbbb"));
        assert!(r.is_empty());
        let r = rx.observe_parity(base + 2, &wire, ts_clip);
        assert!(r.is_empty(), "two still missing when the parity lands");
        // The straggler #502 arrives, leaving exactly one hole (#500) -> recover.
        let recovered = rx.observe_data(base + 2, 4, 0, 30, Bytes::from_static(b"cccc"));
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].seq, base);
        assert_eq!(&recovered[0].payload[..], b"aaaa");
    }

    #[test]
    fn receiver_cannot_recover_two_losses() {
        let psize = 8;
        let members: [(u16, u8, u32, &[u8]); 3] =
            [(4, 0, 1, b"aaaa"), (4, 0, 2, b"bbbb"), (4, 0, 3, b"cccc")];
        let (wire, ts_clip) = row_parity(&members, psize);
        let base = SeqNumber::new(7);

        let mut rx = FecReceiver::new(3, psize);
        // Only #7 survives; #8 and #9 are both lost.
        rx.observe_data(base, 4, 0, 1, Bytes::from_static(b"aaaa"));
        let recovered = rx.observe_parity(base + 2, &wire, ts_clip);
        assert!(recovered.is_empty(), "XOR cannot solve two unknowns");
    }

    #[test]
    fn receiver_ignores_a_column_parity() {
        let psize = 8;
        let mut enc = FecEncoder::new(2, psize);
        enc.feed(data(4, 0, 1, b"aaaa"));
        let parity = enc.feed(data(4, 0, 2, b"bbbb")).unwrap();
        let column_wire = parity.encode(0); // index 0 = a column group, not row

        let mut rx = FecReceiver::new(2, psize);
        rx.observe_data(SeqNumber::new(1), 4, 0, 1, Bytes::from_static(b"aaaa"));
        let recovered = rx.observe_parity(SeqNumber::new(2), &column_wire, parity.timestamp_clip);
        assert!(recovered.is_empty(), "only row FEC is decoded in v1");
    }
}
