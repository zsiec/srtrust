//! Pure helpers for UDP batching (GSO send / GRO receive).
//!
//! These hold the *logic* — how to group outgoing datagrams into segmentation
//! batches and how to split a coalesced receive back into datagrams — separate
//! from the syscalls, so it is unit-testable on any platform (the kernel offloads
//! themselves are Linux-only; see [`crate::runtime`]).

use bytes::Bytes;

/// Groups consecutive datagrams into Generic Segmentation Offload (GSO) batches:
/// each yielded slice is a run of **equal-length** datagrams, at most
/// `max_segments` long. A length change ends the current batch (GSO transmits a
/// run of one segment size). With `max_segments <= 1` every datagram is its own
/// batch — the no-offload path.
pub(crate) fn gso_batches(
    datagrams: &[Bytes],
    max_segments: usize,
) -> impl Iterator<Item = &[Bytes]> {
    let cap = max_segments.max(1);
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= datagrams.len() {
            return None;
        }
        let seg_len = datagrams[start].len();
        let mut end = start + 1;
        while end < datagrams.len() && end - start < cap && datagrams[end].len() == seg_len {
            end += 1;
        }
        let batch = &datagrams[start..end];
        start = end;
        Some(batch)
    })
}

/// Splits a received buffer that may hold several GRO-coalesced datagrams into the
/// individual datagrams. `total` bytes are valid; each datagram is `stride` bytes
/// except possibly a shorter final one. A `stride` of 0 or `>= total` yields the
/// whole thing as a single datagram (the no-offload path). An empty receive
/// yields nothing.
pub(crate) fn gro_split(buf: &[u8], total: usize, stride: usize) -> impl Iterator<Item = &[u8]> {
    let total = total.min(buf.len());
    let step = if stride == 0 || stride > total {
        total
    } else {
        stride
    };
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= total {
            return None;
        }
        let end = (start + step).min(total);
        let segment = &buf[start..end];
        start = end;
        Some(segment)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dg(len: usize, tag: u8) -> Bytes {
        Bytes::from(vec![tag; len])
    }

    #[test]
    fn gso_groups_equal_length_runs() {
        let datagrams = [
            dg(1316, 0),
            dg(1316, 1),
            dg(1316, 2),
            dg(40, 3),
            dg(1316, 4),
        ];
        let batches: Vec<usize> = gso_batches(&datagrams, 8).map(<[Bytes]>::len).collect();
        // Three equal 1316s, then a lone 40, then a lone 1316.
        assert_eq!(batches, vec![3, 1, 1]);
    }

    #[test]
    fn gso_caps_each_batch_at_max_segments() {
        let datagrams: Vec<Bytes> = (0..10).map(|i| dg(1200, i)).collect();
        let sizes: Vec<usize> = gso_batches(&datagrams, 4).map(<[Bytes]>::len).collect();
        assert_eq!(sizes, vec![4, 4, 2], "batches are capped at 4");
    }

    #[test]
    fn gso_with_no_offload_emits_singletons() {
        let datagrams = [dg(1316, 0), dg(1316, 1), dg(1316, 2)];
        let sizes: Vec<usize> = gso_batches(&datagrams, 1).map(<[Bytes]>::len).collect();
        assert_eq!(sizes, vec![1, 1, 1]);
        // max 0 is treated as 1.
        let sizes0: Vec<usize> = gso_batches(&datagrams, 0).map(<[Bytes]>::len).collect();
        assert_eq!(sizes0, vec![1, 1, 1]);
    }

    #[test]
    fn gso_empty_input_yields_nothing() {
        assert_eq!(gso_batches(&[], 8).count(), 0);
    }

    #[test]
    fn gro_splits_a_coalesced_buffer() {
        // Three 4-byte datagrams coalesced into 12 bytes, stride 4.
        let buf = [1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3];
        let segs: Vec<&[u8]> = gro_split(&buf, 12, 4).collect();
        assert_eq!(segs, vec![&[1, 1, 1, 1], &[2, 2, 2, 2], &[3, 3, 3, 3]]);
    }

    #[test]
    fn gro_handles_a_short_final_segment() {
        // 10 bytes, stride 4 => 4 + 4 + 2.
        let buf = [0u8; 10];
        let lens: Vec<usize> = gro_split(&buf, 10, 4).map(<[u8]>::len).collect();
        assert_eq!(lens, vec![4, 4, 2]);
    }

    #[test]
    fn gro_no_offload_is_a_single_datagram() {
        let buf = [7u8; 1316];
        // stride 0 (no GRO) or stride >= total both yield one datagram.
        assert_eq!(gro_split(&buf, 1316, 0).count(), 1);
        assert_eq!(gro_split(&buf, 1316, 1316).count(), 1);
        assert_eq!(gro_split(&buf, 1316, 9999).count(), 1);
        assert_eq!(gro_split(&buf, 1316, 0).next().unwrap().len(), 1316);
    }

    #[test]
    fn gro_empty_receive_yields_nothing() {
        assert_eq!(gro_split(&[0u8; 100], 0, 1316).count(), 0);
    }
}
