use serde::Serialize;

use crate::ProtocolError;

pub const FRAME_HEADER_BYTES: usize = 4;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// The decoder retains at most one partial frame. Complete frames are returned
/// from `push` immediately and are not counted against this internal limit.
pub const MAX_BUFFERED_BYTES: usize = FRAME_HEADER_BYTES + MAX_FRAME_BYTES;

#[derive(Debug, Eq, PartialEq)]
pub struct FrameDecodeProgress {
    consumed: usize,
    payload: Option<Vec<u8>>,
}

impl FrameDecodeProgress {
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    pub fn into_payload(self) -> Option<Vec<u8>> {
        self.payload
    }
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_BYTES,
        });
    }

    let mut frame = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

#[derive(Debug, Default)]
pub struct FrameDecoder {
    prefix: [u8; FRAME_HEADER_BYTES],
    prefix_len: usize,
    expected_payload_len: Option<usize>,
    payload: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn buffered_len(&self) -> usize {
        self.prefix_len + self.payload.len()
    }

    /// Consumes at most one complete frame from an arbitrary byte-stream
    /// chunk. The caller processes the payload, advances by `consumed`, and
    /// calls again with any remaining bytes. This keeps memory bounded without
    /// making valid streams depend on operating-system read boundaries.
    pub fn push(&mut self, chunk: &[u8]) -> Result<FrameDecodeProgress, ProtocolError> {
        let mut consumed = 0;

        if self.expected_payload_len.is_none() {
            let needed = FRAME_HEADER_BYTES - self.prefix_len;
            let prefix_bytes = needed.min(chunk.len());
            self.prefix[self.prefix_len..self.prefix_len + prefix_bytes]
                .copy_from_slice(&chunk[..prefix_bytes]);
            self.prefix_len += prefix_bytes;
            consumed += prefix_bytes;

            if self.prefix_len < FRAME_HEADER_BYTES {
                return Ok(FrameDecodeProgress {
                    consumed,
                    payload: None,
                });
            }

            let payload_len = read_payload_len(self.prefix)?;
            if payload_len == 0 {
                return Err(ProtocolError::EmptyFrame);
            }
            self.expected_payload_len = Some(payload_len);
            self.payload = Vec::with_capacity(payload_len);
        }

        let expected_payload_len = self
            .expected_payload_len
            .expect("a complete prefix establishes the payload length");
        let remaining = &chunk[consumed..];
        let needed = expected_payload_len - self.payload.len();
        let payload_bytes = needed.min(remaining.len());
        self.payload.extend_from_slice(&remaining[..payload_bytes]);
        consumed += payload_bytes;

        let payload = if self.payload.len() == expected_payload_len {
            let payload = std::mem::take(&mut self.payload);
            self.reset();
            Some(payload)
        } else {
            None
        };

        debug_assert!(self.buffered_len() <= MAX_BUFFERED_BYTES);
        Ok(FrameDecodeProgress { consumed, payload })
    }

    /// Marks the byte stream as closed and rejects an incomplete final frame.
    pub fn finish(self) -> Result<(), ProtocolError> {
        if self.prefix_len == 0 && self.expected_payload_len.is_none() && self.payload.is_empty() {
            return Ok(());
        }

        let expected = self
            .expected_payload_len
            .map_or(FRAME_HEADER_BYTES, |length| FRAME_HEADER_BYTES + length);
        Err(ProtocolError::TruncatedFrame {
            expected,
            actual: self.buffered_len(),
        })
    }

    fn reset(&mut self) {
        self.prefix = [0; FRAME_HEADER_BYTES];
        self.prefix_len = 0;
        self.expected_payload_len = None;
        self.payload.clear();
    }
}

fn read_payload_len(prefix: [u8; FRAME_HEADER_BYTES]) -> Result<usize, ProtocolError> {
    let payload_len = u32::from_be_bytes(prefix) as usize;
    if payload_len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            actual: payload_len,
            maximum: MAX_FRAME_BYTES,
        });
    }
    Ok(payload_len)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn incrementally_decodes_frames_across_arbitrary_boundaries() {
        let first = json!({"message": "line one\nline two"});
        let second = json!({"ok": true});
        let first_frame = encode_frame(&first).expect("first frame");
        let second_frame = encode_frame(&second).expect("second frame");
        let mut decoder = FrameDecoder::new();

        let prefix = decoder.push(&first_frame[..3]).expect("prefix");
        assert_eq!(prefix.consumed(), 3);
        assert!(prefix.payload().is_none());
        let joined = [&first_frame[3..], second_frame.as_slice()].concat();
        let first_progress = decoder.push(&joined).expect("first joined frame");
        let first_consumed = first_progress.consumed();
        let first_payload = first_progress.into_payload().expect("first payload");
        let second_progress = decoder
            .push(&joined[first_consumed..])
            .expect("second joined frame");
        let second_payload = second_progress.into_payload().expect("second payload");
        let values = [first_payload, second_payload]
            .iter()
            .map(|payload| serde_json::from_slice::<Value>(payload).expect("valid JSON"))
            .collect::<Vec<_>>();

        assert_eq!(values, vec![first, second]);
        assert_eq!(decoder.buffered_len(), 0);
    }

    #[test]
    fn finish_rejects_a_truncated_frame() {
        let frame = encode_frame(&json!({"ok": true})).expect("frame should encode");
        let mut decoder = FrameDecoder::new();
        decoder
            .push(&frame[..frame.len() - 1])
            .expect("partial frame");

        assert!(matches!(
            decoder.finish(),
            Err(ProtocolError::TruncatedFrame { .. })
        ));
    }

    #[test]
    fn rejects_empty_frames_without_batching_complete_frames() {
        let mut empty_decoder = FrameDecoder::new();
        assert!(matches!(
            empty_decoder.push(&0_u32.to_be_bytes()),
            Err(ProtocolError::EmptyFrame)
        ));

        let frame = encode_frame(&json!(null)).expect("small frame");
        let batch = frame.repeat(257);
        let mut decoder = FrameDecoder::new();
        let mut remaining = batch.as_slice();
        let mut completed = 0;
        while !remaining.is_empty() {
            let progress = decoder.push(remaining).expect("valid frame batch");
            assert!(progress.consumed() > 0);
            let consumed = progress.consumed();
            completed += usize::from(progress.into_payload().is_some());
            remaining = &remaining[consumed..];
        }
        assert_eq!(completed, 257);
    }
}
