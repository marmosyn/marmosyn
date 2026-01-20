// Copyright (C) 2026 Mikhail Yatsenko <mikhail.yatsenko@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Codec for the binary transport protocol.
//!
//! Implements length-prefixed frame encoding and decoding for the MarmoSyn
//! binary protocol used in sender-to-receiver communication.
//!
//! ## Frame format
//!
//! ```text
//! ┌────────────┬──────────┬─────────────┐
//! │ Length (4B) │ Type (1B)│ Payload (N) │
//! │ u32 BE     │ u8       │ bytes       │
//! └────────────┴──────────┴─────────────┘
//! ```
//!
//! - **Length**: 4-byte big-endian unsigned integer representing the total size
//!   of the Type + Payload (i.e. `1 + N`).
//! - **Type**: 1-byte message type identifier (see [`super::protocol::MessageType`]).
//! - **Payload**: variable-length JSON-serialized payload specific to the message type.
//!
//! ## Usage
//!
//! The [`ProtocolCodec`] implements `tokio_util::codec::Encoder` and `Decoder`,
//! so it can be used with `Framed` streams:
//!
//! ```ignore
//! use tokio_util::codec::Framed;
//! use marmosyn::transport::codec::{ProtocolCodec, Frame};
//!
//! let framed = Framed::new(tcp_stream, ProtocolCodec::new());
//! ```

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::protocol::{MessageType, MAX_FRAME_SIZE};

/// Length of the frame header: 4 bytes for length + 1 byte for message type.
const HEADER_SIZE: usize = 4;

/// Minimum frame body size (just the type byte, no payload).
const MIN_BODY_SIZE: usize = 1;

/// A decoded protocol frame containing the message type and raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The message type identifier.
    pub msg_type: MessageType,
    /// The raw payload bytes (may be empty for messages with no payload).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Creates a new frame with the given message type and payload.
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Creates a new frame with an empty payload.
    pub fn empty(msg_type: MessageType) -> Self {
        Self {
            msg_type,
            payload: Vec::new(),
        }
    }

    /// Creates a frame from a message type and a serializable payload.
    ///
    /// The payload is serialized to JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON serialization fails.
    pub fn from_payload<T: serde::Serialize>(
        msg_type: MessageType,
        payload: &T,
    ) -> Result<Self, CodecError> {
        let bytes = serde_json::to_vec(payload).map_err(|e| CodecError::SerializeError {
            message: format!("failed to serialize payload: {e}"),
        })?;
        Ok(Self::new(msg_type, bytes))
    }

    /// Deserializes the payload into the given type.
    ///
    /// # Errors
    ///
    /// Returns an error if JSON deserialization fails.
    pub fn decode_payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, CodecError> {
        serde_json::from_slice(&self.payload).map_err(|e| CodecError::DeserializeError {
            message: format!("failed to deserialize payload: {e}"),
        })
    }

    /// Returns the total wire size of this frame (header + type + payload).
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + MIN_BODY_SIZE + self.payload.len()
    }
}

/// Errors that can occur during frame encoding or decoding.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The frame body exceeds the maximum allowed size.
    #[error("frame too large: {size} bytes (max: {max})")]
    FrameTooLarge {
        /// Actual frame body size in bytes.
        size: u32,
        /// Maximum allowed body size.
        max: u32,
    },

    /// The frame body is smaller than the minimum required size.
    #[error("frame too small: {size} bytes (min: {min})")]
    FrameTooSmall {
        /// Actual frame body size.
        size: u32,
        /// Minimum required body size.
        min: u32,
    },

    /// An unknown message type byte was encountered.
    #[error("unknown message type: 0x{value:02X}")]
    UnknownMessageType {
        /// The raw byte value that could not be mapped to a [`MessageType`].
        value: u8,
    },

    /// An I/O error occurred during reading or writing.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A serialization error occurred when encoding a payload.
    #[error("serialization error: {message}")]
    SerializeError {
        /// Description of the serialization failure.
        message: String,
    },

    /// A deserialization error occurred when decoding a payload.
    #[error("deserialization error: {message}")]
    DeserializeError {
        /// Description of the deserialization failure.
        message: String,
    },
}

/// Codec for encoding and decoding MarmoSyn protocol frames.
///
/// Implements `tokio_util::codec::Encoder<Frame>` and `tokio_util::codec::Decoder`
/// for use with `Framed` TCP/TLS streams.
///
/// The codec handles length-prefixed frames where:
/// - The first 4 bytes are a big-endian u32 representing the body length.
/// - The body starts with a 1-byte message type identifier.
/// - The remaining bytes are the message payload.
#[derive(Debug, Clone)]
pub struct ProtocolCodec {
    /// Maximum allowed frame body size (type + payload).
    max_frame_size: u32,
}

impl ProtocolCodec {
    /// Creates a new codec with the default maximum frame size.
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Creates a new codec with a custom maximum frame size.
    ///
    /// This is useful for testing or for connections where a smaller
    /// buffer is appropriate.
    pub fn with_max_frame_size(max_frame_size: u32) -> Self {
        Self { max_frame_size }
    }
}

impl Default for ProtocolCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for ProtocolCodec {
    type Item = Frame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, CodecError> {
        // Need at least the length header (4 bytes) to proceed
        if src.len() < HEADER_SIZE {
            return Ok(None);
        }

        // Peek at the length without consuming
        let body_len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);

        // Validate frame size
        if body_len > self.max_frame_size {
            return Err(CodecError::FrameTooLarge {
                size: body_len,
                max: self.max_frame_size,
            });
        }

        if body_len < MIN_BODY_SIZE as u32 {
            return Err(CodecError::FrameTooSmall {
                size: body_len,
                min: MIN_BODY_SIZE as u32,
            });
        }

        let total_frame_size = HEADER_SIZE + body_len as usize;

        // Check if we have the full frame
        if src.len() < total_frame_size {
            // Reserve space for the rest of the frame so the next read
            // has enough room without reallocating.
            src.reserve(total_frame_size - src.len());
            return Ok(None);
        }

        // Consume the length header
        src.advance(HEADER_SIZE);

        // Read the message type byte
        let type_byte = src[0];
        src.advance(1);

        let msg_type = MessageType::from_u8(type_byte)
            .ok_or(CodecError::UnknownMessageType { value: type_byte })?;

        // Read the payload
        let payload_len = body_len as usize - MIN_BODY_SIZE;
        let payload = src.split_to(payload_len).to_vec();

        Ok(Some(Frame::new(msg_type, payload)))
    }
}

impl Encoder<Frame> for ProtocolCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), CodecError> {
        let body_len = (MIN_BODY_SIZE + item.payload.len()) as u32;

        if body_len > self.max_frame_size {
            return Err(CodecError::FrameTooLarge {
                size: body_len,
                max: self.max_frame_size,
            });
        }

        // Reserve space for the entire frame
        dst.reserve(HEADER_SIZE + body_len as usize);

        // Write the length header (big-endian u32)
        dst.put_u32(body_len);

        // Write the message type byte
        dst.put_u8(item.msg_type as u8);

        // Write the payload
        dst.put_slice(&item.payload);

        Ok(())
    }
}

/// Helper: reads a frame from an async reader using the codec.
///
/// This is a convenience function for one-shot reads outside of a `Framed`
/// stream (e.g. during initial handshake before the stream is set up).
pub async fn read_frame<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Frame, CodecError> {
    // Read the 4-byte length header
    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let body_len = u32::from_be_bytes(header);

    if body_len > MAX_FRAME_SIZE {
        return Err(CodecError::FrameTooLarge {
            size: body_len,
            max: MAX_FRAME_SIZE,
        });
    }

    if body_len < MIN_BODY_SIZE as u32 {
        return Err(CodecError::FrameTooSmall {
            size: body_len,
            min: MIN_BODY_SIZE as u32,
        });
    }

    // Read the body
    let mut body = vec![0u8; body_len as usize];
    reader.read_exact(&mut body).await?;

    // Parse message type
    let type_byte = body[0];
    let msg_type = MessageType::from_u8(type_byte)
        .ok_or(CodecError::UnknownMessageType { value: type_byte })?;

    let payload = body[1..].to_vec();

    Ok(Frame::new(msg_type, payload))
}

/// Helper: writes a frame to an async writer.
///
/// This is a convenience function for one-shot writes outside of a `Framed`
/// stream (e.g. during initial handshake).
pub async fn write_frame<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), CodecError> {
    let body_len = (MIN_BODY_SIZE + frame.payload.len()) as u32;

    if body_len > MAX_FRAME_SIZE {
        return Err(CodecError::FrameTooLarge {
            size: body_len,
            max: MAX_FRAME_SIZE,
        });
    }

    // Write the length header
    writer.write_all(&body_len.to_be_bytes()).await?;

    // Write the message type byte
    writer.write_all(&[frame.msg_type as u8]).await?;

    // Write the payload
    writer.write_all(&frame.payload).await?;

    writer.flush().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_codec_encode_decode_empty_payload() {
        let mut codec = ProtocolCodec::new();
        let frame = Frame::empty(MessageType::StatusRequest);

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Should be 4 (length) + 1 (type) = 5 bytes
        assert_eq!(buf.len(), 5);

        // Verify length header is 1 (just the type byte)
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 1);

        // Verify type byte
        assert_eq!(buf[4], MessageType::StatusRequest as u8);

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.msg_type, MessageType::StatusRequest);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_codec_encode_decode_with_payload() {
        let mut codec = ProtocolCodec::new();
        let payload = b"hello world".to_vec();
        let frame = Frame::new(MessageType::Handshake, payload.clone());

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(frame, &mut buf).unwrap();

        // Should be 4 + 1 + 11 = 16 bytes
        assert_eq!(buf.len(), 16);

        // Verify length header is 12 (1 type + 11 payload)
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 12);

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.msg_type, MessageType::Handshake);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_codec_decode_partial_header() {
        let mut codec = ProtocolCodec::new();
        let mut buf = BytesMut::from(&[0x00, 0x00][..]);

        // Not enough data for header — should return None
        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_codec_decode_partial_body() {
        let mut codec = ProtocolCodec::new();

        // Length header says 5 bytes of body, but we only provide 2
        let mut buf = BytesMut::new();
        buf.put_u32(5); // body length
        buf.put_u8(MessageType::Handshake as u8); // type byte
        buf.put_u8(0xAA); // only 1 byte of the expected 4-byte payload

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_codec_decode_frame_too_large() {
        let mut codec = ProtocolCodec::with_max_frame_size(100);

        let mut buf = BytesMut::new();
        buf.put_u32(200); // body length exceeds max
        buf.put_u8(0x01);

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CodecError::FrameTooLarge { .. }));
    }

    #[test]
    fn test_codec_decode_frame_too_small() {
        let mut codec = ProtocolCodec::new();

        let mut buf = BytesMut::new();
        buf.put_u32(0); // zero-length body (not enough for type byte)

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CodecError::FrameTooSmall { .. }));
    }

    #[test]
    fn test_codec_decode_unknown_message_type() {
        let mut codec = ProtocolCodec::new();

        let mut buf = BytesMut::new();
        buf.put_u32(1); // body length = 1 (just type, no payload)
        buf.put_u8(0x42); // unknown type

        let result = codec.decode(&mut buf);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            CodecError::UnknownMessageType { value: 0x42 }
        ));
    }

    #[test]
    fn test_codec_encode_frame_too_large() {
        let mut codec = ProtocolCodec::with_max_frame_size(10);
        let frame = Frame::new(MessageType::PushFile, vec![0u8; 20]);

        let mut buf = BytesMut::new();
        let result = codec.encode(frame, &mut buf);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CodecError::FrameTooLarge { .. }
        ));
    }

    #[test]
    fn test_codec_multiple_frames() {
        let mut codec = ProtocolCodec::new();
        let mut buf = BytesMut::new();

        // Encode two frames back-to-back
        let frame1 = Frame::new(MessageType::Handshake, b"auth-token".to_vec());
        let frame2 = Frame::new(MessageType::HandshakeAck, b"ok".to_vec());

        codec.encode(frame1.clone(), &mut buf).unwrap();
        codec.encode(frame2.clone(), &mut buf).unwrap();

        // Decode them
        let decoded1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded1.msg_type, frame1.msg_type);
        assert_eq!(decoded1.payload, frame1.payload);

        let decoded2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded2.msg_type, frame2.msg_type);
        assert_eq!(decoded2.payload, frame2.payload);

        // No more frames
        let decoded3 = codec.decode(&mut buf).unwrap();
        assert!(decoded3.is_none());
    }

    #[test]
    fn test_frame_from_payload_and_decode() {
        use super::super::protocol::HandshakePayload;

        let handshake = HandshakePayload {
            version: 1,
            auth_token: "test-secret".to_string(),
        };

        let frame = Frame::from_payload(MessageType::Handshake, &handshake).unwrap();
        assert_eq!(frame.msg_type, MessageType::Handshake);
        assert!(!frame.payload.is_empty());

        // Decode back
        let decoded: HandshakePayload = frame.decode_payload().unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.auth_token, "test-secret");
    }

    #[test]
    fn test_frame_decode_payload_wrong_type() {
        use super::super::protocol::HandshakePayload;

        let frame = Frame::new(MessageType::Error, b"not json".to_vec());
        let result: Result<HandshakePayload, _> = frame.decode_payload();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CodecError::DeserializeError { .. }
        ));
    }

    #[test]
    fn test_frame_wire_size() {
        let frame = Frame::new(MessageType::Handshake, vec![0u8; 100]);
        // 4 (header) + 1 (type) + 100 (payload)
        assert_eq!(frame.wire_size(), 105);
    }

    #[test]
    fn test_frame_wire_size_empty() {
        let frame = Frame::empty(MessageType::StatusRequest);
        // 4 (header) + 1 (type) + 0 (payload)
        assert_eq!(frame.wire_size(), 5);
    }

    #[test]
    fn test_codec_default() {
        let codec = ProtocolCodec::default();
        assert_eq!(codec.max_frame_size, MAX_FRAME_SIZE);
    }

    #[test]
    fn test_codec_custom_max_size() {
        let codec = ProtocolCodec::with_max_frame_size(1024);
        assert_eq!(codec.max_frame_size, 1024);
    }

    #[tokio::test]
    async fn test_read_write_frame_async() {
        use super::super::protocol::HandshakePayload;

        let handshake = HandshakePayload {
            version: 1,
            auth_token: "my-token".to_string(),
        };

        let frame = Frame::from_payload(MessageType::Handshake, &handshake).unwrap();

        // Write to an in-memory buffer
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &frame).await.unwrap();

        // Read back
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).await.unwrap();

        assert_eq!(decoded.msg_type, MessageType::Handshake);
        let decoded_payload: HandshakePayload = decoded.decode_payload().unwrap();
        assert_eq!(decoded_payload.version, 1);
        assert_eq!(decoded_payload.auth_token, "my-token");
    }

    #[tokio::test]
    async fn test_read_frame_too_large() {
        // Craft a buffer with a length header that exceeds MAX_FRAME_SIZE
        let mut buf: Vec<u8> = Vec::new();
        let huge_len = MAX_FRAME_SIZE + 1;
        buf.extend_from_slice(&huge_len.to_be_bytes());
        buf.push(0x01); // type byte

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CodecError::FrameTooLarge { .. }
        ));
    }

    #[tokio::test]
    async fn test_read_frame_too_small() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // zero length

        let mut cursor = std::io::Cursor::new(buf);
        let result = read_frame(&mut cursor).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CodecError::FrameTooSmall { .. }
        ));
    }

    #[tokio::test]
    async fn test_write_frame_too_large() {
        let huge_payload = vec![0u8; MAX_FRAME_SIZE as usize + 1];
        let frame = Frame::new(MessageType::PushFile, huge_payload);

        let mut buf: Vec<u8> = Vec::new();
        let result = write_frame(&mut buf, &frame).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CodecError::FrameTooLarge { .. }
        ));
    }

    #[tokio::test]
    async fn test_read_write_empty_payload() {
        let frame = Frame::empty(MessageType::StatusRequest);

        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &frame).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_frame(&mut cursor).await.unwrap();

        assert_eq!(decoded.msg_type, MessageType::StatusRequest);
        assert!(decoded.payload.is_empty());
    }

    #[tokio::test]
    async fn test_read_write_multiple_frames() {
        let frame1 = Frame::new(MessageType::ListRequest, b"path1".to_vec());
        let frame2 = Frame::new(MessageType::DeleteRequest, b"path2".to_vec());

        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &frame1).await.unwrap();
        write_frame(&mut buf, &frame2).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded1 = read_frame(&mut cursor).await.unwrap();
        let decoded2 = read_frame(&mut cursor).await.unwrap();

        assert_eq!(decoded1.msg_type, MessageType::ListRequest);
        assert_eq!(decoded1.payload, b"path1");
        assert_eq!(decoded2.msg_type, MessageType::DeleteRequest);
        assert_eq!(decoded2.payload, b"path2");
    }

    #[test]
    fn test_codec_error_display() {
        let err = CodecError::FrameTooLarge {
            size: 1000,
            max: 100,
        };
        assert!(format!("{err}").contains("1000"));
        assert!(format!("{err}").contains("100"));

        let err = CodecError::UnknownMessageType { value: 0x42 };
        assert!(format!("{err}").contains("0x42"));

        let err = CodecError::SerializeError {
            message: "test error".to_string(),
        };
        assert!(format!("{err}").contains("test error"));
    }

    #[test]
    fn test_frame_equality() {
        let frame1 = Frame::new(MessageType::Handshake, b"data".to_vec());
        let frame2 = Frame::new(MessageType::Handshake, b"data".to_vec());
        let frame3 = Frame::new(MessageType::HandshakeAck, b"data".to_vec());
        let frame4 = Frame::new(MessageType::Handshake, b"other".to_vec());

        assert_eq!(frame1, frame2);
        assert_ne!(frame1, frame3);
        assert_ne!(frame1, frame4);
    }

    #[test]
    fn test_frame_clone() {
        let frame = Frame::new(MessageType::PushFile, b"file data".to_vec());
        let cloned = frame.clone();
        assert_eq!(frame, cloned);
    }

    #[test]
    fn test_frame_debug() {
        let frame = Frame::empty(MessageType::Error);
        let debug = format!("{frame:?}");
        assert!(debug.contains("Error"));
    }

    #[test]
    fn test_all_message_types_roundtrip_through_codec() {
        let types = [
            MessageType::Handshake,
            MessageType::HandshakeAck,
            MessageType::ResolveAlias,
            MessageType::ResolveAck,
            MessageType::ListRequest,
            MessageType::ListResponse,
            MessageType::ChecksumReq,
            MessageType::ChecksumResp,
            MessageType::PushFile,
            MessageType::PushAck,
            MessageType::DeleteRequest,
            MessageType::DeleteAck,
            MessageType::StatusRequest,
            MessageType::StatusResp,
            MessageType::Error,
        ];

        let mut codec = ProtocolCodec::new();

        for msg_type in types {
            let frame = Frame::new(msg_type, b"test-payload".to_vec());
            let mut buf = BytesMut::new();
            codec.encode(frame.clone(), &mut buf).unwrap();

            let decoded = codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(
                decoded.msg_type, msg_type,
                "roundtrip failed for {:?}",
                msg_type
            );
            assert_eq!(decoded.payload, b"test-payload");
        }
    }
}
