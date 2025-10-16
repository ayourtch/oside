use crate::*;
use serde::{Deserialize, Serialize};

// WireGuard uses UDP port 51820 by default
// WireGuard protocol specification: https://www.wireguard.com/papers/wireguard.pdf

/// WireGuard Message Type identifier
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WgMessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
    WgArbitrary(u8)
}

impl Encode for WgMessageType {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let val: u8 = match self {
          WgMessageType::HandshakeInitiation => 1,
          WgMessageType::HandshakeResponse => 2,
          WgMessageType::CookieReply => 3,
          WgMessageType::TransportData => 4,
          WgMessageType::WgArbitrary(x) => *x,
        };
        val.encode::<E>()
    }
}

impl Decode for WgMessageType {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (val, size) = u8::decode::<D>(buf)?;
        let msg_type = match val {
            1 => WgMessageType::HandshakeInitiation,
            2 => WgMessageType::HandshakeResponse,
            3 => WgMessageType::CookieReply,
            4 => WgMessageType::TransportData,
            x => WgMessageType::WgArbitrary(x),
        };
        Some((msg_type, size))
    }
}

/// WireGuard Message Container (dispatches to specific message types)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 51820))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 51820))]
pub struct WgMessage {
    #[nproto(next: WIREGUARD_MESSAGE_TYPES => MessageType)]
    pub message_type: Value<u8>,

    #[nproto(default = 0, encode = encode_reserved_3bytes, decode = decode_reserved_3bytes)]
    pub reserved_zero: Value<u32>, // 3 bytes, but using u32 for convenience
}

/// WireGuard Handshake Initiation Message (Type 1)
/// Total size: 148 bytes (including 4-byte header in WgMessage)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(WIREGUARD_MESSAGE_TYPES, MessageType = 1))]
pub struct WgHandshakeInit {
    pub sender_index: Value<u32>,

    #[nproto(encode = encode_wg_32bytes, decode = decode_wg_32bytes)]
    pub unencrypted_ephemeral: Vec<u8>, // 32 bytes

    #[nproto(encode = encode_wg_48bytes, decode = decode_wg_48bytes)]
    pub encrypted_static: Vec<u8>, // 48 bytes (32 + 16 AEAD)

    #[nproto(encode = encode_wg_28bytes, decode = decode_wg_28bytes)]
    pub encrypted_timestamp: Vec<u8>, // 28 bytes (12 + 16 AEAD)

    #[nproto(encode = encode_wg_16bytes, decode = decode_wg_16bytes)]
    pub mac1: Vec<u8>, // 16 bytes

    #[nproto(encode = encode_wg_16bytes, decode = decode_wg_16bytes)]
    pub mac2: Vec<u8>, // 16 bytes
}

/// WireGuard Handshake Response Message (Type 2)
/// Total size: 92 bytes (including 4-byte header in WgMessage)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(WIREGUARD_MESSAGE_TYPES, MessageType = 2))]
pub struct WgHandshakeResponse {
    pub sender_index: Value<u32>,
    pub receiver_index: Value<u32>,

    #[nproto(encode = encode_wg_32bytes, decode = decode_wg_32bytes)]
    pub unencrypted_ephemeral: Vec<u8>, // 32 bytes

    #[nproto(encode = encode_wg_16bytes, decode = decode_wg_16bytes)]
    pub encrypted_nothing: Vec<u8>, // 16 bytes (0 + 16 AEAD)

    #[nproto(encode = encode_wg_16bytes, decode = decode_wg_16bytes)]
    pub mac1: Vec<u8>, // 16 bytes

    #[nproto(encode = encode_wg_16bytes, decode = decode_wg_16bytes)]
    pub mac2: Vec<u8>, // 16 bytes
}

/// WireGuard Cookie Reply Message (Type 3)
/// Total size: 64 bytes (including 4-byte header in WgMessage)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(WIREGUARD_MESSAGE_TYPES, MessageType = 3))]
pub struct WgCookieReply {
    pub receiver_index: Value<u32>,

    #[nproto(encode = encode_wg_24bytes, decode = decode_wg_24bytes)]
    pub nonce: Vec<u8>, // 24 bytes

    #[nproto(encode = encode_wg_32bytes, decode = decode_wg_32bytes)]
    pub encrypted_cookie: Vec<u8>, // 32 bytes (16 + 16 AEAD)
}

/// WireGuard Transport Data Message (Type 4)
/// Variable size, minimum 32 bytes (including 4-byte header in WgMessage)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(WIREGUARD_MESSAGE_TYPES, MessageType = 4))]
pub struct WgTransportData {
    pub receiver_index: Value<u32>,

    pub counter: Value<u64>, // 8 bytes nonce/counter

    // Encrypted encapsulated packet (variable length)
    // Includes 16-byte AEAD authentication tag at the end
    pub encrypted_encapsulated_packet: Vec<u8>,
}

// Custom encode/decode functions for fixed-size byte arrays

fn encode_reserved_3bytes<E: Encoder>(
    _me: &dyn std::any::Any,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    vec![0, 0, 0]
}

fn decode_reserved_3bytes<D: Decoder>(
    buf: &[u8],
    ci: usize,
    _me: &mut dyn std::any::Any,
) -> Option<(u32, usize)> {
    if ci + 3 <= buf.len() {
        // Read 3 bytes and interpret as u32 (big-endian, padded with leading zero)
        let value = ((buf[ci] as u32) << 16) | ((buf[ci + 1] as u32) << 8) | (buf[ci + 2] as u32);
        Some((value, 3))
    } else {
        None
    }
}

fn encode_wg_16bytes<E: Encoder>(
    me: &dyn std::any::Any,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(bytes) = me.downcast_ref::<Vec<u8>>() {
        if bytes.len() == 16 {
            bytes.clone()
        } else {
            vec![0; 16]
        }
    } else {
        vec![0; 16]
    }
}

fn decode_wg_16bytes<D: Decoder>(
    buf: &[u8],
    ci: usize,
    _me: &mut dyn std::any::Any,
) -> Option<(Vec<u8>, usize)> {
    if ci + 16 <= buf.len() {
        Some((buf[ci..ci + 16].to_vec(), 16))
    } else {
        None
    }
}

fn encode_wg_24bytes<E: Encoder>(
    me: &dyn std::any::Any,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(bytes) = me.downcast_ref::<Vec<u8>>() {
        if bytes.len() == 24 {
            bytes.clone()
        } else {
            vec![0; 24]
        }
    } else {
        vec![0; 24]
    }
}

fn decode_wg_24bytes<D: Decoder>(
    buf: &[u8],
    ci: usize,
    _me: &mut dyn std::any::Any,
) -> Option<(Vec<u8>, usize)> {
    if ci + 24 <= buf.len() {
        Some((buf[ci..ci + 24].to_vec(), 24))
    } else {
        None
    }
}

fn encode_wg_28bytes<E: Encoder>(
    me: &dyn std::any::Any,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(bytes) = me.downcast_ref::<Vec<u8>>() {
        if bytes.len() == 28 {
            bytes.clone()
        } else {
            vec![0; 28]
        }
    } else {
        vec![0; 28]
    }
}

fn decode_wg_28bytes<D: Decoder>(
    buf: &[u8],
    ci: usize,
    _me: &mut dyn std::any::Any,
) -> Option<(Vec<u8>, usize)> {
    if ci + 28 <= buf.len() {
        Some((buf[ci..ci + 28].to_vec(), 28))
    } else {
        None
    }
}

fn encode_wg_32bytes<E: Encoder>(
    me: &dyn std::any::Any,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(bytes) = me.downcast_ref::<Vec<u8>>() {
        if bytes.len() == 32 {
            bytes.clone()
        } else {
            vec![0; 32]
        }
    } else {
        vec![0; 32]
    }
}

fn decode_wg_32bytes<D: Decoder>(
    buf: &[u8],
    ci: usize,
    _me: &mut dyn std::any::Any,
) -> Option<(Vec<u8>, usize)> {
    if ci + 32 <= buf.len() {
        Some((buf[ci..ci + 32].to_vec(), 32))
    } else {
        None
    }
}

fn encode_wg_48bytes<E: Encoder>(
    me: &dyn std::any::Any,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(bytes) = me.downcast_ref::<Vec<u8>>() {
        if bytes.len() == 48 {
            bytes.clone()
        } else {
            vec![0; 48]
        }
    } else {
        vec![0; 48]
    }
}

fn decode_wg_48bytes<D: Decoder>(
    buf: &[u8],
    ci: usize,
    _me: &mut dyn std::any::Any,
) -> Option<(Vec<u8>, usize)> {
    if ci + 48 <= buf.len() {
        Some((buf[ci..ci + 48].to_vec(), 48))
    } else {
        None
    }
}
