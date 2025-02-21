use crate::*;
use rand::distributions::{Distribution, Standard};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum TftpOpcode {
    Read = 1,
    Write = 2,
    Data = 3,
    Ack = 4,
    Error = 5,
}

impl Default for TftpOpcode {
    fn default() -> Self {
        TftpOpcode::Read
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TransferMode {
    Netascii,
    Octet,
    Mail,
}

impl Default for TransferMode {
    fn default() -> Self {
        TransferMode::Octet
    }
}

impl ToString for TransferMode {
    fn to_string(&self) -> String {
        match self {
            TransferMode::Netascii => "netascii".to_string(),
            TransferMode::Octet => "octet".to_string(),
            TransferMode::Mail => "mail".to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TftpMessage {
    ReadRequest {
        filename: String,
        mode: TransferMode,
    },
    WriteRequest {
        filename: String,
        mode: TransferMode,
    },
    Data {
        block_number: u16,
        data: Vec<u8>,
    },
    Acknowledgment {
        block_number: u16,
    },
    Error {
        code: TftpErrorCode,
        message: String,
    },
    Raw {
        opcode: TftpOpcode,
        payload: Vec<u8>,
    },
}

impl Default for TftpMessage {
    fn default() -> Self {
        TftpMessage::ReadRequest {
            filename: String::new(),
            mode: TransferMode::default(),
        }
    }
}

impl FromStr for TftpMessage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(TftpMessage::ReadRequest {
            filename: s.to_string(),
            mode: TransferMode::default(),
        })
    }
}

impl From<Value<TftpMessage>> for TftpMessage {
    fn from(value: Value<TftpMessage>) -> Self {
        match value {
            Value::Set(msg) => msg,
            Value::Auto => TftpMessage::default(),
            Value::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen()
            }
            Value::Func(f) => f(),
        }
    }
}

impl Distribution<TftpMessage> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> TftpMessage {
        match rng.gen_range(0..5) {
            0 => TftpMessage::ReadRequest {
                filename: String::from("random.txt"),
                mode: TransferMode::Octet,
            },
            1 => TftpMessage::WriteRequest {
                filename: String::from("random.txt"),
                mode: TransferMode::Octet,
            },
            2 => TftpMessage::Data {
                block_number: rng.gen(),
                data: vec![0; rng.gen_range(0..512)],
            },
            3 => TftpMessage::Acknowledgment {
                block_number: rng.gen(),
            },
            _ => TftpMessage::Error {
                code: TftpErrorCode::NotDefined,
                message: String::from("Random error"),
            },
        }
    }
}

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum TftpErrorCode {
    NotDefined = 0,
    FileNotFound = 1,
    AccessViolation = 2,
    DiskFull = 3,
    IllegalOperation = 4,
    UnknownTransferId = 5,
    FileExists = 6,
    NoSuchUser = 7,
}

impl Default for TftpErrorCode {
    fn default() -> Self {
        TftpErrorCode::NotDefined
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 69))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 69))]
pub struct Tftp {
    #[nproto(decode = decode_tftp_message, encode = encode_tftp_message)]
    pub message: Value<TftpMessage>,
}

fn decode_string(buf: &[u8], start: &mut usize) -> Option<String> {
    let mut end = *start;
    while end < buf.len() && buf[end] != 0 {
        end += 1;
    }
    if end >= buf.len() {
        return None;
    }
    let s = String::from_utf8(buf[*start..end].to_vec()).ok()?;
    *start = end + 1;
    Some(s)
}

fn parse_mode(mode: &str) -> Option<TransferMode> {
    match mode.to_lowercase().as_str() {
        "netascii" => Some(TransferMode::Netascii),
        "octet" => Some(TransferMode::Octet),
        "mail" => Some(TransferMode::Mail),
        _ => None,
    }
}

fn decode_tftp_message<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Tftp,
) -> Option<(Value<TftpMessage>, usize)> {
    let buf = &buf[ci..];
    if buf.len() < 2 {
        return None;
    }

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    let mut cursor = 2;

    let message = match opcode {
        1 | 2 => {
            // RRQ or WRQ
            if let Some(filename) = decode_string(buf, &mut cursor) {
                if let Some(mode_str) = decode_string(buf, &mut cursor) {
                    if let Some(mode) = parse_mode(&mode_str) {
                        if opcode == 1 {
                            TftpMessage::ReadRequest { filename, mode }
                        } else {
                            TftpMessage::WriteRequest { filename, mode }
                        }
                    } else {
                        TftpMessage::Raw {
                            opcode: TftpOpcode::from_repr(opcode).unwrap_or(TftpOpcode::Read),
                            payload: buf[2..].to_vec(),
                        }
                    }
                } else {
                    TftpMessage::Raw {
                        opcode: TftpOpcode::from_repr(opcode).unwrap_or(TftpOpcode::Read),
                        payload: buf[2..].to_vec(),
                    }
                }
            } else {
                TftpMessage::Raw {
                    opcode: TftpOpcode::from_repr(opcode).unwrap_or(TftpOpcode::Read),
                    payload: buf[2..].to_vec(),
                }
            }
        }
        3 => {
            // DATA
            if cursor + 2 <= buf.len() {
                let block_number = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                let data = buf[cursor..].to_vec();
                cursor = buf.len();

                TftpMessage::Data { block_number, data }
            } else {
                TftpMessage::Raw {
                    opcode: TftpOpcode::Data,
                    payload: buf[2..].to_vec(),
                }
            }
        }
        4 => {
            // ACK
            if cursor + 2 <= buf.len() {
                let block_number = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;

                TftpMessage::Acknowledgment { block_number }
            } else {
                TftpMessage::Raw {
                    opcode: TftpOpcode::Ack,
                    payload: buf[2..].to_vec(),
                }
            }
        }
        5 => {
            // ERROR
            if cursor + 2 <= buf.len() {
                let error_code = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;

                if let Some(message) = decode_string(buf, &mut cursor) {
                    let code =
                        TftpErrorCode::from_repr(error_code).unwrap_or(TftpErrorCode::NotDefined);
                    TftpMessage::Error { code, message }
                } else {
                    TftpMessage::Raw {
                        opcode: TftpOpcode::Error,
                        payload: buf[2..].to_vec(),
                    }
                }
            } else {
                TftpMessage::Raw {
                    opcode: TftpOpcode::Error,
                    payload: buf[2..].to_vec(),
                }
            }
        }
        _ => TftpMessage::Raw {
            opcode: TftpOpcode::Read,
            payload: buf[2..].to_vec(),
        },
    };

    Some((Value::Set(message), cursor))
}

fn encode_tftp_message<E: Encoder>(
    my_layer: &Tftp,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();

    match &my_layer.message.value() {
        TftpMessage::ReadRequest { filename, mode } => {
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(filename.as_bytes());
            out.push(0);
            out.extend_from_slice(mode.to_string().as_bytes());
            out.push(0);
        }
        TftpMessage::WriteRequest { filename, mode } => {
            out.extend_from_slice(&2u16.to_be_bytes());
            out.extend_from_slice(filename.as_bytes());
            out.push(0);
            out.extend_from_slice(mode.to_string().as_bytes());
            out.push(0);
        }
        TftpMessage::Data { block_number, data } => {
            out.extend_from_slice(&3u16.to_be_bytes());
            out.extend_from_slice(&block_number.to_be_bytes());
            out.extend_from_slice(data);
        }
        TftpMessage::Acknowledgment { block_number } => {
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&block_number.to_be_bytes());
        }
        TftpMessage::Error { code, message } => {
            out.extend_from_slice(&5u16.to_be_bytes());
            out.extend_from_slice(&((*code).clone() as u16).to_be_bytes());
            out.extend_from_slice(message.as_bytes());
            out.push(0);
        }
        TftpMessage::Raw { opcode, payload } => {
            out.extend_from_slice(&((*opcode).clone() as u16).to_be_bytes());
            out.extend_from_slice(payload);
        }
    }

    out
}

impl Tftp {
    pub fn read_request(filename: impl Into<String>, mode: TransferMode) -> Self {
        Self {
            message: Value::Set(TftpMessage::ReadRequest {
                filename: filename.into(),
                mode,
            }),
        }
    }

    pub fn write_request(filename: impl Into<String>, mode: TransferMode) -> Self {
        Self {
            message: Value::Set(TftpMessage::WriteRequest {
                filename: filename.into(),
                mode,
            }),
        }
    }

    pub fn data(block_number: u16, data: impl Into<Vec<u8>>) -> Self {
        Self {
            message: Value::Set(TftpMessage::Data {
                block_number,
                data: data.into(),
            }),
        }
    }

    pub fn ack(block_number: u16) -> Self {
        Self {
            message: Value::Set(TftpMessage::Acknowledgment { block_number }),
        }
    }

    pub fn error(code: TftpErrorCode, message: impl Into<String>) -> Self {
        Self {
            message: Value::Set(TftpMessage::Error {
                code,
                message: message.into(),
            }),
        }
    }

    pub fn raw(opcode: TftpOpcode, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            message: Value::Set(TftpMessage::Raw {
                opcode,
                payload: payload.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_read_request() {
        let orig = Tftp::read_request("test.txt", TransferMode::Octet);
        let encoded = encode_tftp_message::<BinaryBigEndian>(
            &orig,
            &LayerStack::default(),
            0,
            &EncodingVecVec::default(),
        );
        let mut decoded = Tftp::default();
        let (msg, _) = decode_tftp_message::<BinaryBigEndian>(&encoded, 0, &mut decoded).unwrap();
        assert_eq!(orig.message.value(), msg.value());
    }

    #[test]
    fn test_encode_decode_write_request() {
        let orig = Tftp::write_request("test.txt", TransferMode::Netascii);
        let encoded = encode_tftp_message::<BinaryBigEndian>(
            &orig,
            &LayerStack::default(),
            0,
            &EncodingVecVec::default(),
        );
        let mut decoded = Tftp::default();
        let (msg, _) = decode_tftp_message::<BinaryBigEndian>(&encoded, 0, &mut decoded).unwrap();
        assert_eq!(orig.message.value(), msg.value());
    }

    #[test]
    fn test_encode_decode_data() {
        let orig = Tftp::data(1, vec![1, 2, 3, 4]);
        let encoded = encode_tftp_message::<BinaryBigEndian>(
            &orig,
            &LayerStack::default(),
            0,
            &EncodingVecVec::default(),
        );
        let mut decoded = Tftp::default();
        let (msg, _) = decode_tftp_message::<BinaryBigEndian>(&encoded, 0, &mut decoded).unwrap();
        assert_eq!(orig.message.value(), msg.value());
    }

    #[test]
    fn test_encode_decode_ack() {
        let orig = Tftp::ack(1);
        let encoded = encode_tftp_message::<BinaryBigEndian>(
            &orig,
            &LayerStack::default(),
            0,
            &EncodingVecVec::default(),
        );
        let mut decoded = Tftp::default();
        let (msg, _) = decode_tftp_message::<BinaryBigEndian>(&encoded, 0, &mut decoded).unwrap();
        assert_eq!(orig.message.value(), msg.value());
    }

    #[test]
    fn test_encode_decode_error() {
        let orig = Tftp::error(TftpErrorCode::FileNotFound, "File not found");
        let encoded = encode_tftp_message::<BinaryBigEndian>(
            &orig,
            &LayerStack::default(),
            0,
            &EncodingVecVec::default(),
        );
        let mut decoded = Tftp::default();
        let (msg, _) = decode_tftp_message::<BinaryBigEndian>(&encoded, 0, &mut decoded).unwrap();
        assert_eq!(orig.message.value(), msg.value());
    }

    #[test]
    fn test_encode_decode_raw() {
        let orig = Tftp::raw(TftpOpcode::Read, vec![1, 2, 3, 4]);
        let encoded = encode_tftp_message::<BinaryBigEndian>(
            &orig,
            &LayerStack::default(),
            0,
            &EncodingVecVec::default(),
        );
        let mut decoded = Tftp::default();
        let (msg, _) = decode_tftp_message::<BinaryBigEndian>(&encoded, 0, &mut decoded).unwrap();
        assert_eq!(orig.message.value(), msg.value());
    }

    #[test]
    fn test_malformed_packet_handling() {
        // Test with truncated packet
        let mut decoded = Tftp::default();
        let result = decode_tftp_message::<BinaryBigEndian>(&[0, 1], 0, &mut decoded);
        assert!(matches!(
            result,
            Some((Value::Set(TftpMessage::Raw { .. }), _))
        ));

        // Test with invalid mode
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes()); // RRQ
        buf.extend_from_slice(b"test.txt\0");
        buf.extend_from_slice(b"invalid_mode\0");
        let result = decode_tftp_message::<BinaryBigEndian>(&buf, 0, &mut decoded);
        assert!(matches!(
            result,
            Some((Value::Set(TftpMessage::Raw { .. }), _))
        ));
    }
}
