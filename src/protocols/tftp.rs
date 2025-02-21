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
    OptionAck = 6,
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
pub struct TftpOption {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TftpMessage {
    ReadRequest {
        filename: String,
        mode: TransferMode,
        options: Vec<TftpOption>,
    },
    WriteRequest {
        filename: String,
        mode: TransferMode,
        options: Vec<TftpOption>,
    },
    Data {
        block_number: u16,
        data: Vec<u8>,
    },
    Acknowledgment {
        block_number: u16,
    },
    OptionAcknowledgment {
        options: Vec<TftpOption>,
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
            options: Vec::new(),
        }
    }
}

impl FromStr for TftpMessage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(TftpMessage::ReadRequest {
            filename: s.to_string(),
            mode: TransferMode::default(),
            options: Vec::new(),
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
        match rng.gen_range(0..6) {
            0 => TftpMessage::ReadRequest {
                filename: String::from("random.txt"),
                mode: TransferMode::Octet,
                options: vec![],
            },
            1 => TftpMessage::WriteRequest {
                filename: String::from("random.txt"),
                mode: TransferMode::Octet,
                options: vec![],
            },
            2 => TftpMessage::Data {
                block_number: rng.gen(),
                data: vec![0; rng.gen_range(0..512)],
            },
            3 => TftpMessage::Acknowledgment {
                block_number: rng.gen(),
            },
            4 => TftpMessage::OptionAcknowledgment { options: vec![] },
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

fn decode_options(buf: &[u8], start: &mut usize) -> Vec<TftpOption> {
    let mut options = Vec::new();
    while let Some(name) = decode_string(buf, start) {
        if let Some(value) = decode_string(buf, start) {
            options.push(TftpOption { name, value });
        } else {
            break;
        }
    }
    options
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
            if let Some(filename) = decode_string(buf, &mut cursor) {
                if let Some(mode_str) = decode_string(buf, &mut cursor) {
                    if let Some(mode) = parse_mode(&mode_str) {
                        let options = decode_options(buf, &mut cursor);
                        if opcode == 1 {
                            TftpMessage::ReadRequest {
                                filename,
                                mode,
                                options,
                            }
                        } else {
                            TftpMessage::WriteRequest {
                                filename,
                                mode,
                                options,
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
            } else {
                TftpMessage::Raw {
                    opcode: TftpOpcode::from_repr(opcode).unwrap_or(TftpOpcode::Read),
                    payload: buf[2..].to_vec(),
                }
            }
        }
        3 => {
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
        6 => {
            let options = decode_options(buf, &mut cursor);
            TftpMessage::OptionAcknowledgment { options }
        }
        _ => TftpMessage::Raw {
            opcode: TftpOpcode::Read,
            payload: buf[2..].to_vec(),
        },
    };

    Some((Value::Set(message), cursor))
}

fn encode_options(options: &[TftpOption]) -> Vec<u8> {
    let mut out = Vec::new();
    for option in options {
        out.extend_from_slice(option.name.as_bytes());
        out.push(0);
        out.extend_from_slice(option.value.as_bytes());
        out.push(0);
    }
    out
}

fn encode_tftp_message<E: Encoder>(
    my_layer: &Tftp,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();

    match &my_layer.message.value() {
        TftpMessage::ReadRequest {
            filename,
            mode,
            options,
        } => {
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(filename.as_bytes());
            out.push(0);
            out.extend_from_slice(mode.to_string().as_bytes());
            out.push(0);
            out.extend_from_slice(&encode_options(options));
        }
        TftpMessage::WriteRequest {
            filename,
            mode,
            options,
        } => {
            out.extend_from_slice(&2u16.to_be_bytes());
            out.extend_from_slice(filename.as_bytes());
            out.push(0);
            out.extend_from_slice(mode.to_string().as_bytes());
            out.push(0);
            out.extend_from_slice(&encode_options(options));
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
        TftpMessage::OptionAcknowledgment { options } => {
            out.extend_from_slice(&6u16.to_be_bytes());
            out.extend_from_slice(&encode_options(options));
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
    pub fn read_request(
        filename: impl Into<String>,
        mode: TransferMode,
        options: Vec<TftpOption>,
    ) -> Self {
        Self {
            message: Value::Set(TftpMessage::ReadRequest {
                filename: filename.into(),
                mode,
                options,
            }),
        }
    }

    pub fn write_request(
        filename: impl Into<String>,
        mode: TransferMode,
        options: Vec<TftpOption>,
    ) -> Self {
        Self {
            message: Value::Set(TftpMessage::WriteRequest {
                filename: filename.into(),
                mode,
                options,
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

    pub fn oack(options: Vec<TftpOption>) -> Self {
        Self {
            message: Value::Set(TftpMessage::OptionAcknowledgment { options }),
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
        let options = vec![
            TftpOption {
                name: "timeout".to_string(),
                value: "6".to_string(),
            },
            TftpOption {
                name: "tsize".to_string(),
                value: "1024".to_string(),
            },
        ];
        let orig = Tftp::read_request("test.txt", TransferMode::Octet, options);
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
        let options = vec![TftpOption {
            name: "timeout".to_string(),
            value: "6".to_string(),
        }];
        let orig = Tftp::write_request("test.txt", TransferMode::Netascii, options);
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
    fn test_encode_decode_oack() {
        let options = vec![
            TftpOption {
                name: "timeout".to_string(),
                value: "6".to_string(),
            },
            TftpOption {
                name: "tsize".to_string(),
                value: "1024".to_string(),
            },
        ];
        let orig = Tftp::oack(options);
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
        let mut decoded = Tftp::default();
        let result = decode_tftp_message::<BinaryBigEndian>(&[0, 1], 0, &mut decoded);
        assert!(matches!(
            result,
            Some((Value::Set(TftpMessage::Raw { .. }), _))
        ));

        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(b"test.txt\0");
        buf.extend_from_slice(b"invalid_mode\0");
        let result = decode_tftp_message::<BinaryBigEndian>(&buf, 0, &mut decoded);
        assert!(matches!(
            result,
            Some((Value::Set(TftpMessage::Raw { .. }), _))
        ));
    }
}
