use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum DnsType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
}

impl Default for DnsType {
    fn default() -> Self {
        DnsType::A
    }
}

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum DnsClass {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
}

impl Default for DnsClass {
    fn default() -> Self {
        DnsClass::IN
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 53))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 53))]
pub struct Dns {
    pub id: Value<u16>,
    #[nproto(encode = encode_flags)]
    pub flags: Value<u16>,
    #[nproto(encode = encode_question_count)]
    pub qdcount: Value<u16>,
    #[nproto(encode = encode_answer_count)]
    pub ancount: Value<u16>,
    #[nproto(encode = encode_authority_count)]
    pub nscount: Value<u16>,
    #[nproto(encode = encode_additional_count)]
    pub arcount: Value<u16>,
    #[nproto(decode = decode_questions, encode = encode_questions)]
    pub questions: Vec<DnsQuestion>,
    #[nproto(decode = decode_resource_records, encode = encode_resource_records)]
    pub answers: Vec<DnsResourceRecord>,
    #[nproto(decode = decode_resource_records, encode = encode_resource_records)]
    pub authorities: Vec<DnsResourceRecord>,
    #[nproto(decode = decode_resource_records, encode = encode_resource_records)]
    pub additionals: Vec<DnsResourceRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: DnsType,
    pub qclass: DnsClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DnsResourceRecord {
    pub name: String,
    pub type_: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: DnsRData,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DnsRData {
    A(Ipv4Address),
    NS(String),
    CNAME(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(Vec<String>),
    AAAA(Vec<u8>),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    OPT(Vec<u8>),
    Unknown(Vec<u8>),
}

impl Default for DnsRData {
    fn default() -> Self {
        DnsRData::Unknown(vec![])
    }
}

struct DnsEncoder {
    compression_map: HashMap<String, u16>,
    next_offset: u16,
}

impl DnsEncoder {
    fn new() -> Self {
        DnsEncoder {
            compression_map: HashMap::new(),
            next_offset: 0,
        }
    }

    fn encode_name(&mut self, name: &str) -> Vec<u8> {
        let mut result = Vec::new();
        let mut remaining = name;

        while !remaining.is_empty() {
            if let Some(&offset) = self.compression_map.get(remaining) {
                result.extend_from_slice(&((offset | 0xC000_u16).to_be_bytes()));
                break;
            }

            if remaining.starts_with('.') {
                remaining = &remaining[1..];
                continue;
            }

            let end = remaining.find('.').unwrap_or(remaining.len());
            let label = &remaining[..end];
            
            if !label.is_empty() {
                if self.next_offset < 0x3FFF {
                    self.compression_map.insert(remaining.to_string(), self.next_offset);
                    self.next_offset += (label.len() + 1) as u16;
                }

                result.push(label.len() as u8);
                result.extend_from_slice(label.as_bytes());
            }

            if end < remaining.len() {
                remaining = &remaining[end + 1..];
            } else {
                break;
            }
        }

        result.push(0);
        result
    }
}

struct DnsDecoder {
    data: Vec<u8>,
}

impl DnsDecoder {
    fn new(data: Vec<u8>) -> Self {
        DnsDecoder { data }
    }

    fn decode_name(&self, offset: &mut usize) -> Option<String> {
        let mut result = Vec::new();
        let mut curr_offset = *offset;
        let mut last_offset = curr_offset; 
        loop {
            if curr_offset < last_offset {
                println!("Loop res: {:?}, curr: {}, last: {}!", &result, &curr_offset, &last_offset);
                if result.len() > 150 {
                    panic!("Result implausibly long");
                }
            }
            last_offset = curr_offset;
            if curr_offset >= self.data.len() {
                return None;
            }

            let length = self.data[curr_offset];
            if length == 0 {
                *offset = curr_offset + 1;
                break;
            }

            if (length & 0xC0) == 0xC0 {
                if curr_offset + 1 >= self.data.len() {
                    return None;
                }
                let pointer = ((length as u16 & 0x3F) << 8) | self.data[curr_offset + 1] as u16;
                if *offset == curr_offset {
                    *offset = curr_offset + 2;
                }
                curr_offset = pointer as usize;
                continue;
            }

            curr_offset += 1;
            if curr_offset + length as usize > self.data.len() {
                return None;
            }

            if !result.is_empty() {
                result.push(b'.');
            }

            result.extend_from_slice(&self.data[curr_offset..curr_offset + length as usize]);
            curr_offset += length as usize;
        }

        String::from_utf8(result).ok()
    }
}

fn encode_flags<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    me.flags.value().encode::<E>()
}

fn encode_question_count<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    (me.questions.len() as u16).encode::<E>()
}

fn encode_answer_count<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    (me.answers.len() as u16).encode::<E>()
}

fn encode_authority_count<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    (me.authorities.len() as u16).encode::<E>()
}

fn encode_additional_count<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    (me.additionals.len() as u16).encode::<E>()
}

fn decode_questions<D: Decoder>(buf: &[u8], me: &mut Dns) -> Option<(Vec<DnsQuestion>, usize)> {
    let decoder = DnsDecoder::new(buf.to_vec());
    let mut questions = Vec::new();
    let mut offset = 0;

    for _ in 0..me.qdcount.value() {
        let qname = decoder.decode_name(&mut offset)?;
        if offset + 4 > buf.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let qclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);

        questions.push(DnsQuestion {
            qname,
            qtype: DnsType::from_repr(qtype).unwrap_or(DnsType::A),
            qclass: DnsClass::from_repr(qclass).unwrap_or(DnsClass::IN),
        });

        offset += 4;
    }

    Some((questions, offset))
}

fn encode_questions<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut encoder = DnsEncoder::new();
    let mut result = Vec::new();

    for question in &me.questions {
        result.extend(encoder.encode_name(&question.qname));
        result.extend_from_slice(&(question.qtype.clone() as u16).to_be_bytes());
        result.extend_from_slice(&(question.qclass.clone() as u16).to_be_bytes());
    }

    result
}

fn decode_resource_records<D: Decoder>(buf: &[u8], me: &mut Dns) -> Option<(Vec<DnsResourceRecord>, usize)> {
    let decoder = DnsDecoder::new(buf.to_vec());
    let mut records = Vec::new();
    let mut offset = 0;

    while offset < buf.len() {
        let name = decoder.decode_name(&mut offset)?;
        if offset + 10 > buf.len() {
            break;
        }

        let type_ = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let class = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;

        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        let rdata = match DnsType::from_repr(type_).unwrap_or(DnsType::A) {
            DnsType::A => {
                if rdlength == 4 {
                    DnsRData::A(Ipv4Address::from([
                        buf[offset],
                        buf[offset + 1],
                        buf[offset + 2],
                        buf[offset + 3],
                    ]))
                } else {
                    DnsRData::Unknown(buf[offset..offset + rdlength].to_vec())
                }
            }
            // Add other record type decodings here
            _ => DnsRData::Unknown(buf[offset..offset + rdlength].to_vec()),
        };

        records.push(DnsResourceRecord {
            name,
            type_: DnsType::from_repr(type_).unwrap_or(DnsType::A),
            class: DnsClass::from_repr(class).unwrap_or(DnsClass::IN),
            ttl,
            rdata,
        });

        offset += rdlength;
    }

    Some((records, offset))
}

fn encode_resource_records<E: Encoder>(
    me: &Dns,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut encoder = DnsEncoder::new();
    let mut result = Vec::new();

    for record in &me.answers {
        result.extend(encoder.encode_name(&record.name));
        result.extend_from_slice(&(record.type_.clone() as u16).to_be_bytes());
        result.extend_from_slice(&(record.class.clone() as u16).to_be_bytes());
        result.extend_from_slice(&record.ttl.clone().to_be_bytes());

        let rdata = match &record.rdata {
            DnsRData::A(addr) => addr.encode::<E>(),
            DnsRData::Unknown(data) => data.clone(),
            // Add other record type encodings here
            _ => vec![],
        };

        result.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        result.extend(rdata);
    }

    result
}
