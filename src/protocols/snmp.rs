use crate::encdec::asn1::Asn1Decoder;
use crate::encdec::asn1::Asn1Encoder;
use crate::typ::string::FixedSizeString;
use crate::*;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Community(Vec<u8>);

impl FromStr for Community {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Community(s.to_string().into_bytes()))
    }
}

impl From<&[u8; 6]> for Community {
    fn from(arg: &[u8; 6]) -> Self {
        Community(arg.to_vec())
    }
}
impl From<&str> for Community {
    fn from(arg: &str) -> Self {
        Community(arg.to_string().into_bytes())
    }
}

impl Distribution<Community> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Community {
        // Generate a random community string (typically "public" or "private" for testing)
        let communities = ["public", "private", "test", "community"];
        let idx = rng.gen_range(0..communities.len());
        Community(communities[idx].to_string().into_bytes())
    }
}

impl fmt::Display for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", String::from_utf8_lossy(&self.0)))
    }
}

impl Decode for Community {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (out, delta) = D::decode_octetstring(buf)?;
        Some((Community(out), delta))
    }
}

impl Encode for Community {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_vec(&self.0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BerTagAndLen(pub asn1::Tag, pub usize);

impl FromStr for BerTagAndLen {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse format like "tag:length" or just use defaults
        if let Some((tag_str, len_str)) = s.split_once(':') {
            if let (Ok(tag_num), Ok(len)) = (tag_str.parse::<u8>(), len_str.parse::<usize>()) {
                return Ok(BerTagAndLen(asn1::Tag::UnknownTag(tag_num), len));
            }
        }
        // Default to sequence with length 0
        Ok(BerTagAndLen(asn1::Tag::Sequence, 0))
    }
}

impl From<&[u8; 6]> for BerTagAndLen {
    fn from(arg: &[u8; 6]) -> Self {
        Self::default()
    }
}

impl Distribution<BerTagAndLen> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerTagAndLen {
        // Generate random tag and length for testing
        let tags = [
            asn1::Tag::Sequence,
            asn1::Tag::Integer,
            asn1::Tag::OctetString,
            asn1::Tag::Boolean,
        ];
        let tag = tags[rng.gen_range(0..tags.len())].clone();
        let len = rng.gen_range(0..256);
        BerTagAndLen(tag, len)
    }
}

impl Decode for BerTagAndLen {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let ((tag, len), delta) = Asn1Decoder::parse_tag_and_len(buf, 0)?;
        Some((BerTagAndLen(tag, len), delta))
    }
}

impl Encode for BerTagAndLen {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let tag = &self.0;
        let len = &self.1;
        let mut out = Asn1Encoder::encode_tag(tag);
        out.extend(Asn1Encoder::encode_length(*len));
        out
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Hash, Copy)]
pub struct BerTag(asn1::Tag);

impl FromStr for BerTag {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse common SNMP tags by name or number
        match s.to_lowercase().as_str() {
            "sequence" => Ok(BerTag(asn1::Tag::Sequence)),
            "integer" => Ok(BerTag(asn1::Tag::Integer)),
            "octetstring" => Ok(BerTag(asn1::Tag::OctetString)),
            "boolean" => Ok(BerTag(asn1::Tag::Boolean)),
            "null" => Ok(BerTag(asn1::Tag::Null)),
            "oid" => Ok(BerTag(asn1::Tag::ObjectIdentifier)),
            // SNMP PDU types
            "get" => Ok(BerTag(asn1::Tag::UnknownTag(160))), // 0xa0
            "getnext" => Ok(BerTag(asn1::Tag::UnknownTag(161))), // 0xa1
            "response" => Ok(BerTag(asn1::Tag::UnknownTag(162))), // 0xa2
            "set" => Ok(BerTag(asn1::Tag::UnknownTag(163))), // 0xa3
            "trap" => Ok(BerTag(asn1::Tag::UnknownTag(164))), // 0xa4
            "getbulk" => Ok(BerTag(asn1::Tag::UnknownTag(165))), // 0xa5
            "inform" => Ok(BerTag(asn1::Tag::UnknownTag(166))), // 0xa6
            "trapv2" => Ok(BerTag(asn1::Tag::UnknownTag(167))), // 0xa7
            _ => {
                // Try to parse as number
                if let Ok(tag_num) = s.parse::<u8>() {
                    Ok(BerTag(asn1::Tag::UnknownTag(tag_num)))
                } else {
                    Err(ValueParseError::Error)
                }
            }
        }
    }
}

impl From<&[u8; 6]> for BerTag {
    fn from(arg: &[u8; 6]) -> Self {
        Self::default()
    }
}

impl Distribution<BerTag> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerTag {
        // Generate random SNMP PDU tags for testing
        let tags = [160, 161, 162, 163, 164, 165, 166, 167]; // SNMP PDU types
        let tag = tags[rng.gen_range(0..tags.len())];
        BerTag(asn1::Tag::UnknownTag(tag))
    }
}

impl Decode for BerTag {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (tag, delta) = Asn1Decoder::parse_tag(buf, 0).ok()?;
        Some((BerTag(tag), delta))
    }
}

impl Encode for BerTag {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        Asn1Encoder::encode_tag(&self.0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BerLen(pub usize);

impl FromStr for BerLen {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<usize>() {
            Ok(len) => Ok(BerLen(len)),
            Err(_) => Err(ValueParseError::Error),
        }
    }
}

impl From<&[u8; 6]> for BerLen {
    fn from(arg: &[u8; 6]) -> Self {
        Self::default()
    }
}

impl Distribution<BerLen> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerLen {
        // Generate reasonable length values for testing
        BerLen(rng.gen_range(0..1024))
    }
}

impl Decode for BerLen {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (len, delta) = Asn1Decoder::parse_length(buf, 0).ok()?;
        Some((BerLen(len), delta))
    }
}

impl Encode for BerLen {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        Asn1Encoder::encode_length(self.0)
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 161))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 161))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct Snmp {
    #[nproto(encode=Skip, fill=auto)]
    pub _seq_tag_len: Value<BerTagAndLen>,
    //#[nproto(default = 1)] // 1 == SNMPv2c
    #[nproto(next: SNMP_VERSIONS => Version )]
    #[nproto(post_encode = post_encode_seq_tag_len)]
    pub version: Value<u8>,
}

fn post_encode_seq_tag_len<E: Encoder>(
    me: &Snmp,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let mut out_len = 0;
    println!("SNMP my index: {}", my_index);
    for i in my_index + 1..encoded_data.len() {
        println!("ADD Other layer({}) len: {} bytes: {:x?}", i, encoded_data[i].len(), &encoded_data[i]);
        out_len += encoded_data[i].len();
    }
    // Also account for what has been encoded on this level already
    out_len += out.len() - old_len;

    // out_len += 2; // tag + len overhead

    let seq_tag_len = if !me._seq_tag_len.is_auto() {
        me._seq_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out_len)
    };
    println!("idx: {} SNMP OLD LEN: {},  OUT_LEN: {}", my_index, old_len, out_len);
    // find out the length of inner layers
    let bytes = seq_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_VERSIONS, Version = 1))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpV2c {
    #[nproto(default = "public")]
    pub community: Value<Community>,
    #[nproto(next: SNMP_PDUS => Tag)]
    pub _pdu_tag: Value<BerTag>,
    #[nproto(encode = encode_pdu_len, fill=auto)]
    pub _pdu_len: Value<BerLen>,
}

fn encode_pdu_len<E: Encoder>(
    me: &SnmpV2c,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    let mut out_len = 0;
    for i in my_index + 1..encoded_data.len() {
        out_len += encoded_data[i].len();
    }
    let pdu_len = if !me._pdu_len.is_auto() {
        me._pdu_len.value()
    } else {
        BerLen(out_len)
    };
    let bytes = pdu_len.encode::<E>();
    bytes
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(160))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGet(pub SnmpGetOrResponse);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(161))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetNext(pub SnmpGetOrResponse);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(162))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetResponse(pub SnmpGetOrResponse);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetOrResponse {
    pub request_id: Value<u32>,
    pub error_status: Value<i32>,
    pub error_index: Value<i32>,
    #[nproto(encode = Skip)]
    pub _bindings_tag_len: Value<BerTagAndLen>,
    #[nproto(post_encode = post_encode_bindings_tag_len)]
    pub var_bindings: Vec<SnmpVarBind>,
}

fn post_encode_bindings_tag_len<E: Encoder>(
    me: &SnmpGetOrResponse,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let bindings_tag_len = if !me._bindings_tag_len.is_auto() {
        me._bindings_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out.len() - old_len)
    };
    let bytes = bindings_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

impl AutoDecodeAsSequence for Vec<SnmpVarBind> {}
impl AutoEncodeAsSequence for Vec<SnmpVarBind> {}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpVarBind {
    #[nproto(encode = Skip)]
    pub _bind_tag_len: Value<BerTagAndLen>,
    pub name: Value<BerOid>,
    #[nproto(post_encode = post_encode_bind_tag_len)]
    pub value: Value<SnmpValue>,
}

fn post_encode_bind_tag_len<E: Encoder>(
    me: &SnmpVarBind,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let bind_tag_len = if !me._bind_tag_len.is_auto() {
        me._bind_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out.len())
    };
    let bytes = bind_tag_len.encode::<E>();
    out.splice(0..0, bytes);
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BerOid(Vec<u64>);

impl FromStr for BerOid {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse dotted decimal notation like "1.3.6.1.2.1.1.1.0"
        let parts: Result<Vec<u64>, _> = s.split('.').map(|part| part.parse::<u64>()).collect();
        match parts {
            Ok(mut oid_parts) => {
                if oid_parts.len() < 2 {
                    return Err(ValueParseError::Error);
                }
                // First two components are encoded as first_part * 40 + second_part
                let first_encoded = oid_parts[0] * 40 + oid_parts[1];
                oid_parts[0] = first_encoded;
                oid_parts.remove(1);
                Ok(BerOid(oid_parts))
            }
            Err(_) => Err(ValueParseError::Error),
        }
    }
}

impl From<&str> for BerOid {
    fn from(s: &str) -> Self {
        BerOid::from_str(s).unwrap_or_default()
    }
}

impl From<&[u8; 6]> for BerOid {
    fn from(arg: &[u8; 6]) -> Self {
        // Convert 6 bytes to a basic OID (not very meaningful, but for compatibility)
        let oid = vec![
            arg[0] as u64 * 40 + arg[1] as u64,
            arg[2] as u64,
            arg[3] as u64,
            arg[4] as u64,
            arg[5] as u64,
        ];
        BerOid(oid)
    }
}

impl std::fmt::Display for BerOid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(".")
        )
    }
}

impl Distribution<BerOid> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerOid {
        // Generate common SNMP OIDs for testing
        let common_oids = [
            vec![43, 6, 1, 2, 1, 1, 1, 0], // 1.3.6.1.2.1.1.1.0 (sysDescr)
            vec![43, 6, 1, 2, 1, 1, 2, 0], // 1.3.6.1.2.1.1.2.0 (sysObjectID)
            vec![43, 6, 1, 2, 1, 1, 3, 0], // 1.3.6.1.2.1.1.3.0 (sysUpTime)
            vec![43, 6, 1, 2, 1, 1, 4, 0], // 1.3.6.1.2.1.1.4.0 (sysContact)
            vec![43, 6, 1, 2, 1, 1, 5, 0], // 1.3.6.1.2.1.1.5.0 (sysName)
        ];
        let idx = rng.gen_range(0..common_oids.len());
        BerOid(common_oids[idx].clone())
    }
}

impl Decode for BerOid {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let mut ci = 0;
        let ((tag, len), tldelta) = Asn1Decoder::parse_tag_and_len(buf, 0)?;
        Asn1Decoder::parse_oid(buf, tldelta, len).map(|(oid, delta)| (BerOid(oid), tldelta + delta))
    }
}

impl Encode for BerOid {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let oid_bytes = Asn1Encoder::encode_oid(&self.0);
        let mut out = Asn1Encoder::encode_tag(&asn1::Tag::ObjectIdentifier);
        out.extend(Asn1Encoder::encode_length(oid_bytes.len()));
        out.extend(oid_bytes);
        out
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BerValue(asn1::ASN1Object);

impl FromStr for BerValue {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse different value types based on prefix or content
        if s.starts_with("int:") {
            if let Ok(val) = s[4..].parse::<i64>() {
                return Ok(BerValue(asn1::ASN1Object {
                    tag: asn1::Tag::Integer,
                    value: asn1::Value::Integer(val),
                }));
            }
        } else if s.starts_with("str:") {
            return Ok(BerValue(asn1::ASN1Object {
                tag: asn1::Tag::OctetString,
                value: asn1::Value::OctetString(s[4..].as_bytes().to_vec()),
            }));
        } else if s == "null" {
            return Ok(BerValue(asn1::ASN1Object {
                tag: asn1::Tag::Null,
                value: asn1::Value::Null,
            }));
        } else if s.starts_with("oid:") {
            // Parse OID value
            if let Ok(ber_oid) = BerOid::from_str(&s[4..]) {
                return Ok(BerValue(asn1::ASN1Object {
                    tag: asn1::Tag::ObjectIdentifier,
                    value: asn1::Value::ObjectIdentifier(ber_oid.0),
                }));
            }
        } else {
            // Try to parse as integer by default
            if let Ok(val) = s.parse::<i64>() {
                return Ok(BerValue(asn1::ASN1Object {
                    tag: asn1::Tag::Integer,
                    value: asn1::Value::Integer(val),
                }));
            }
        }
        Err(ValueParseError::Error)
    }
}

impl From<&[u8; 6]> for BerValue {
    fn from(arg: &[u8; 6]) -> Self {
        // Convert bytes to octet string value
        BerValue(asn1::ASN1Object {
            tag: asn1::Tag::OctetString,
            value: asn1::Value::OctetString(arg.to_vec()),
        })
    }
}

impl From<&str> for BerValue {
    fn from(arg: &str) -> Self {
        // Convert string to octet string value
        BerValue(asn1::ASN1Object {
            tag: asn1::Tag::OctetString,
            value: asn1::Value::OctetString(arg.as_bytes().to_vec()),
        })
    }
}

impl Distribution<BerValue> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerValue {
        // Generate different types of values for testing
        match rng.gen_range(0..4) {
            0 => BerValue(asn1::ASN1Object {
                tag: asn1::Tag::Integer,
                value: asn1::Value::Integer(rng.gen_range(-1000..1000)),
            }),
            1 => BerValue(asn1::ASN1Object {
                tag: asn1::Tag::OctetString,
                value: asn1::Value::OctetString(b"test string".to_vec()),
            }),
            2 => BerValue(asn1::ASN1Object {
                tag: asn1::Tag::Null,
                value: asn1::Value::Null,
            }),
            _ => BerValue(asn1::ASN1Object {
                tag: asn1::Tag::ObjectIdentifier,
                value: asn1::Value::ObjectIdentifier(vec![43, 6, 1, 2, 1, 1, 1, 0]),
            }),
        }
    }
}

impl Decode for BerValue {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (out, delta) = Asn1Decoder::parse(buf, 0).ok()?;
        Some((BerValue(out), delta))
    }
}

impl Encode for BerValue {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        Asn1Encoder::encode_asn1_object(&self.0)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SnmpValue {
    #[default]
    Null,
    Unknown(asn1::ASN1Object),
    Integer(i64),
    OctetString(Vec<u8>),
    ObjectIdentifier(BerOid),
    IpAddress(Ipv4Address),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32), // Use this one (standard capitalization)
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
    #[serde(untagged)]
    SimpleInt32(i32),
}

impl FromStr for SnmpValue {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "null" => Ok(SnmpValue::Null),
            _ => {
                // Try different prefixes for typed values
                if s.starts_with("int:") {
                    if let Ok(val) = s[4..].parse::<i32>() {
                        return Ok(SnmpValue::SimpleInt32(val));
                    }
                } else if s.starts_with("timeticks:") {
                    if let Ok(val) = s[10..].parse::<u32>() {
                        return Ok(SnmpValue::TimeTicks(val));
                    }
                } else if s.starts_with("counter64:") {
                    if let Ok(val) = s[10..].parse::<u64>() {
                        return Ok(SnmpValue::Counter64(val));
                    }
                } else {
                    // Try to parse as integer by default
                    if let Ok(val) = s.parse::<i32>() {
                        return Ok(SnmpValue::SimpleInt32(val));
                    }
                }
                Err(ValueParseError::Error)
            }
        }
    }
}

impl From<&[u8; 6]> for SnmpValue {
    fn from(arg: &[u8; 6]) -> Self {
        // Convert MAC address bytes to SNMP OctetString value
        // This preserves all 6 bytes of the MAC address
        SnmpValue::Unknown(asn1::ASN1Object {
            tag: asn1::Tag::OctetString,
            value: asn1::Value::OctetString(arg.to_vec()),
        })
    }
}

impl From<&str> for SnmpValue {
    fn from(arg: &str) -> Self {
        // Try to parse from string
        match SnmpValue::from_str(arg) {
            Ok(val) => val,
            Err(_) => SnmpValue::Null,
        }
    }
}

impl Distribution<SnmpValue> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SnmpValue {
        // Generate different SNMP value types for testing
        match rng.gen_range(0..5) {
            0 => SnmpValue::Null,
            1 => SnmpValue::SimpleInt32(rng.gen_range(-1000..1000)),
            2 => SnmpValue::TimeTicks(rng.gen()),
            3 => SnmpValue::Counter64(rng.gen()),
            _ => SnmpValue::Unknown(asn1::ASN1Object {
                tag: asn1::Tag::OctetString,
                value: asn1::Value::OctetString(b"random data".to_vec()),
            }),
        }
    }
}

impl Decode for SnmpValue {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (out, delta) = Asn1Decoder::parse(buf, 0).ok()?;
        let snmp_out = match out.tag {
            asn1::Tag::Null => SnmpValue::Null,
            asn1::Tag::Integer => {
                if let asn1::Value::Integer(iv) = out.value {
                    if iv < -2147483648 || iv > 2147483647 {
                        return None;
                    }
                    SnmpValue::SimpleInt32(iv as i32)
                } else {
                    return None;
                }
            }
            asn1::Tag::UnknownTag(0x43) => {
                if let asn1::Value::UnknownPrimitive(_, data) = out.value {
                    let (value, _) =
                        Asn1Decoder::parse_just_integer_unsigned(&data, data.len()).ok()?;
                    if value > 4294967295 {
                        return None;
                    }
                    SnmpValue::TimeTicks(value as u32)
                } else {
                    return None;
                }
            }
            asn1::Tag::UnknownTag(0x46) => {
                if let asn1::Value::UnknownPrimitive(_, data) = out.value {
                    let (value, _) =
                        Asn1Decoder::parse_just_integer_unsigned(&data, data.len()).ok()?;
                    SnmpValue::Counter64(value)
                } else {
                    return None;
                }
            }
            x => SnmpValue::Unknown(out),
        };
        Some((snmp_out, delta))
    }
}

impl Encode for SnmpValue {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let asn1obj = match self {
            SnmpValue::Unknown(x) => x,
            SnmpValue::Null => &asn1::ASN1Object {
                tag: asn1::Tag::Null,
                value: asn1::Value::Null,
            },
            SnmpValue::SimpleInt32(x) => &asn1::ASN1Object {
                tag: asn1::Tag::Integer,
                value: asn1::Value::Integer(*x as i64),
            },
            // Add these new cases:
            SnmpValue::Integer(x) => &asn1::ASN1Object {
                tag: asn1::Tag::Integer,
                value: asn1::Value::Integer(*x),
            },
            SnmpValue::OctetString(bytes) => &asn1::ASN1Object {
                tag: asn1::Tag::OctetString,
                value: asn1::Value::OctetString(bytes.clone()),
            },
            SnmpValue::ObjectIdentifier(oid) => &asn1::ASN1Object {
                tag: asn1::Tag::ObjectIdentifier,
                value: asn1::Value::ObjectIdentifier(oid.0.clone()),
            },
            SnmpValue::IpAddress(ip) => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x40), // IpAddress tag
                value: asn1::Value::OctetString(ip.encode::<E>()),
            },
            SnmpValue::Counter32(x) => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x41), // Counter32 tag
                value: asn1::Value::UnknownPrimitive(0x41, (*x as u64).to_be_bytes().to_vec()),
            },
            SnmpValue::Gauge32(x) => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x42), // Gauge32 tag
                value: asn1::Value::UnknownPrimitive(0x42, (*x as u64).to_be_bytes().to_vec()),
            },
            SnmpValue::Opaque(bytes) => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x44), // Opaque tag
                value: asn1::Value::OctetString(bytes.clone()),
            },
            SnmpValue::NoSuchObject => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x80), // noSuchObject tag
                value: asn1::Value::Null,
            },
            SnmpValue::NoSuchInstance => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x81), // noSuchInstance tag
                value: asn1::Value::Null,
            },
            SnmpValue::EndOfMibView => &asn1::ASN1Object {
                tag: asn1::Tag::UnknownTag(0x82), // endOfMibView tag
                value: asn1::Value::Null,
            },
            // TimeTicks and Counter64 already handled above, so we need to add pattern matches for them too
            SnmpValue::TimeTicks(x) => {
                let mut result = vec![0x43];
                let value_bytes = Asn1Encoder::encode_integer_bytes(*x as u64, false);
                result.extend(Asn1Encoder::encode_length(value_bytes.len()));
                result.extend(value_bytes);
                return result;
            }
            SnmpValue::Counter64(x) => {
                let mut result = vec![0x46];
                let value_bytes = Asn1Encoder::encode_integer_bytes(*x, true);
                result.extend(Asn1Encoder::encode_length(value_bytes.len()));
                result.extend(value_bytes);
                return result;
            }
        };
        Asn1Encoder::encode_asn1_object(asn1obj)
    }
}

// First, create a newtype wrapper for Vec<u8> to implement third-party traits
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ByteArray(Vec<u8>);

impl FromStr for ByteArray {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse hex string or plain string
        if s.starts_with("0x") || s.starts_with("0X") {
            // Parse as hex
            let hex_str = &s[2..];
            let mut bytes = Vec::new();
            for chunk in hex_str.as_bytes().chunks(2) {
                if chunk.len() == 2 {
                    let hex_byte = std::str::from_utf8(chunk).unwrap();
                    if let Ok(byte) = u8::from_str_radix(hex_byte, 16) {
                        bytes.push(byte);
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
            }
            Ok(ByteArray(bytes))
        } else {
            // Parse as UTF-8 string
            Ok(ByteArray(s.as_bytes().to_vec()))
        }
    }
}

impl Distribution<ByteArray> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ByteArray {
        let len = rng.gen_range(0..32);
        let mut bytes = vec![0u8; len];
        rng.fill_bytes(&mut bytes);
        ByteArray(bytes)
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(v: Vec<u8>) -> Self {
        ByteArray(v)
    }
}

impl From<&[u8]> for ByteArray {
    fn from(v: &[u8]) -> Self {
        ByteArray(v.to_vec())
    }
}

impl From<&str> for ByteArray {
    fn from(s: &str) -> Self {
        ByteArray(s.as_bytes().to_vec())
    }
}

impl Deref for ByteArray {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Decode for ByteArray {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        // ByteArray is encoded as OCTET STRING in ASN.1
        match Asn1Decoder::decode_octetstring(buf) {
            Some((bytes, consumed)) => Some((ByteArray(bytes), consumed)),
            None => None,
        }
    }
}

// Step 2: Add missing SNMP PDU types and prepare foundation for SNMPv3

// First, let's add the missing SNMPv2c PDU types that are currently missing

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(163))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpSet(pub SnmpSetRequest);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(166))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpInform(pub SnmpGetOrResponse);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(165))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetBulk(pub SnmpGetBulkRequest);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(164))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpTrap(pub SnmpTrapPdu);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(167))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpTrapV2(pub SnmpTrapV2Pdu);

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetBulkRequest {
    pub request_id: Value<u32>,
    pub non_repeaters: Value<i32>,
    pub max_repetitions: Value<i32>,
    #[nproto(encode = Skip)]
    pub _bindings_tag_len: Value<BerTagAndLen>,
    #[nproto(post_encode = post_encode_bindings_tag_len_getbulk)]
    pub var_bindings: Vec<SnmpVarBind>,
}

fn post_encode_bindings_tag_len_getbulk<E: Encoder>(
    me: &SnmpGetBulkRequest,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let bindings_tag_len = if !me._bindings_tag_len.is_auto() {
        me._bindings_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out.len() - old_len)
    };
    let bytes = bindings_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpSetRequest {
    pub request_id: Value<u32>,
    pub error_status: Value<i32>,
    pub error_index: Value<i32>,
    #[nproto(encode = Skip)]
    pub _bindings_tag_len: Value<BerTagAndLen>,
    #[nproto(post_encode = post_encode_bindings_tag_len_setrequest)]
    pub var_bindings: Vec<SnmpVarBind>,
}

fn post_encode_bindings_tag_len_setrequest<E: Encoder>(
    me: &SnmpSetRequest,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let bindings_tag_len = if !me._bindings_tag_len.is_auto() {
        me._bindings_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out.len() - old_len)
    };
    let bytes = bindings_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpTrapPdu {
    pub enterprise: Value<BerOid>,
    pub agent_addr: Value<Ipv4Address>,
    pub generic_trap: Value<i32>,
    pub specific_trap: Value<i32>,
    pub time_stamp: Value<u32>,
    #[nproto(encode = Skip)]
    pub _bindings_tag_len: Value<BerTagAndLen>,
    #[nproto(post_encode = post_encode_bindings_tag_len_trap)]
    pub var_bindings: Vec<SnmpVarBind>,
}

fn post_encode_bindings_tag_len_trap<E: Encoder>(
    me: &SnmpTrapPdu,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let bindings_tag_len = if !me._bindings_tag_len.is_auto() {
        me._bindings_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out.len() - old_len)
    };
    let bytes = bindings_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpTrapV2Pdu {
    pub request_id: Value<u32>,
    pub error_status: Value<i32>,
    pub error_index: Value<i32>,
    #[nproto(encode = Skip)]
    pub _bindings_tag_len: Value<BerTagAndLen>,
    #[nproto(post_encode = post_encode_bindings_tag_len_trapv2)]
    pub var_bindings: Vec<SnmpVarBind>,
}

fn post_encode_bindings_tag_len_trapv2<E: Encoder>(
    me: &SnmpTrapV2Pdu,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let bindings_tag_len = if !me._bindings_tag_len.is_auto() {
        me._bindings_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out.len() - old_len)
    };
    let bytes = bindings_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_VERSIONS, Version = 43))]
// #[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 9999))]
// #[nproto(register(UDP_DST_PORT_APPS, DstPort = 9999))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpV3Mock {
   data: Value<GenericAsn1Data>,
}


// Add SNMPv3 support - Foundation structures

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_VERSIONS, Version = 3))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpV3 {
    #[nproto(encode=Skip, fill=auto)]
    pub _seq_tag_len_v3: Value<BerTagAndLen>,

    pub msg_id: Value<u32>,
    pub msg_max_size: Value<u32>,
    pub msg_flags: Value<ByteArray>,
    #[nproto(post_encode = post_encode_seq_tag_len_v3)]
    pub msg_security_model: Value<u32>,

    pub msg_security_parameters: Value<SnmpV3SecurityParameters>,
}

fn post_encode_seq_tag_len_v3<E: Encoder>(
    me: &SnmpV3,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    use std::convert::TryInto;
    let mut skip_point = skip_points;
    let old_len = skip_points[0];
    let mut out_len = 0;
/*
    inner levels are NOT part of this seq, so this chunk of code does not apply

    for i in my_index + 1..encoded_data.len() {
        println!("already encoded data: {}", encoded_data[i].len());
        out_len += encoded_data[i].len();
    }
*/
    // Also account for what has been encoded on this level already
    out_len += out.len() - old_len;


    println!("idx: {} SNMPV3 OLD LEN: {}, OUT LEN: {}", my_index, old_len, out_len);
    let seq_tag_len_v3 = if !me._seq_tag_len_v3.is_auto() {
        me._seq_tag_len_v3.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out_len)
    };
    // find out the length of inner layers
    let bytes = seq_tag_len_v3.encode::<E>();
    out.splice(old_len..old_len, bytes);
}


#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum SnmpV3SecurityParameters {
    #[default]
    None,
    Usm(UsmSecurityParameters),
    Raw(ByteArray),
}

impl FromStr for SnmpV3SecurityParameters {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(SnmpV3SecurityParameters::None),
            "usm" => Ok(SnmpV3SecurityParameters::Usm(
                UsmSecurityParameters::default(),
            )),
            _ => {
                // Try to parse as hex for raw data
                if s.starts_with("0x") {
                    if let Ok(byte_array) = ByteArray::from_str(s) {
                        return Ok(SnmpV3SecurityParameters::Raw(byte_array));
                    }
                }
                Err(ValueParseError::Error)
            }
        }
    }
}

impl Distribution<SnmpV3SecurityParameters> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SnmpV3SecurityParameters {
        match rng.gen_range(0..3) {
            0 => SnmpV3SecurityParameters::None,
            1 => SnmpV3SecurityParameters::Usm(UsmSecurityParameters::default()),
            _ => {
                let len = rng.gen_range(0..32);
                let mut bytes = vec![0u8; len];
                rng.fill_bytes(&mut bytes);
                SnmpV3SecurityParameters::Raw(ByteArray::from(bytes))
            }
        }
    }
}

impl Decode for SnmpV3SecurityParameters {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        // FIXME: For now, decode as raw bytes - in a full implementation,
        // this would parse the specific security model format
        let (bytes, size) = D::decode_octetstring(buf)?;
        Some((SnmpV3SecurityParameters::Raw(ByteArray(bytes)), size))
    }
 }
 
impl Encode for SnmpV3SecurityParameters {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            SnmpV3SecurityParameters::None => {
                // Empty octet string for no security
                Asn1Encoder::encode_octetstring(&[])
            }
            SnmpV3SecurityParameters::Usm(params) => {
                // For USM, we need to encode the UsmSecurityParameters structure
                // This is a simplified version - real implementation would encode the full ASN.1 structure
                let mut result = Vec::new();

                // Encode engine ID
                result.extend(Asn1Encoder::encode_octetstring(
                    &params.msg_authoritative_engine_id.value(),
                ));

                // Encode engine boots (4 bytes)
                result.extend(Asn1Encoder::encode_integer(
                    params.msg_authoritative_engine_boots.value() as i64,
                ));

                // Encode engine time (4 bytes)
                result.extend(Asn1Encoder::encode_integer(
                    params.msg_authoritative_engine_time.value() as i64,
                ));

                // Encode user name
                result.extend(Asn1Encoder::encode_octetstring(
                    &params.msg_user_name.value(),
                ));

                // Encode auth parameters
                result.extend(Asn1Encoder::encode_octetstring(
                    &params.msg_authentication_parameters.value(),
                ));

                // Encode privacy parameters
                result.extend(Asn1Encoder::encode_octetstring(
                    &params.msg_privacy_parameters.value(),
                ));

                // Wrap in sequence
                let seq = Asn1Encoder::encode_sequence(&result);
                Asn1Encoder::encode_octetstring(&seq)
            }
            SnmpV3SecurityParameters::Raw(data) => Asn1Encoder::encode_octetstring(data),
        }
    }

}

// User-based Security Model (USM) parameters - RFC 3414
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_SECURITY_MODELS, ModelNumber = 3))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct UsmSecurityParameters {
    #[nproto(encode=Skip, fill=auto)]
    pub _octet_string_tag_len: Value<BerTagAndLen>,

    #[nproto(encode=Skip, fill=auto)]
    pub _seq_tag_len: Value<BerTagAndLen>,
    
    pub msg_authoritative_engine_id: Value<ByteArray>,
    pub msg_authoritative_engine_boots: Value<u32>,
    pub msg_authoritative_engine_time: Value<u32>,
    pub msg_user_name: Value<ByteArray>,
    pub msg_authentication_parameters: Value<ByteArray>,
    
    // #[nproto(post_encode = post_encode_usm_seq_tag_len)]
    #[nproto(post_encode = post_encode_usm_with_octet_string)]
    pub msg_privacy_parameters: Value<ByteArray>,
}

fn post_encode_usm_with_octet_string<E: Encoder>(
    me: &UsmSecurityParameters,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    let octet_string_skip = skip_points[0];
    let seq_skip = skip_points[1];
    
    // Calculate the length of the SEQUENCE content
    let mut seq_content_len = 0;
    for i in my_index + 1..encoded_data.len() {
        seq_content_len += encoded_data[i].len();
    }
    seq_content_len += out.len() - seq_skip;
    
    // Insert SEQUENCE tag and length
    let seq_tag_len = if !me._seq_tag_len.is_auto() {
        me._seq_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, seq_content_len)
    };
    let seq_bytes = seq_tag_len.encode::<E>();
    let seq_bytes_len = seq_bytes.len();
    out.splice(seq_skip..seq_skip, seq_bytes);
    
    // Calculate total length including the SEQUENCE tag we just added
    let total_content_len = seq_content_len + seq_bytes_len;
    
    // Insert OCTET STRING tag and length at the beginning
    let octet_tag_len = if !me._octet_string_tag_len.is_auto() {
        me._octet_string_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::OctetString, total_content_len)
    };
    let octet_bytes = octet_tag_len.encode::<E>();
    out.splice(octet_string_skip..octet_string_skip, octet_bytes);
}

fn post_encode_usm_seq_tag_len<E: Encoder>(
    me: &UsmSecurityParameters,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    let old_len = skip_points[0];
    let mut out_len = 0;
    for i in my_index + 1..encoded_data.len() {
        out_len += encoded_data[i].len();
    }
    out_len += out.len() - old_len;
    println!("USM SEQ LEN: {}", out_len);
    
    let seq_tag_len = if !me._seq_tag_len.is_auto() {
        me._seq_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out_len)
    };
    
    let bytes = seq_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}


#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpV3ScopedPdu {
    #[nproto(encode=Skip, fill=auto)]
    pub _scoped_pdu_seq_tag_len: Value<BerTagAndLen>,
    
    pub context_engine_id: Value<ByteArray>,
    pub context_name: Value<ByteArray>,
    
    #[nproto(post_encode = post_encode_scoped_pdu_seq_tag_len)]
    pub pdu: Value<SnmpV3Pdu>,
}

fn post_encode_scoped_pdu_seq_tag_len<E: Encoder>(
    me: &SnmpV3ScopedPdu,
    stack: &LayerStack,
    my_index: usize,
    out: &mut Vec<u8>,
    skip_points: &Vec<usize>,
    encoded_data: &EncodingVecVec,
) {
    let old_len = skip_points[0];
    let mut out_len = 0;
    for i in my_index + 1..encoded_data.len() {
        out_len += encoded_data[i].len();
    }
    out_len += out.len() - old_len;

    // out_len += 2; // tag + len bytes?
    
    let seq_tag_len = if !me._scoped_pdu_seq_tag_len.is_auto() {
        me._scoped_pdu_seq_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out_len)
    };

    println!("idx: {} SNMP SCOPED PDU OLD_LEN: {}, OUT_LEN: {}", my_index, old_len, out_len);
    
    let bytes = seq_tag_len.encode::<E>();
    out.splice(old_len..old_len, bytes);
}

impl FromStr for SnmpV3ScopedPdu {
    type Err = ValueParseError;
    
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        Ok(SnmpV3ScopedPdu::default())
    }
}

impl Distribution<SnmpV3ScopedPdu> for Standard {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> SnmpV3ScopedPdu {
        SnmpV3ScopedPdu::default()
    }
}

impl From<Value<SnmpV3ScopedPdu>> for SnmpV3ScopedPdu {
    fn from(value: Value<SnmpV3ScopedPdu>) -> Self {
        match value {
            Value::Set(pdu) => pdu,
            Value::Auto => SnmpV3ScopedPdu::default(),
            Value::Random => SnmpV3ScopedPdu::default(),
            Value::Func(f) => f(),
        }
    }
}



#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SnmpV3Pdu {
    Get(SnmpGetOrResponse),
    GetNext(SnmpGetOrResponse),
    GetBulk(SnmpGetBulkRequest),
    Set(SnmpSetRequest),
    Response(SnmpGetOrResponse),
    Inform(SnmpGetOrResponse),
    Report(SnmpGetOrResponse),
    TrapV2(SnmpTrapV2Pdu),
}

impl Default for SnmpV3Pdu {
    fn default() -> Self {
        SnmpV3Pdu::Get(SnmpGetOrResponse::default())
    }
}


impl Encode for SnmpV3Pdu {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            SnmpV3Pdu::Get(pdu) => {
                // Context tag [0] for Get requests
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(0, &inner)
            }
            SnmpV3Pdu::GetNext(pdu) => {
                // Context tag [1] for GetNext requests
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(1, &inner)
            }
            SnmpV3Pdu::Response(pdu) => {
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(2, &inner)
            }
            SnmpV3Pdu::Set(pdu) => {
                // Context tag [3] for Set requests
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(3, &inner)
            }
            SnmpV3Pdu::GetBulk(pdu) => {
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(5, &inner)
            }
            SnmpV3Pdu::Inform(pdu) => {
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(6, &inner)
            }
            SnmpV3Pdu::Report(pdu) => {
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(8, &inner)
            }
            SnmpV3Pdu::TrapV2(pdu) => {
                // Context tag [7] for SNMPv2c Trap
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(7, &inner)
            }
        }
    }
}

impl Decode for SnmpV3Pdu {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return None;
        }
        
        // Read the tag byte to determine PDU type
        let tag_byte = buf[0];
        
        match tag_byte {
            0xA0 => SnmpGetOrResponse::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::Get(pdu), consumed)),
            
            0xA1 => SnmpGetOrResponse::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::GetNext(pdu), consumed)),
            
            0xA2 => SnmpGetOrResponse::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::Response(pdu), consumed)),
            
            0xA3 => SnmpSetRequest::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::Set(pdu), consumed)),
            
            0xA5 => SnmpGetBulkRequest::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::GetBulk(pdu), consumed)),
            
            0xA6 => SnmpGetOrResponse::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::Inform(pdu), consumed)),
            
            0xA7 => SnmpTrapV2Pdu::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::TrapV2(pdu), consumed)),
            
            0xA8 => SnmpGetOrResponse::decode::<D>(buf)
                .map(|(pdu, consumed)| (SnmpV3Pdu::Report(pdu), consumed)),
            
            // If tag doesn't match any known PDU, fail the decode
            // Framework will automatically fall back to Raw layer
            _ => None,
        }
    }
}

impl FromStr for SnmpV3Pdu {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "get" => Ok(SnmpV3Pdu::Get(SnmpGetOrResponse::default())),
            "getnext" => Ok(SnmpV3Pdu::GetNext(SnmpGetOrResponse::default())),
            "getbulk" => Ok(SnmpV3Pdu::GetBulk(SnmpGetBulkRequest::default())),
            "set" => Ok(SnmpV3Pdu::Set(SnmpSetRequest::default())),
            "response" => Ok(SnmpV3Pdu::Response(SnmpGetOrResponse::default())),
            "inform" => Ok(SnmpV3Pdu::Inform(SnmpGetOrResponse::default())),
            "report" => Ok(SnmpV3Pdu::Report(SnmpGetOrResponse::default())),
            _ => Err(ValueParseError::Error),
        }
    }
}

impl Distribution<SnmpV3Pdu> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SnmpV3Pdu {
        match rng.gen_range(0..8) {
            0 => SnmpV3Pdu::Get(SnmpGetOrResponse::default()),
            1 => SnmpV3Pdu::GetNext(SnmpGetOrResponse::default()),
            2 => SnmpV3Pdu::GetBulk(SnmpGetBulkRequest::default()),
            // 3 => SnmpV3Pdu::Set(SnmpSetRequest::default()),
            4 => SnmpV3Pdu::Response(SnmpGetOrResponse::default()),
            6 => SnmpV3Pdu::Inform(SnmpGetOrResponse::default()),
            _ => SnmpV3Pdu::Report(SnmpGetOrResponse::default()),
        }
    }
}

// Helper traits and implementations for convenience

impl SnmpV3 {
    pub fn new() -> Self {
        Self {
            _seq_tag_len_v3: Value::Auto, 
            msg_id: Value::Set(1),
            msg_max_size: Value::Set(65507),
            msg_flags: SnmpV3::flags(0), // Value::Set(0),          // No auth, no priv
            msg_security_model: Value::Set(3), // USM
            msg_security_parameters: SnmpV3::default_security(),
        }
    }

pub fn set_msg_flags_byte(&mut self, flags: u8) {
        self.msg_flags = Value::Set(ByteArray::from(vec![flags]));
    }
    
    pub fn get_msg_flags_byte(&self) -> u8 {
        match &self.msg_flags {
            Value::Set(bytes) => bytes.0.get(0).copied().unwrap_or(0),
            Value::Auto => 0,
            Value::Random => {
                use rand::Rng;
                rand::thread_rng().gen::<u8>() & 0x07
            }
            Value::Func(f) => f().0.get(0).copied().unwrap_or(0),
        }
    }

    pub fn flags(flags: u8) -> Value<ByteArray> {
       Value::Set(ByteArray::from(vec![flags]))
    }

    pub fn default_security() -> Value<SnmpV3SecurityParameters> {
       // Value::Set(ByteArray::from(vec![]))
       Value::Set(SnmpV3SecurityParameters::None)
    }
    
    // Convenience methods for flag operations
    pub fn has_authentication(&self) -> bool {
        (self.get_msg_flags_byte() & 0x01) != 0
    }
    
    pub fn has_privacy(&self) -> bool {
        (self.get_msg_flags_byte() & 0x02) != 0
    }
    
    pub fn is_reportable(&self) -> bool {
        (self.get_msg_flags_byte() & 0x04) != 0
    }
    
    pub fn set_authentication(&mut self, auth: bool) {
        let current = self.get_msg_flags_byte();
        let new_flags = if auth { current | 0x01 } else { current & !0x01 };
        self.set_msg_flags_byte(new_flags);
    }
    
    pub fn set_privacy(&mut self, priv_flag: bool) {
        let current = self.get_msg_flags_byte();
        let new_flags = if priv_flag { current | 0x02 } else { current & !0x02 };
        self.set_msg_flags_byte(new_flags);
    }
    
    pub fn set_reportable(&mut self, reportable: bool) {
        let current = self.get_msg_flags_byte();
        let new_flags = if reportable { current | 0x04 } else { current & !0x04 };
        self.set_msg_flags_byte(new_flags);
    }


    pub fn with_usm_auth(mut self, user_name: &str, auth_params: Vec<u8>) -> Self {
        self.msg_flags = SnmpV3::flags(1); // Value::Set(1); // Auth, no priv
        self.msg_security_model = Value::Set(3);
        self.msg_security_parameters =
            Value::Set(SnmpV3SecurityParameters::Usm(UsmSecurityParameters {
                _octet_string_tag_len: Value::Auto,
                _seq_tag_len: Value::Auto,
                msg_authoritative_engine_id: Value::Set(ByteArray::from(vec![])),
                msg_authoritative_engine_boots: Value::Set(0),
                msg_authoritative_engine_time: Value::Set(0),
                msg_user_name: Value::Set(ByteArray::from(user_name.as_bytes().to_vec())),
                msg_authentication_parameters: Value::Set(ByteArray::from(auth_params)),
                msg_privacy_parameters: Value::Set(ByteArray::from(vec![])),
            }));
        self
    }

    pub fn with_usm_auth_priv(
        mut self,
        user_name: &str,
        auth_params: Vec<u8>,
        priv_params: Vec<u8>,
    ) -> Self {
        self.msg_flags = SnmpV3::flags(3); // Value::Set(3); // Auth and priv
        self.msg_security_model = Value::Set(3);
        self.msg_security_parameters =
            Value::Set(SnmpV3SecurityParameters::Usm(UsmSecurityParameters {
                _octet_string_tag_len: Value::Auto,
                _seq_tag_len: Value::Auto,
                msg_authoritative_engine_id: Value::Set(ByteArray::from(vec![])),
                msg_authoritative_engine_boots: Value::Set(0),
                msg_authoritative_engine_time: Value::Set(0),
                msg_user_name: Value::Set(ByteArray::from(user_name.as_bytes().to_vec())),
                msg_authentication_parameters: Value::Set(ByteArray::from(auth_params)),
                msg_privacy_parameters: Value::Set(ByteArray::from(priv_params)),
            }));
        self
    }
}

// Error types for better error handling
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnmpError {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2,
    BadValue = 3,
    ReadOnly = 4,
    GenErr = 5,
    NoAccess = 6,
    WrongType = 7,
    WrongLength = 8,
    WrongEncoding = 9,
    WrongValue = 10,
    NoCreation = 11,
    InconsistentValue = 12,
    ResourceUnavailable = 13,
    CommitFailed = 14,
    UndoFailed = 15,
    AuthorizationError = 16,
    NotWritable = 17,
    InconsistentName = 18,
}

impl From<i32> for SnmpError {
    fn from(value: i32) -> Self {
        match value {
            0 => SnmpError::NoError,
            1 => SnmpError::TooBig,
            2 => SnmpError::NoSuchName,
            3 => SnmpError::BadValue,
            4 => SnmpError::ReadOnly,
            5 => SnmpError::GenErr,
            6 => SnmpError::NoAccess,
            7 => SnmpError::WrongType,
            8 => SnmpError::WrongLength,
            9 => SnmpError::WrongEncoding,
            10 => SnmpError::WrongValue,
            11 => SnmpError::NoCreation,
            12 => SnmpError::InconsistentValue,
            13 => SnmpError::ResourceUnavailable,
            14 => SnmpError::CommitFailed,
            15 => SnmpError::UndoFailed,
            16 => SnmpError::AuthorizationError,
            17 => SnmpError::NotWritable,
            18 => SnmpError::InconsistentName,
            _ => SnmpError::GenErr,
        }
    }
}

impl From<SnmpError> for i32 {
    fn from(error: SnmpError) -> Self {
        error as i32
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SnmpPdu {
    Get(SnmpGetOrResponse),
    GetNext(SnmpGetOrResponse),
    Response(SnmpGetOrResponse),
    Set(SnmpSetRequest),
    GetBulk(SnmpGetBulkRequest), // SNMPv2c only
    TrapV1(SnmpTrapPdu),         // SNMPv1 trap
    TrapV2(SnmpTrapV2Pdu),       // SNMPv2c trap
}

impl Default for SnmpPdu {
    fn default() -> Self {
        SnmpPdu::Get(SnmpGetOrResponse::default())
    }
}

impl FromStr for SnmpPdu {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "get" => Ok(SnmpPdu::Get(SnmpGetOrResponse::default())),
            "getnext" => Ok(SnmpPdu::GetNext(SnmpGetOrResponse::default())),
            "response" => Ok(SnmpPdu::Response(SnmpGetOrResponse::default())),
            "set" => Ok(SnmpPdu::Set(SnmpSetRequest::default())),
            "getbulk" => Ok(SnmpPdu::GetBulk(SnmpGetBulkRequest::default())),
            "trapv1" => Ok(SnmpPdu::TrapV1(SnmpTrapPdu::default())),
            "trapv2" => Ok(SnmpPdu::TrapV2(SnmpTrapV2Pdu::default())),
            _ => Err(ValueParseError::Error),
        }
    }
}

impl Distribution<SnmpPdu> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SnmpPdu {
        match rng.gen_range(0..7) {
            0 => SnmpPdu::Get(SnmpGetOrResponse::default()),
            1 => SnmpPdu::GetNext(SnmpGetOrResponse::default()),
            2 => SnmpPdu::Response(SnmpGetOrResponse::default()),
            3 => SnmpPdu::Set(SnmpSetRequest::default()),
            4 => SnmpPdu::GetBulk(SnmpGetBulkRequest::default()),
            5 => SnmpPdu::TrapV1(SnmpTrapPdu::default()),
            _ => SnmpPdu::TrapV2(SnmpTrapV2Pdu::default()),
        }
    }
}

impl Encode for SnmpPdu {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            SnmpPdu::Get(pdu) => {
                // Context tag [0] for Get requests
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(0, &inner)
            }
            SnmpPdu::GetNext(pdu) => {
                // Context tag [1] for GetNext requests
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(1, &inner)
            }
            SnmpPdu::Response(pdu) => {
                // Context tag [2] for Response
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(2, &inner)
            }
            SnmpPdu::Set(pdu) => {
                // Context tag [3] for Set requests
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(3, &inner)
            }
            SnmpPdu::GetBulk(pdu) => {
                // Context tag [5] for GetBulk requests (SNMPv2c only)
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(5, &inner)
            }
            SnmpPdu::TrapV1(pdu) => {
                // Context tag [4] for SNMPv1 Trap
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(4, &inner)
            }
            SnmpPdu::TrapV2(pdu) => {
                // Context tag [7] for SNMPv2c Trap
                let inner = pdu.encode::<E>();
                Asn1Encoder::encode_context_tag(7, &inner)
            }
        }
    }
}

impl Decode for SnmpPdu {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return None;
        }

        // Check the context tag to determine PDU type
        let tag = buf[0];
        if (tag & 0x80) == 0 {
            return None; // Not a context-specific tag
        }

        let pdu_type = tag & 0x1F;
        match pdu_type {
            0 => {
                // Get request
                let (inner_data, size) = Asn1Decoder::decode_context_tag(0, buf)?;
                let (pdu, _) = SnmpGetOrResponse::decode::<D>(&inner_data)?;
                Some((SnmpPdu::Get(pdu), size))
            }
            1 => {
                // GetNext request
                let (inner_data, size) = Asn1Decoder::decode_context_tag(1, buf)?;
                let (pdu, _) = SnmpGetOrResponse::decode::<D>(&inner_data)?;
                Some((SnmpPdu::GetNext(pdu), size))
            }
            2 => {
                // Response
                let (inner_data, size) = Asn1Decoder::decode_context_tag(2, buf)?;
                let (pdu, _) = SnmpGetOrResponse::decode::<D>(&inner_data)?;
                Some((SnmpPdu::Response(pdu), size))
            }
            3 => {
                // Set request
                let (inner_data, size) = Asn1Decoder::decode_context_tag(3, buf)?;
                let (pdu, _) = SnmpSetRequest::decode::<D>(&inner_data)?;
                Some((SnmpPdu::Set(pdu), size))
            }
            4 => {
                // SNMPv1 Trap
                let (inner_data, size) = Asn1Decoder::decode_context_tag(4, buf)?;
                let (pdu, _) = SnmpTrapPdu::decode::<D>(&inner_data)?;
                Some((SnmpPdu::TrapV1(pdu), size))
            }
            5 => {
                // GetBulk request (SNMPv2c only)
                let (inner_data, size) = Asn1Decoder::decode_context_tag(5, buf)?;
                let (pdu, _) = SnmpGetBulkRequest::decode::<D>(&inner_data)?;
                Some((SnmpPdu::GetBulk(pdu), size))
            }
            7 => {
                // SNMPv2c Trap
                let (inner_data, size) = Asn1Decoder::decode_context_tag(7, buf)?;
                let (pdu, _) = SnmpTrapV2Pdu::decode::<D>(&inner_data)?;
                Some((SnmpPdu::TrapV2(pdu), size))
            }
            _ => None, // Unknown PDU type
        }
    }
}

// Add the decode_context_tag method to Asn1Decoder
impl Asn1Decoder {
    pub fn decode_context_tag(expected_tag: u8, buf: &[u8]) -> Option<(Vec<u8>, usize)> {
        if buf.is_empty() {
            return None;
        }

        let tag = buf[0];
        let expected_tag_byte = 0x80 | expected_tag; // Context-specific tag

        if tag != expected_tag_byte {
            return None;
        }

        let mut offset = 1;

        // Decode length
        if offset >= buf.len() {
            return None;
        }

        let length = if buf[offset] & 0x80 == 0 {
            // Short form
            let len = buf[offset] as usize;
            offset += 1;
            len
        } else {
            // Long form
            let len_octets = (buf[offset] & 0x7F) as usize;
            offset += 1;

            if len_octets == 0 || len_octets > 4 || offset + len_octets > buf.len() {
                return None;
            }

            let mut len = 0usize;
            for _ in 0..len_octets {
                len = (len << 8) | (buf[offset] as usize);
                offset += 1;
            }
            len
        };

        if offset + length > buf.len() {
            return None;
        }

        let data = buf[offset..offset + length].to_vec();
        Some((data, offset + length))
    }
}

// Step 3: Add convenience methods, builders, and complete the SNMP implementation

use std::collections::HashMap;

// Add convenience constructors and builder methods
impl Snmp {
    pub fn v1_get(community: &str, oids: &Vec<&str>) -> LayerStack {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();

        let get_pdu = SnmpGet(SnmpGetOrResponse {
            request_id: Value::Set(rand::random()),
            error_status: Value::Set(0),
            error_index: Value::Set(0),
            _bindings_tag_len: Value::Auto,
            var_bindings,
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(0),
            })
            .push(SnmpV2c {
                community: Value::Set(Community::from(community)),
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(160))), // Get tag
                _pdu_len: Value::Auto,
            })
            .push(get_pdu)
    }
    /// Create a new SNMPv2c GET request
    pub fn v2c_get(community: &str, oids: &Vec<&str>) -> LayerStack {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();

        let get_pdu = SnmpGet(SnmpGetOrResponse {
            request_id: Value::Set(rand::random()),
            error_status: Value::Set(0),
            error_index: Value::Set(0),
            _bindings_tag_len: Value::Auto,
            var_bindings,
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(1),
            }) // SNMPv2c
            .push(SnmpV2c {
                community: Value::Set(Community::from(community)),
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(160))), // Get tag
                _pdu_len: Value::Auto,
            })
            .push(get_pdu)
    }

    /// Create a new SNMPv1 SET request
    pub fn v1_set(community: &str, bindings: Vec<(&str, SnmpValue)>) -> LayerStack {
        let var_bindings = bindings
            .into_iter()
            .map(|(oid, value)| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(value),
            })
            .collect();

        let set_pdu = SnmpSet(SnmpSetRequest {
            request_id: Value::Set(rand::random()),
            error_status: Value::Set(0),
            error_index: Value::Set(0),
            _bindings_tag_len: Value::Auto,
            var_bindings,
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(0),
            }) // SNMPv1
            .push(SnmpV2c {
                community: Value::Set(Community::from(community)),
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(163))), // Set tag
                _pdu_len: Value::Auto,
            })
            .push(set_pdu)
    }
    /// Create a new SNMPv2c SET request
    pub fn v2c_set(community: &str, bindings: Vec<(&str, SnmpValue)>) -> LayerStack {
        let var_bindings = bindings
            .into_iter()
            .map(|(oid, value)| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(value),
            })
            .collect();

        let set_pdu = SnmpSet(SnmpSetRequest {
            request_id: Value::Set(rand::random()),
            error_status: Value::Set(0),
            error_index: Value::Set(0),
            _bindings_tag_len: Value::Auto,
            var_bindings,
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(1),
            }) // SNMPv2c
            .push(SnmpV2c {
                community: Value::Set(Community::from(community)),
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(163))), // Set tag
                _pdu_len: Value::Auto,
            })
            .push(set_pdu)
    }

    /// Create a new SNMPv2c GETBULK request
    pub fn v2c_getbulk(
        community: &str,
        non_repeaters: i32,
        max_repetitions: i32,
        oids: &Vec<&str>,
    ) -> LayerStack {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();

        let getbulk_pdu = SnmpGetBulk(SnmpGetBulkRequest {
            request_id: Value::Set(rand::random()),
            non_repeaters: Value::Set(non_repeaters),
            max_repetitions: Value::Set(max_repetitions),
            _bindings_tag_len: Value::Auto,
            var_bindings,
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(1),
            }) // SNMPv2c
            .push(SnmpV2c {
                community: Value::Set(Community::from(community)),
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(165))), // GetBulk tag
                _pdu_len: Value::Auto,
            })
            .push(getbulk_pdu)
    }
    /// Create a response from a request
    pub fn create_response(&self, bindings: Vec<(&str, SnmpValue)>) -> LayerStack {
        let var_bindings = bindings
            .into_iter()
            .map(|(oid, value)| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(value),
            })
            .collect();

        // For now, use a random request ID since we can't easily extract it from LayerStack
        let request_id = rand::random();

        let response_pdu = SnmpGetResponse(SnmpGetOrResponse {
            request_id: Value::Set(request_id),
            error_status: Value::Set(0),
            error_index: Value::Set(0),
            _bindings_tag_len: Value::Auto,
            var_bindings,
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(1),
            }) // Default to SNMPv2c
            .push(SnmpV2c {
                community: Value::Set(Community::from("public")), // Default community
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(162))), // Response tag
                _pdu_len: Value::Auto,
            })
            .push(response_pdu)
    }
    /// Create an error response
    pub fn create_error_response(&self, error_status: SnmpError, error_index: i32) -> LayerStack {
        // For now, use a random request ID since we can't easily extract it from LayerStack
        let request_id = rand::random();

        let response_pdu = SnmpGetResponse(SnmpGetOrResponse {
            request_id: Value::Set(request_id),
            error_status: Value::Set(error_status as i32),
            error_index: Value::Set(error_index),
            _bindings_tag_len: Value::Auto,
            var_bindings: vec![],
        });

        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(1),
            }) // Default to SNMPv2c
            .push(SnmpV2c {
                community: Value::Set(Community::from("public")), // Default community
                _pdu_tag: Value::Set(BerTag(asn1::Tag::UnknownTag(162))), // Response tag
                _pdu_len: Value::Auto,
            })
            .push(response_pdu)
    }

    /// Create a new SNMPv3 GET request with no security using LayerStack
    pub fn v3_get(oids: &Vec<&str>) -> LayerStack {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();
 

        let scoped_pdu = SnmpV3ScopedPdu {
            _scoped_pdu_seq_tag_len: Value::Auto,
            context_engine_id: Value::Set(ByteArray::from(vec![0x40, 0x41])),
            context_name: Value::Set(ByteArray::from(vec![0x42, 0x43, 0x44])),
            pdu: Value::Set(SnmpV3Pdu::Get(SnmpGetOrResponse {
                request_id: Value::Set(42), // rand::random()),
                error_status: Value::Set(0),
                error_index: Value::Set(0),
                _bindings_tag_len: Value::Auto,
                var_bindings,
            })),
        };


        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(3),
            })
            .push(SnmpV3 {
                _seq_tag_len_v3: Value::Auto,
                msg_id: Value::Set(rand::random()),
                msg_max_size: Value::Set(65507),
                msg_flags: SnmpV3::flags(0), // Value::Set(0),          // No auth, no priv
                msg_security_model: Value::Auto, // Value::Set(0), // Clear
                msg_security_parameters: SnmpV3::default_security(),
            }
                // .with_usm_auth("testing123", vec![])
            ).push(scoped_pdu)
    }

    /// Create a new SNMPv3 GETNEXT request
    pub fn v3_getnext(oids: &Vec<&str>) -> LayerStack {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();

        let scoped_pdu = SnmpV3ScopedPdu {
            _scoped_pdu_seq_tag_len: Value::Auto,
            context_engine_id: Value::Set(ByteArray::from(vec![])),
            context_name: Value::Set(ByteArray::from(vec![])),
            pdu: Value::Set(SnmpV3Pdu::GetNext(SnmpGetOrResponse {
                request_id: Value::Set(rand::random()),
                error_status: Value::Set(0),
                error_index: Value::Set(0),
                _bindings_tag_len: Value::Auto,
                var_bindings,
            })),
        };


        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(3),
            })
            .push(SnmpV3 {
                _seq_tag_len_v3: Value::Auto,
                msg_id: Value::Set(rand::random()),
                msg_max_size: Value::Set(65507),
                msg_flags: SnmpV3::flags(0), // Value::Set(0),          // No auth, no priv
                msg_security_model: Value::Set(3), // USM
                msg_security_parameters: SnmpV3::default_security(),
            })
    }

    /// Create a new SNMPv3 GET request with USM authentication
    pub fn v3_get_auth(user_name: &str, engine_id: &[u8], oids: &Vec<&str>) -> LayerStack {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();


        let scoped_pdu = SnmpV3ScopedPdu {
            _scoped_pdu_seq_tag_len: Value::Auto,
            context_engine_id: Value::Set(ByteArray::from(vec![])),
            context_name: Value::Set(ByteArray::from(vec![])),
            pdu: Value::Set(SnmpV3Pdu::Get(SnmpGetOrResponse {
                request_id: Value::Set(rand::random()),
                error_status: Value::Set(0),
                error_index: Value::Set(0),
                _bindings_tag_len: Value::Auto,
                var_bindings,
            })),
        };


        LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(3),
            })
            .push(SnmpV3 {
                _seq_tag_len_v3: Value::Auto,
                msg_id: Value::Set(rand::random()),
                msg_max_size: Value::Set(65507),
                msg_flags: SnmpV3::flags(1), // Value::Set(1),          // Auth, no priv
                msg_security_model: Value::Set(3), // USM
                msg_security_parameters: SnmpV3::default_security(),
            })
    }

}

// Add convenience methods for SNMPv3
impl SnmpV3 {
    /// Create a new SNMPv3 GET request with no security
    pub fn no_auth_get(oids: &Vec<&str>) -> Self {
        let var_bindings = oids
            .into_iter()
            .map(|oid| SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            })
            .collect();

        let scoped_pdu = SnmpV3ScopedPdu {
            _scoped_pdu_seq_tag_len: Value::Auto,
            context_engine_id: Value::Set(ByteArray::from(vec![])),
            context_name: Value::Set(ByteArray::from(vec![])),
            pdu: Value::Set(SnmpV3Pdu::Get(SnmpGetOrResponse {
                request_id: Value::Set(rand::random()),
                error_status: Value::Set(0),
                error_index: Value::Set(0),
                _bindings_tag_len: Value::Auto,
                var_bindings,
            })),
        };


        SnmpV3 {
            _seq_tag_len_v3: Value::Auto,
            msg_id: Value::Set(rand::random()),
            msg_max_size: Value::Set(65507),
            msg_flags: SnmpV3::flags(0), // Value::Set(0),          // No auth, no priv
            msg_security_model: Value::Set(3), // USM
            msg_security_parameters: SnmpV3::default_security(),
        }
    }

    /// Create a new SNMPv3 GET request with USM authentication
    pub fn usm_auth_get(user_name: &str, engine_id: &[u8], oids: &Vec<&str>) -> Self {
        let mut snmp = Self::no_auth_get(oids);
        snmp = snmp.with_usm_auth(user_name, vec![]); // Empty auth params for now

        // Set the engine ID
        if let Value::Set(SnmpV3SecurityParameters::Usm(ref mut usm)) =
            &mut snmp.msg_security_parameters
        {
            usm.msg_authoritative_engine_id = Value::Set(ByteArray::from(engine_id));
        }

        snmp
    }

    /// Check if the message requires authentication
    pub fn requires_auth(&self) -> bool {
        (self.msg_flags.value()[0] & 0x01) != 0
    }

    /// Check if the message requires privacy (encryption)
    pub fn requires_privacy(&self) -> bool {
        (self.msg_flags.value()[0] & 0x02) != 0
    }

    /// Get the user name from USM security parameters
    pub fn user_name(&self) -> Option<String> {
        match &self.msg_security_parameters.value() {
            SnmpV3SecurityParameters::Usm(usm) => {
                Some(String::from_utf8_lossy(&usm.msg_user_name.value().0).to_string())
            }
            _ => None,
        }
    }

}

// Add utility functions for working with SNMP values
impl SnmpValue {
    /// Create an integer value
    pub fn integer(value: i64) -> Self {
        SnmpValue::Integer(value)
    }

    /// Create a string value
    pub fn string(value: &str) -> Self {
        SnmpValue::OctetString(value.as_bytes().to_vec())
    }

    /// Create an OID value
    pub fn oid(value: &str) -> Self {
        SnmpValue::ObjectIdentifier(BerOid::from_str(value).unwrap_or_default())
    }

    /// Create a counter32 value
    pub fn counter32(value: u32) -> Self {
        SnmpValue::Counter32(value)
    }

    /// Create a gauge32 value
    pub fn gauge32(value: u32) -> Self {
        SnmpValue::Gauge32(value)
    }

    /// Create a timeticks value
    pub fn timeticks(value: u32) -> Self {
        SnmpValue::TimeTicks(value)
    }

    /// Create a counter64 value
    pub fn counter64(value: u64) -> Self {
        SnmpValue::Counter64(value)
    }

    /// Create an IP address value
    pub fn ip_address(ip: &str) -> Self {
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            SnmpValue::IpAddress(Ipv4Address::from(addr))
        } else {
            SnmpValue::Null
        }
    }

    /// Get the type name as a string
    pub fn type_name(&self) -> &'static str {
        match self {
            SnmpValue::Integer(_) => "INTEGER",
            SnmpValue::OctetString(_) => "OCTET STRING",
            SnmpValue::Null => "NULL",
            SnmpValue::ObjectIdentifier(_) => "OBJECT IDENTIFIER",
            SnmpValue::IpAddress(_) => "IpAddress",
            SnmpValue::Counter32(_) => "Counter32",
            SnmpValue::Gauge32(_) => "Gauge32",
            SnmpValue::TimeTicks(_) => "TimeTicks",
            SnmpValue::Opaque(_) => "Opaque",
            SnmpValue::Counter64(_) => "Counter64",
            SnmpValue::NoSuchObject => "noSuchObject",
            SnmpValue::NoSuchInstance => "noSuchInstance",
            SnmpValue::EndOfMibView => "endOfMibView",
            x => panic!("Inknown type name: {:?}", x),
        }
    }

    /// Try to convert to integer
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            SnmpValue::Integer(i) => Some(*i),
            SnmpValue::Counter32(c) => Some(*c as i64),
            SnmpValue::Gauge32(g) => Some(*g as i64),
            SnmpValue::TimeTicks(t) => Some(*t as i64),
            SnmpValue::Counter64(c) => Some(*c as i64),
            _ => None,
        }
    }

    /// Try to convert to string
    pub fn as_string(&self) -> Option<String> {
        match self {
            SnmpValue::OctetString(bytes) => Some(String::from_utf8_lossy(bytes).to_string()),
            SnmpValue::ObjectIdentifier(oid) => Some(oid.to_string()),
            SnmpValue::IpAddress(ip) => Some(ip.to_string()),
            _ => None,
        }
    }
}

// Add error handling utilities
impl SnmpError {
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => SnmpError::NoError,
            1 => SnmpError::TooBig,
            2 => SnmpError::NoSuchName,
            3 => SnmpError::BadValue,
            4 => SnmpError::ReadOnly,
            5 => SnmpError::GenErr,
            6 => SnmpError::NoAccess,
            7 => SnmpError::WrongType,
            8 => SnmpError::WrongLength,
            9 => SnmpError::WrongEncoding,
            10 => SnmpError::WrongValue,
            11 => SnmpError::NoCreation,
            12 => SnmpError::InconsistentValue,
            13 => SnmpError::ResourceUnavailable,
            14 => SnmpError::CommitFailed,
            15 => SnmpError::UndoFailed,
            16 => SnmpError::AuthorizationError,
            17 => SnmpError::NotWritable,
            18 => SnmpError::InconsistentName,
            _ => SnmpError::GenErr,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SnmpError::NoError => "No error",
            SnmpError::TooBig => "Response too big",
            SnmpError::NoSuchName => "No such name",
            SnmpError::BadValue => "Bad value",
            SnmpError::ReadOnly => "Read only",
            SnmpError::GenErr => "General error",
            SnmpError::NoAccess => "No access",
            SnmpError::WrongType => "Wrong type",
            SnmpError::WrongLength => "Wrong length",
            SnmpError::WrongEncoding => "Wrong encoding",
            SnmpError::WrongValue => "Wrong value",
            SnmpError::NoCreation => "No creation",
            SnmpError::InconsistentValue => "Inconsistent value",
            SnmpError::ResourceUnavailable => "Resource unavailable",
            SnmpError::CommitFailed => "Commit failed",
            SnmpError::UndoFailed => "Undo failed",
            SnmpError::AuthorizationError => "Authorization error",
            SnmpError::NotWritable => "Not writable",
            SnmpError::InconsistentName => "Inconsistent name",
        }
    }
}

// Add builder pattern for complex SNMP messages
pub struct SnmpBuilder {
    version: i32,
    community: Option<String>,
    request_id: Option<u32>,
    bindings: Vec<(String, SnmpValue)>,
}

impl SnmpBuilder {
    pub fn new() -> Self {
        Self {
            version: 1, // Default to SNMPv2c
            community: None,
            request_id: None,
            bindings: Vec::new(),
        }
    }

    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    pub fn community(mut self, community: &str) -> Self {
        self.community = Some(community.to_string());
        self
    }

    pub fn request_id(mut self, id: u32) -> Self {
        self.request_id = Some(id);
        self
    }

    pub fn add_binding(mut self, oid: &str, value: SnmpValue) -> Self {
        self.bindings.push((oid.to_string(), value));
        self
    }

    pub fn add_null_binding(mut self, oid: &str) -> Self {
        self.bindings.push((oid.to_string(), SnmpValue::Null));
        self
    }

    pub fn build_get(self) -> LayerStack {
        let community = self.community.unwrap_or_else(|| "public".to_string());
        let request_id = self.request_id.unwrap_or_else(|| rand::random());

        let null_bindings_str: Vec<&str> = self
            .bindings
            .iter()
            .map(|(oid, value)| oid.as_str())
            .collect();

        match self.version {
            1 => Snmp::v1_get(&community, &null_bindings_str),
            2 => Snmp::v2c_get(&community, &null_bindings_str),
            _ => todo!(),
        }
    }
}

// Add common SNMP OIDs as constants
pub mod oids {
    pub const SYSTEM_DESCRIPTION: &str = "1.3.6.1.2.1.1.1.0";
    pub const SYSTEM_OBJECT_ID: &str = "1.3.6.1.2.1.1.2.0";
    pub const SYSTEM_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
    pub const SYSTEM_CONTACT: &str = "1.3.6.1.2.1.1.4.0";
    pub const SYSTEM_NAME: &str = "1.3.6.1.2.1.1.5.0";
    pub const SYSTEM_LOCATION: &str = "1.3.6.1.2.1.1.6.0";
    pub const SYSTEM_SERVICES: &str = "1.3.6.1.2.1.1.7.0";

    pub const IF_TABLE: &str = "1.3.6.1.2.1.2.2";
    pub const IF_NUMBER: &str = "1.3.6.1.2.1.2.1.0";
    pub const IF_INDEX: &str = "1.3.6.1.2.1.2.2.1.1";
    pub const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
    pub const IF_TYPE: &str = "1.3.6.1.2.1.2.2.1.3";
    pub const IF_MTU: &str = "1.3.6.1.2.1.2.2.1.4";
    pub const IF_SPEED: &str = "1.3.6.1.2.1.2.2.1.5";
    pub const IF_PHYS_ADDRESS: &str = "1.3.6.1.2.1.2.2.1.6";
    pub const IF_ADMIN_STATUS: &str = "1.3.6.1.2.1.2.2.1.7";
    pub const IF_OPER_STATUS: &str = "1.3.6.1.2.1.2.2.1.8";

    pub const SNMP_IN_PKTS: &str = "1.3.6.1.2.1.11.1.0";
    pub const SNMP_OUT_PKTS: &str = "1.3.6.1.2.1.11.2.0";
    pub const SNMP_IN_BAD_VERSIONS: &str = "1.3.6.1.2.1.11.3.0";
    pub const SNMP_IN_BAD_COMMUNITY_NAMES: &str = "1.3.6.1.2.1.11.4.0";
    pub const SNMP_IN_ASN_PARSE_ERRS: &str = "1.3.6.1.2.1.11.6.0";
}

// Example usage functions
impl Snmp {
    /// Example: Create a simple system info query
    pub fn system_info_query() -> LayerStack {
        Self::v2c_get(
            "public",
            &vec![
                oids::SYSTEM_DESCRIPTION,
                oids::SYSTEM_NAME,
                oids::SYSTEM_LOCATION,
                oids::SYSTEM_UPTIME,
            ],
        )
    }

    /// Example: Create an interface table walk request  
    pub fn interface_walk() -> LayerStack {
        Self::v2c_getbulk("public", 0, 10, &vec![oids::IF_TABLE])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_v1_get() {
        let snmp = Snmp::v1_get("public", &vec!["1.3.6.1.2.1.1.1.0"]);
    }

    #[test]
    fn test_snmp_v2c_getbulk() {
        let snmp = Snmp::v2c_getbulk("public", 0, 10, &vec!["1.3.6.1.2.1.2.2"]);
    }

    #[test]
    fn test_snmpv3_no_auth() {
        let snmp = SnmpV3::no_auth_get(&vec!["1.3.6.1.2.1.1.1.0"]);
        println!("SNMPv3: {:#?}", &snmp);
        // assert_eq!(1,2);
    }

    #[test]
    fn test_snmp_value_creation() {
        let int_val = SnmpValue::integer(42);
        assert_eq!(int_val.as_integer(), Some(42));
        assert_eq!(int_val.type_name(), "INTEGER");

        let str_val = SnmpValue::string("test");
        assert_eq!(str_val.as_string(), Some("test".to_string()));
        assert_eq!(str_val.type_name(), "OCTET STRING");
    }

    #[test]
    fn test_builder_pattern() {
        let snmp = SnmpBuilder::new()
            .version(1)
            .community("test")
            .add_null_binding("1.3.6.1.2.1.1.1.0")
            .add_binding("1.3.6.1.2.1.1.5.0", SnmpValue::string("router1"))
            .build_get();
    }
}





use crate::asn1::{ASN1Object, Tag, Value as Asn1Value};
// use serde::{Deserialize, Serialize};

// Generic ASN.1 data structure
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenericAsn1Data {
    pub objects: Vec<ASN1Object>,
}

impl Default for GenericAsn1Data {
    fn default() -> Self {
        Self {
            objects: Vec::new(),
        }
    }
}

impl Encode for GenericAsn1Data {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        for obj in &self.objects {
            result.extend(Asn1Encoder::encode_asn1_object(obj));
        }
        
        result
    }
}

impl Decode for GenericAsn1Data {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let mut objects = Vec::new();
        let mut cursor = 0;
        
        // Parse all ASN.1 objects in the buffer
        while cursor < buf.len() {
            match Asn1Decoder::parse(buf, cursor) {
                Ok((obj, delta)) => {
                    objects.push(obj);
                    cursor += delta;
                }
                Err(_) => {
                    // If we can't parse more, stop
                    break;
                }
            }
        }
        
        let data = GenericAsn1Data { objects };
        Some((data, cursor))
    }
}


// Add FromStr implementation (required by Value<T>)
impl FromStr for GenericAsn1Data {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // For now, just return an empty structure
        // In a real implementation, you might parse ASN.1 text representation
        Ok(GenericAsn1Data::default())
    }
}

// Add Distribution implementation (required by Value<T>)
impl Distribution<GenericAsn1Data> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> GenericAsn1Data {
        // Generate some random ASN.1 objects for testing
        let mut objects = Vec::new();
        
        // Add a random integer
        objects.push(ASN1Object {
            tag: asn1::Tag::Integer,
            value: asn1::Value::Integer(rng.gen_range(-1000..1000)),
        });
        
        // Add a random string
        objects.push(ASN1Object {
            tag: asn1::Tag::OctetString,
            value: asn1::Value::OctetString(b"random".to_vec()),
        });
        
        GenericAsn1Data { objects }
    }
}

// Generic ASN.1 NetworkProtocol
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
/// #[nproto(decode = decode_generic_asn1, encode = encode_generic_asn1)]
pub struct GenericAsn1 {
    #[nproto(decode = decode_generic_asn1_field, encode = encode_generic_asn1_field)]
    pub data: Value<GenericAsn1Data>,
}

// Fix 3: Add the missing From<Value<T>> implementation

// Add this implementation for GenericAsn1Data:
impl From<Value<GenericAsn1Data>> for GenericAsn1Data {
    fn from(value: Value<GenericAsn1Data>) -> Self {
        match value {
            Value::Set(data) => data,
            Value::Auto => GenericAsn1Data::default(),
            Value::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen()
            }
            Value::Func(f) => f(),
        }
    }
}

// Also need to fix the decode function signature - it should return the field type, not Value<T>
fn decode_generic_asn1_field<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut GenericAsn1,
) -> Option<(GenericAsn1Data, usize)> {  // Changed return type here
    let mut objects = Vec::new();
    let mut cursor = 0;
    
    // Parse all ASN.1 objects in the remaining buffer
    while cursor < buf[ci..].len() {
        match Asn1Decoder::parse(&buf[ci..], cursor) {
            Ok((obj, delta)) => {
                objects.push(obj);
                cursor += delta;
            }
            Err(_) => {
                // If we can't parse more, stop
                break;
            }
        }
    }
    
    let data = GenericAsn1Data { objects };
    Some((data, cursor))  // Return the data directly, not wrapped in Value
}

// Also fix the encode function to access the field correctly
fn encode_generic_asn1_field<E: Encoder>(
    me: &GenericAsn1,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    let mut result = Vec::new();
    
    // Access the data through the Value wrapper
    let data = match &me.data {
        Value::Set(data) => data,
        Value::Auto => &GenericAsn1Data::default(),
        Value::Random => {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            &rng.gen()
        }
        Value::Func(f) => &f(),
    };
    
    for obj in &data.objects {
        result.extend(Asn1Encoder::encode_asn1_object(obj));
    }
    
    result
}

// Custom decode function that parses all ASN.1 objects in the buffer
fn decode_generic_asn1<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut GenericAsn1,
) -> Option<(Value<GenericAsn1Data>, usize)> {
    let mut objects = Vec::new();
    let mut cursor = ci;
    let buf = &buf[ci..];
    
    // Parse all ASN.1 objects in the buffer
    while cursor < buf.len() {
        match Asn1Decoder::parse(&buf, cursor - ci) {
            Ok((obj, delta)) => {
                objects.push(obj);
                cursor += delta;
            }
            Err(_) => {
                // If we can't parse more, stop
                break;
            }
        }
    }
    
    let data = GenericAsn1Data { objects };
    Some((Value::Set(data), cursor - ci))
}

// Custom encode function that encodes all ASN.1 objects
fn encode_generic_asn1<E: Encoder>(
    me: &GenericAsn1,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    let mut result = Vec::new();
    
    for obj in &me.data.value().objects {
        result.extend(Asn1Encoder::encode_asn1_object(obj));
    }
    
    result
}

// Convenience methods for creating ASN.1 structures
impl GenericAsn1 {
    pub fn new() -> Self {
        Self {
            data: Value::Set(GenericAsn1Data::default()),
        }
    }
    
    pub fn from_objects(objects: Vec<ASN1Object>) -> Self {
        Self {
            data: Value::Set(GenericAsn1Data { objects }),
        }
    }
    
    pub fn add_object(&mut self, obj: ASN1Object) {
        if let Value::Set(ref mut data) = &mut self.data {
            data.objects.push(obj);
        }
    }
    
    pub fn add_integer(&mut self, value: i64) -> &mut Self {
        self.add_object(ASN1Object {
            tag: Tag::Integer,
            value: Asn1Value::Integer(value),
        });
        self
    }
    
    pub fn add_string(&mut self, value: &str) -> &mut Self {
        self.add_object(ASN1Object {
            tag: Tag::OctetString,
            value: Asn1Value::OctetString(value.as_bytes().to_vec()),
        });
        self
    }
    
    pub fn add_oid(&mut self, oid: Vec<u64>) -> &mut Self {
        self.add_object(ASN1Object {
            tag: Tag::ObjectIdentifier,
            value: Asn1Value::ObjectIdentifier(oid),
        });
        self
    }
    
    pub fn add_sequence(&mut self, objects: Vec<ASN1Object>) -> &mut Self {
        self.add_object(ASN1Object {
            tag: Tag::Sequence,
            value: Asn1Value::Sequence(objects),
        });
        self
    }
    
    pub fn add_null(&mut self) -> &mut Self {
        self.add_object(ASN1Object {
            tag: Tag::Null,
            value: Asn1Value::Null,
        });
        self
    }
    
    // Helper to get objects by type
    pub fn get_integers(&self) -> Vec<i64> {
        self.data.value().objects.iter()
            .filter_map(|obj| {
                if let Asn1Value::Integer(i) = &obj.value {
                    Some(*i)
                } else {
                    None
                }
            })
            .collect()
    }
    
    pub fn get_strings(&self) -> Vec<String> {
        self.data.value().objects.iter()
            .filter_map(|obj| {
                if let Asn1Value::OctetString(bytes) = &obj.value {
                    String::from_utf8(bytes.clone()).ok()
                } else {
                    None
                }
            })
            .collect()
    }
    
    pub fn get_oids(&self) -> Vec<Vec<u64>> {
        self.data.value().objects.iter()
            .filter_map(|obj| {
                if let Asn1Value::ObjectIdentifier(oid) = &obj.value {
                    Some(oid.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

// For pretty printing ASN.1 structures
impl std::fmt::Display for GenericAsn1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ASN.1 Structure:")?;
        for (i, obj) in self.data.value().objects.iter().enumerate() {
            writeln!(f, "  [{}] {}", i, format_asn1_object(obj, 2))?;
        }
        Ok(())
    }
}

fn format_asn1_object(obj: &ASN1Object, indent: usize) -> String {
    let indent_str = " ".repeat(indent);
    let tag_str = match &obj.tag {
        Tag::Boolean => "BOOLEAN",
        Tag::Integer => "INTEGER",
        Tag::BitString => "BIT STRING",
        Tag::OctetString => "OCTET STRING",
        Tag::Null => "NULL",
        Tag::ObjectIdentifier => "OBJECT IDENTIFIER",
        Tag::Sequence => "SEQUENCE",
        Tag::UnknownTag(t) => return format!("Unknown Tag({})", t),
        Tag::Extended(t) => return format!("Extended Tag({})", t),
    };
    
    match &obj.value {
        Asn1Value::Boolean(b) => format!("{}: {}", tag_str, b),
        Asn1Value::Integer(i) => format!("{}: {}", tag_str, i),
        Asn1Value::BitString(bytes) => format!("{}: {} bytes", tag_str, bytes.len()),
        Asn1Value::OctetString(bytes) => {
            if bytes.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
                format!("{}: \"{}\"", tag_str, String::from_utf8_lossy(bytes))
            } else {
                format!("{}: {} bytes (hex: {})", 
                    tag_str, 
                    bytes.len(),
                    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
                )
            }
        },
        Asn1Value::Null => format!("{}", tag_str),
        Asn1Value::ObjectIdentifier(oid) => {
            format!("{}: {}", tag_str, oid.iter().map(|n| n.to_string()).collect::<Vec<_>>().join("."))
        },
        Asn1Value::Sequence(seq) => {
            let mut result = format!("{} {{\n", tag_str);
            for (i, inner_obj) in seq.iter().enumerate() {
                result.push_str(&format!("{}[{}] {}\n", 
                    " ".repeat(indent + 2), 
                    i, 
                    format_asn1_object(inner_obj, indent + 4)
                ));
            }
            result.push_str(&format!("{}}}", indent_str));
            result
        },
        Asn1Value::UnknownConstructed(tag, seq) => {
            let mut result = format!("Unknown Constructed({}) {{\n", tag);
            for (i, inner_obj) in seq.iter().enumerate() {
                result.push_str(&format!("{}[{}] {}\n", 
                    " ".repeat(indent + 2), 
                    i, 
                    format_asn1_object(inner_obj, indent + 4)
                ));
            }
            result.push_str(&format!("{}}}", indent_str));
            result
        },
        Asn1Value::UnknownPrimitive(tag, bytes) => {
            format!("Unknown Primitive({}): {} bytes", tag, bytes.len())
        },
    }
}
