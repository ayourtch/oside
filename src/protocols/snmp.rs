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
    for i in my_index + 1..encoded_data.len() {
        out_len += encoded_data[i].len();
    }
    // Also account for what has been encoded on this level already
    out_len += out.len() - old_len;
    let seq_tag_len = if !me._seq_tag_len.is_auto() {
        me._seq_tag_len.value()
    } else {
        BerTagAndLen(asn1::Tag::Sequence, out_len)
    };
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
    Timeticks(u32),
    Counter64(u64),
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
                        return Ok(SnmpValue::Timeticks(val));
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
            2 => SnmpValue::Timeticks(rng.gen()),
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
                    SnmpValue::Timeticks(value as u32)
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
            SnmpValue::Timeticks(x) => {
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
