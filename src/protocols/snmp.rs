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
        panic!("FIXME!");
        Community(vec![])
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
pub struct BerTagAndLen(asn1::Tag, usize);

impl FromStr for BerTagAndLen {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        panic!("FIXME");
        Err(ValueParseError::Error)
    }
}

impl From<&[u8; 6]> for BerTagAndLen {
    fn from(arg: &[u8; 6]) -> Self {
        Self::default()
    }
}

impl Distribution<BerTagAndLen> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerTagAndLen {
        panic!("FIXME!");
        BerTagAndLen::default()
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
        panic!("FIXME");
        Err(ValueParseError::Error)
    }
}

impl From<&[u8; 6]> for BerTag {
    fn from(arg: &[u8; 6]) -> Self {
        Self::default()
    }
}

impl Distribution<BerTag> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerTag {
        panic!("FIXME!");
        BerTag::default()
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
pub struct BerLen(usize);

impl FromStr for BerLen {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        panic!("FIXME");
        Err(ValueParseError::Error)
    }
}

impl From<&[u8; 6]> for BerLen {
    fn from(arg: &[u8; 6]) -> Self {
        Self::default()
    }
}

impl Distribution<BerLen> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerLen {
        panic!("FIXME!");
        BerLen::default()
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
    pub _seq_tag_len: Value<BerTagAndLen>,
    //#[nproto(default = 1)] // 1 == SNMPv2c
    #[nproto(next: SNMP_VERSIONS => Version )]
    pub version: Value<u8>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_VERSIONS, Version = 1))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpV2c {
    #[nproto(default = "public")]
    pub community: Value<Community>,
    #[nproto(next: SNMP_PDUS => Tag)]
    pub _pdu_tag: Value<BerTag>,
    pub _pdu_len: Value<BerLen>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(160))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGet {
    pub request_id: Value<u32>,
    pub error_status: Value<i32>,
    pub error_index: Value<i32>,
    pub _bindings_tag_len: Value<BerTagAndLen>,
    pub var_bindings: Vec<SnmpVarBind>,
}

impl AutoDecodeAsSequence for Vec<SnmpVarBind> {}
impl AutoEncodeAsSequence for Vec<SnmpVarBind> {}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(161))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetNext {
    pub request_id: Value<u32>,
    pub error_status: Value<i32>,
    pub error_index: Value<i32>,
    pub _bindings_tag_len: Value<BerTagAndLen>,
    pub var_bindings: Vec<SnmpVarBind>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(SNMP_PDUS, Tag = BerTag(asn1::Tag::UnknownTag(162))))]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpGetResponse {
    pub request_id: Value<u32>,
    pub error_status: Value<i32>,
    pub error_index: Value<i32>,
    pub _bindings_tag_len: Value<BerTagAndLen>,
    pub var_bindings: Vec<SnmpVarBind>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(decoder(Asn1Decoder), encoder(Asn1Encoder))]
pub struct SnmpVarBind {
    #[nproto(encode = Skip)]
    pub _bind_tag_len: Value<BerTagAndLen>,
    pub name: Value<BerOid>,
    #[nproto(post_encode = post_encode_bind_tag_len)]
    pub value: Value<BerValue>,
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
        //Ok(BerOid(s.to_string().into_bytes()))
        panic!("FIXME");
        Ok(Self::default())
    }
}

impl From<&[u8; 6]> for BerOid {
    fn from(arg: &[u8; 6]) -> Self {
        panic!("FIXME");
        Self::default()
    }
}
impl From<&str> for BerOid {
    fn from(arg: &str) -> Self {
        panic!("FIXME");
        // BerOid(arg.to_string().into_bytes())
        Self::default()
    }
}

impl Distribution<BerOid> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerOid {
        panic!("FIXME!");
        BerOid(vec![])
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
        //Ok(BerValue(s.to_string().into_bytes()))
        panic!("FIXME");
        Ok(Self::default())
    }
}

impl From<&[u8; 6]> for BerValue {
    fn from(arg: &[u8; 6]) -> Self {
        panic!("FIXME");
        Self::default()
    }
}
impl From<&str> for BerValue {
    fn from(arg: &str) -> Self {
        panic!("FIXME");
        // BerValue(arg.to_string().into_bytes())
        Self::default()
    }
}

impl Distribution<BerValue> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BerValue {
        panic!("FIXME!");
        BerValue(Default::default())
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
