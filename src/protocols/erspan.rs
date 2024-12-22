use crate::*;
use serde::{Deserialize, Serialize};

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x88be))]
pub struct erspan {
    // encoded/decoded by the next field encoders
    #[nproto(encode = Skip, decode = Skip)]
    pub version: Value<ErspanType>,
    #[nproto(encode = encode_version_and_vlan, decode = decode_version_and_vlan)]
    pub vlan: Value<u16>,

    #[nproto(encode = Skip, decode = Skip)]
    pub cos: Value<u8>,
    // 2 bit
    #[nproto(encode = Skip, decode = Skip)]
    pub encap_type: Value<u8>,
    #[nproto(encode = Skip, decode = Skip)]
    pub truncated: Value<bool>,
    // 10 bit
    #[nproto(encode = encode_second_u16_fields, decode = decode_second_u16_fields)]
    pub session_id: Value<u16>,
    // 20 bit
    // encoded/decoded by the next decoder
    #[nproto(encode = Skip, decode = Skip)]
    pub port_index: Value<u32>,
    // reserved value
    #[nproto(encode = encode_u32_reserved1, decode = decode_u32_reserved1)]
    pub reserved1: Value<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ErspanType {
    #[default]
    Type1 = 0,
    Type2 = 1,
    Type3 = 2,
    Unknown(u8),
}

impl From<u8> for ErspanType {
    fn from(u: u8) -> Self {
        match u {
            0 => ErspanType::Type1,
            1 => ErspanType::Type2,
            2 => ErspanType::Type3,
            x => ErspanType::Unknown(x),
        }
    }
}

impl Into<u8> for ErspanType {
    fn into(self) -> u8 {
        match self {
            ErspanType::Type1 => 0,
            ErspanType::Type2 => 1,
            ErspanType::Type3 => 2,
            ErspanType::Unknown(x) => x,
        }
    }
}

impl FromStr for ErspanType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // FIXME: implement properly
        Ok(ErspanType::Type1)
    }
}

impl Distribution<ErspanType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ErspanType {
        let r: u8 = rng.gen();
        r.into()
    }
}

fn encode_second_u16_fields<E: Encoder>(
    me: &erspan,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    let mut the_u16: u16 = u16::from(7 & me.cos.value()) << 13
        | u16::from(3 & me.encap_type.value()) << 11
        | u16::from(me.truncated.value()) << 10
        | 0x3ff & me.session_id.value();

    E::encode_u16(the_u16)
}

/*
 * decode the second u16 and set the flags.
 */
fn decode_second_u16_fields<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut erspan,
) -> Option<(u16, usize)> {
    let buf = &buf[ci..];

    let mut ci = 0;
    let (the_u16, _) = D::decode_u16(buf)?;

    me.cos = Value::Set((0x7 & (the_u16 >> 13)) as u8);
    me.encap_type = Value::Set((0x3 & (the_u16 >> 11)) as u8);
    me.truncated = Value::Set((1 & (the_u16 >> 10)) == 1);

    let session_id = 0x3ff & the_u16;
    Some((session_id, 2))
}

fn decode_version_and_vlan<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut erspan,
) -> Option<(u16, usize)> {
    let buf = &buf[ci..];

    let (the_u16, _) = D::decode_u16(buf)?;
    me.version = Value::Set(ErspanType::from((0xf & (the_u16 >> 12)) as u8));
    let vlan = the_u16 & 0xfff;
    Some((vlan, 2))
}

fn encode_version_and_vlan<E: Encoder>(
    me: &erspan,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let version: u8 = me.version.value().into();
    let mut the_u16: u16 = (u16::from(me.vlan.value()) & 0xfff) | u16::from(version & 0xf) << 12;
    E::encode_u16(the_u16)
}

fn decode_u32_reserved1<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut erspan,
) -> Option<(u32, usize)> {
    let buf = &buf[ci..];

    let (the_u32, delta) = D::decode_u32(buf)?;
    me.port_index = Value::Set(0xfffff & the_u32);
    let reserved1: u32 = (the_u32 >> 20) & 0xfff;
    Some((reserved1, delta))
}

fn encode_u32_reserved1<E: Encoder>(
    me: &erspan,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut the_u32: u32 = (u32::from(me.port_index.value()) & 0xfffff)
        | u32::from(me.reserved1.value() & 0xfff) << 20;
    E::encode_u32(the_u32)
}
