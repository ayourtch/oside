use crate::*;
use serde::Serialize;

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x800))]
#[nproto(register(IANA_LAYERS, Proto = 4))]
pub struct Ip {
    #[nproto(default = 4, encode = Skip, decode = Skip)]
    pub version: Value<u8>,
    #[nproto(encode = encode_ver_ihl, decode = decode_ver_ihl, fill = fill_ihl_auto)]
    pub ihl: Value<u8>,
    pub tos: Value<u8>,
    #[nproto(encode = encode_ip_len, fill = fill_ip_len_auto)]
    pub len: Value<u16>,
    #[nproto(default = Random)]
    pub id: Value<u16>,
    #[nproto(encode = encode_flags_frag, decode = decode_flags_frag)]
    pub flags: Value<IpFlags>,
    // #[nproto(decode = Skip)] // set above
    // pub frag: Value<u16>, -- part of flags
    #[nproto(default = 64)]
    pub ttl: Value<u8>,
    #[nproto(next: IANA_LAYERS => Proto )]
    pub proto: Value<u8>,
    #[nproto(encode = encode_ip_chksum, fill = fill_ip_chksum_auto)]
    pub chksum: Value<u16>,
    #[nproto(default = "127.0.0.1")]
    pub src: Value<Ipv4Address>,
    #[nproto(default = "127.0.0.1")]
    pub dst: Value<Ipv4Address>,
    #[nproto(decode = Skip)]
    pub options: Vec<IpOption>,
}

use std::num::ParseIntError;

fn encode_flags_frag<E: Encoder>(
    me: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    me.flags.value().to_raw().encode::<E>()
}

fn decode_flags_frag<D: Decoder>(buf: &[u8], me: &mut Ip) -> Option<(IpFlags, usize)> {
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let flags = IpFlags::from_raw(raw_value);
    Some((flags, delta))
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpFlags {
    reserved: bool,       // Must be 0
    dont_fragment: bool,  // Don't Fragment flag
    more_fragments: bool, // More Fragments flag
    fragment_offset: u16, // 13-bit fragment offset
}

impl IpFlags {
    // Constructor for common cases
    pub fn new(dont_fragment: bool, more_fragments: bool, fragment_offset: u16) -> Self {
        IpFlags {
            reserved: false,
            dont_fragment,
            more_fragments,
            fragment_offset: fragment_offset & 0x1FFF, // Ensure 13-bit max
        }
    }

    // Helper function to create unfragmented packet flags
    pub fn unfragmented() -> Self {
        IpFlags {
            reserved: false,
            dont_fragment: true,
            more_fragments: false,
            fragment_offset: 0,
        }
    }

    // Helper function to create fragmented packet flags
    pub fn fragment(offset: u16, more: bool) -> Self {
        IpFlags {
            reserved: false,
            dont_fragment: false,
            more_fragments: more,
            fragment_offset: offset & 0x1FFF,
        }
    }

    // Get the raw 16-bit value for encoding
    pub fn to_raw(&self) -> u16 {
        let mut flags: u16 = 0;
        if self.reserved {
            flags |= 0x8000;
        }
        if self.dont_fragment {
            flags |= 0x4000;
        }
        if self.more_fragments {
            flags |= 0x2000;
        }
        flags | (self.fragment_offset & 0x1FFF)
    }

    // Parse from raw 16-bit value for decoding
    pub fn from_raw(value: u16) -> Self {
        IpFlags {
            reserved: (value & 0x8000) != 0,
            dont_fragment: (value & 0x4000) != 0,
            more_fragments: (value & 0x2000) != 0,
            fragment_offset: value & 0x1FFF,
        }
    }
}

impl Encode for IpFlags {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        self.to_raw().encode::<E>()
    }
}

impl From<&str> for IpFlags {
    fn from(v: &str) -> Self {
        Self::from_str(v).unwrap()
    }
}

impl FromStr for IpFlags {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse string format like "DF" or "MF,offset=123"
        let parts: Vec<&str> = s.split(',').collect();
        let mut flags = IpFlags::default();

        for part in parts {
            let part = part.trim();
            if part == "DF" {
                flags.dont_fragment = true;
            } else if part == "EVIL" {
                flags.reserved = true;
            } else if part == "MF" {
                flags.more_fragments = true;
            } else if part.starts_with("offset=") {
                if let Ok(offset) = part[7..].parse::<u16>() {
                    flags.fragment_offset = offset & 0x1FFF;
                }
            }
        }
        Ok(flags)
    }
}

impl Distribution<IpFlags> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> IpFlags {
        IpFlags {
            reserved: rng.gen(),
            dont_fragment: rng.gen(),
            more_fragments: rng.gen(),
            fragment_offset: rng.gen::<u16>() & 0x1FFF,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IpOption {
    NOP(),
    SourceRoute(Vec<Ipv4Address>),
}

impl Encode for Vec<IpOption> {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        vec![]
    }
}

impl FromStr for IpOption {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpOption::NOP())
    }
}

fn encode_ver_ihl<E: Encoder>(
    my_layer: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let ver = (my_layer.version.value() as u8) & 0xf;
    let ihl = if my_layer.ihl.is_auto() {
        // fixme
        5
    } else {
        (my_layer.ihl.value() as u8) & 0xf
    };
    E::encode_u8(ver << 4 | ihl)
}

fn decode_ver_ihl<D: Decoder>(buf: &[u8], me: &mut Ip) -> Option<(u8, usize)> {
    let (v_ihl, delta) = u8::decode::<D>(buf)?;
    let ihl = v_ihl & 0xf;
    me.version = Value::Set(v_ihl >> 4);
    Some((ihl, delta))
}

fn fill_ihl_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u8> {
    Value::Auto
}

fn fill_ip_len_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn fill_ip_chksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_ip_len<E: Encoder>(
    me: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    let mut data_len: usize = 0;

    for i in my_index + 1..encoded_data.len() {
        data_len += encoded_data[i].len();
    }
    data_len += 20; // IP HDR
    let len: u16 = data_len.try_into().unwrap();

    len.encode::<E>()
}

fn encode_ip_chksum<E: Encoder>(
    me: &Ip,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    if !me.chksum.is_auto() {
        return me.chksum.value().encode::<E>();
    }

    let encoded_ip_header = if let Some(ip) = stack.item_at(IP!(), my_index) {
        ip.clone().chksum(0).encode(stack, my_index, encoded_data)
    } else {
        vec![]
    };
    // eprintln!("Encoded IP header: {:02x?}", &encoded_ip_header);
    let sum = get_inet_sum(&encoded_ip_header);
    let sum = fold_u32(sum);
    sum.encode::<E>()
}
