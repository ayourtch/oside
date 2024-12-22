use crate::*;
use serde::{Deserialize, Serialize};

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x0806))]
pub struct Arp {
    #[nproto(default = 1)]
    pub hwtype: Value<u16>,
    #[nproto(default = 0x0800)]
    pub ptype: Value<u16>,
    #[nproto(default = 6)]
    pub hwlen: Value<u8>,
    #[nproto(default = 4)]
    pub plen: Value<u8>,
    #[nproto(default = 1)]
    pub op: Value<u16>,
    #[nproto(decode = decode_arp_hwaddr)]
    pub hwsrc: Value<ArpHardwareAddress>,
    #[nproto(decode = decode_arp_paddr)]
    pub psrc: Value<ArpProtocolAddress>,
    #[nproto(decode = decode_arp_hwaddr)]
    pub hwdst: Value<ArpHardwareAddress>,
    #[nproto(decode = decode_arp_paddr)]
    pub pdst: Value<ArpProtocolAddress>,
}

fn decode_arp_hwaddr<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Arp,
) -> Option<(ArpHardwareAddress, usize)> {
    use std::convert::TryInto;

    let buf = &buf[ci..];

    let (v, delta) = D::decode_vec(buf, me.hwlen.value() as usize)?;
    let vlen = v.len();
    match vlen {
        6 => ArpHardwareAddress::decode::<D>(&v),
        _ => Some((ArpHardwareAddress::Bytes(v), vlen)),
    }
}

fn decode_arp_paddr<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Arp,
) -> Option<(ArpProtocolAddress, usize)> {
    use std::convert::TryInto;

    let buf = &buf[ci..];

    let (v, delta) = D::decode_vec(buf, me.plen.value() as usize)?;
    let vlen = v.len();
    match vlen {
        4 => ArpProtocolAddress::decode::<D>(&v),
        _ => Some((ArpProtocolAddress::Bytes(v), vlen)),
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ArpHardwareAddress {
    Ether(MacAddr),
    Bytes(Vec<u8>),
}

impl Default for ArpHardwareAddress {
    fn default() -> Self {
        Self::Ether(Default::default())
    }
}

// FIXME: take into account the hwlen from packet
impl Encode for ArpHardwareAddress {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            Self::Ether(x) => x.0.bytes().to_vec(),
            Self::Bytes(b) => b.to_vec(),
        }
    }
}

// FIXME: take into account the hwlen from packet
impl Decode for ArpHardwareAddress {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((mac_vec, count)) = D::decode_vec(buf, 6) {
            Some((Self::Ether(MacAddr::from(&mac_vec[..])), count))
        } else {
            None
        }
    }
}

impl Serialize for ArpHardwareAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Ether(x) => x.serialize(serializer),
            Self::Bytes(b) => b.to_vec().serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArpHardwareAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::de::Visitor;
        struct ArpHAVisitor {}
        impl<'de> Visitor<'de> for ArpHAVisitor {
            type Value = ArpHardwareAddress;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ArpHardwareAddress")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                panic!("TBD")
            }
        }

        return Ok(deserializer.deserialize_str(ArpHAVisitor {})?);
    }
}

impl Distribution<ArpHardwareAddress> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ArpHardwareAddress {
        ArpHardwareAddress::Ether(MacAddr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ))
    }
}

impl FromStr for ArpHardwareAddress {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match MacAddr::from_str(s) {
            Ok(res) => Ok(Self::Ether(res)),
            Err(e) => {
                panic!("Could not parse");
            }
        }
    }
}

impl From<&str> for ArpHardwareAddress {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub enum ArpProtocolAddress {
    IP(Ipv4Address),
    Bytes(Vec<u8>),
}

impl Default for ArpProtocolAddress {
    fn default() -> Self {
        Self::IP(Default::default())
    }
}

// FIXME: take into account the plen from packet
impl Encode for ArpProtocolAddress {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            Self::IP(x) => x.encode::<E>(),
            Self::Bytes(b) => b.to_vec(),
        }
    }
}

impl Serialize for ArpProtocolAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::IP(x) => (*x).0.serialize(serializer),
            Self::Bytes(b) => b.to_vec().serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArpProtocolAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::de::Visitor;
        struct ArpPAVisitor {}
        impl<'de> Visitor<'de> for ArpPAVisitor {
            type Value = ArpProtocolAddress;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("ArpProtocolAddress")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                panic!("TBD")
            }
        }

        return Ok(deserializer.deserialize_str(ArpPAVisitor {})?);
    }
}

// FIXME: take into account the plen from packet
impl Decode for ArpProtocolAddress {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((ip4, count)) = Ipv4Address::decode::<D>(buf) {
            Some((Self::IP(ip4), count))
        } else {
            None
        }
    }
}

impl Distribution<ArpProtocolAddress> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ArpProtocolAddress {
        ArpProtocolAddress::IP(Ipv4Address::new(rng.gen(), rng.gen(), rng.gen(), rng.gen()))
    }
}

impl FromStr for ArpProtocolAddress {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Ipv4Address::from_str(s) {
            Ok(res) => Ok(Self::IP(res)),
            Err(e) => {
                panic!("Could not parse");
            }
        }
    }
}

impl From<&str> for ArpProtocolAddress {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}
