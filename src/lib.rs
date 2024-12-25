//use std::any::Any;
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

#[macro_use]
extern crate doc_comment;

fn readme_test() {
    doc_comment! {
        include_str!("../README.md"),
        fn readme_test_examples() {}
    }
}

pub use std::any::TypeId;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::ops::Deref;
pub use std::ops::Div;
use std::ops::Index;
use std::str::FromStr;
#[macro_use]
extern crate mopa;
extern crate itertools;
extern crate mac_address;

#[macro_use]
extern crate lazy_static;

pub struct ParseNumberError;
use crate::Value::Random;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

use linkme::distributed_slice;

use crate::encdec::binary_big_endian::BinaryBigEndian;
#[derive(NetworkProtocol, Debug, Clone, Serialize, Deserialize)]
#[nproto(registry(ETHERTYPE_LAYERS, Ethertype: u16))]
#[nproto(registry(IANA_LAYERS, Proto: u8))]
#[nproto(registry(ICMP_TYPES, Type: u8))]
#[nproto(registry(UDP_SRC_PORT_APPS, SrcPort: u16))]
#[nproto(registry(UDP_DST_PORT_APPS, DstPort: u16))]
#[nproto(registry(BOOTP_VENDORS, VendorCookie: u32))]
#[nproto(registry(OSPF_PACKET_TYPES, PacketType: u8))]
/* Only here as a target of derive + attribute macros to make registries */
struct protocolRegistriesSentinel;

// find an enum variant inside a vec
#[macro_export]
macro_rules! vec_find_enum {
    ($name:expr, $inner_type:ident) => {
        $name.iter().find_map(|x| {
            if let $inner_type(data) = x {
                Some(data)
            } else {
                None
            }
        })
    };
}

pub trait Encoder {
    fn encode_u8(v1: u8) -> Vec<u8>;
    fn encode_u16(v1: u16) -> Vec<u8>;
    fn encode_u32(v1: u32) -> Vec<u8>;
    fn encode_u64(v1: u64) -> Vec<u8>;
    fn encode_vec(v1: &Vec<u8>) -> Vec<u8>;
}

pub trait Decoder {
    fn decode_u8(buf: &[u8]) -> Option<(u8, usize)>;
    fn decode_u16(buf: &[u8]) -> Option<(u16, usize)>;
    fn decode_u32(buf: &[u8]) -> Option<(u32, usize)>;
    fn decode_u64(buf: &[u8]) -> Option<(u64, usize)>;
    fn decode_vec(buf: &[u8], len: usize) -> Option<(Vec<u8>, usize)>;
}

pub trait Decode {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)>
    where
        Self: Sized;
}

pub trait ManualDecode {}

impl Decode for u8 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u8(buf)
    }
}

impl Decode for u16 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u16(buf)
    }
}

impl Decode for u32 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u32(buf)
    }
}

impl Decode for i32 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u32(buf).map(|(n, s)| (n as i32, s))
    }
}

impl Decode for u64 {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u64(buf)
    }
}

impl Decode for Ipv4Address {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        D::decode_u32(buf).map(|(a, i)| (Self::from(a), i))
    }
}

impl Decode for MacAddr {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((mac_vec, count)) = D::decode_vec(buf, 6) {
            Some((MacAddr::from(&mac_vec[..]), count))
        } else {
            None
        }
    }
}

pub trait Encode {
    fn encode<E: Encoder>(&self) -> Vec<u8>;
}

// Add a dummy impl if you implementing Encode manually
pub trait ManualEncode {}

impl Encode for u8 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u8(*self)
    }
}

impl Encode for u16 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u16(*self)
    }
}

impl Encode for u32 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u32(*self)
    }
}

impl Encode for i32 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u32(*self as u32)
    }
}

impl Encode for u64 {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u64(*self)
    }
}

impl Encode for Ipv4Address {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_u32(u32::from_be_bytes(self.0.octets()))
    }
}

impl Encode for MacAddr {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        self.0.bytes().to_vec()
    }
}

impl Encode for Vec<u8> {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        E::encode_vec(self)
    }
}
impl ManualEncode for Vec<u8> {}

#[derive(PartialEq, Clone, Eq)]
pub enum Value<T> {
    Auto,
    Random,
    Func(fn() -> T),
    Set(T),
}

impl<T: Serialize> Serialize for Value<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self;
        match data {
            Value::Auto => serializer.serialize_str("<auto>"),
            Value::Random => serializer.serialize_str("<random>"),
            Value::Func(f) => panic!("Serializing functions is not supported"),
            Value::Set(v) => v.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de> + FromStr> Deserialize<'de> for Value<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Error, MapAccess, SeqAccess, Visitor};

        struct ValueVisitor<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for ValueVisitor<T>
        where
            T: Deserialize<'de> + FromStr,
        {
            type Value = Value<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string '<auto>', '<random>', or a value")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match value {
                    "<auto>" => Ok(Value::Auto),
                    "<random>" => Ok(Value::Random),
                    _ => {
                        // Try to parse the string as T
                        T::from_str(value).map(Value::Set).map_err(|_| {
                            E::custom(format!("Failed to parse '{}' as Set value", value))
                        })
                    }
                }
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::deserialize(de::value::I64Deserializer::new(v)).map(Value::Set)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::deserialize(de::value::U64Deserializer::new(v)).map(Value::Set)
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::deserialize(de::value::F64Deserializer::new(v)).map(Value::Set)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::deserialize(de::value::BoolDeserializer::new(v)).map(Value::Set)
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq)).map(Value::Set)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                Deserialize::deserialize(de::value::MapAccessDeserializer::new(map)).map(Value::Set)
            }
        }

        deserializer.deserialize_any(ValueVisitor(PhantomData))
    }
}

impl<T: Clone + std::default::Default> Value<T>
where
    Standard: Distribution<T>,
{
    pub fn value(&self) -> T {
        match self {
            Self::Auto => Default::default(),
            Self::Random => {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen()
            }
            Self::Set(x) => x.clone(),
            Self::Func(f) => f(),
        }
    }
}

impl<T: std::cmp::PartialEq> Value<T> {
    pub fn is_auto(&self) -> bool {
        self == &Self::Auto
    }
}

impl<T: std::fmt::Display> fmt::Display for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str(&format!("Auto")),
            Self::Random => f.write_str(&format!("Random")),
            Self::Set(x) => x.fmt(f),
            Self::Func(x) => f.write_str(&format!("Fn: {:?}", x)),
        }
    }
}

impl<T: std::fmt::Debug> fmt::Debug for Value<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str(&format!("Auto")),
            Self::Random => f.write_str(&format!("Random")),
            Self::Set(x) => f.write_str(&format!("{:?}", &x)),
            Self::Func(x) => f.write_str(&format!("Fn: {:?}", x)),
        }
    }
}

impl<T> Default for Value<T> {
    fn default() -> Self {
        Self::Auto
    }
}

impl<'a, T: From<&'a str>> From<&'a str> for Value<T> {
    fn from(s: &'a str) -> Self {
        Self::Set(T::from(s))
    }
}

#[derive(Clone, Debug)]
pub enum ValueParseError {
    Error,
}

impl<T: FromStr> FromStr for Value<T> {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match T::from_str(s) {
            Ok(res) => Ok(Self::Set(res)),
            Err(e) => panic!("Could not parse!"),
        }
    }
}

#[derive(PartialEq, Clone, Eq)]
pub struct MacAddr(mac_address::MacAddress);

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{}", &self.0))
    }
}

impl Default for MacAddr {
    fn default() -> Self {
        MacAddr(mac_address::MacAddress::new([0, 0, 0, 0, 0, 0]))
    }
}

impl MacAddr {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8, o5: u8, o6: u8) -> Self {
        MacAddr(mac_address::MacAddress::new([o1, o2, o3, o4, o5, o6]))
    }
}

impl Serialize for MacAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::de::Visitor;
        struct MacAddrVisitor {}
        impl<'de> Visitor<'de> for MacAddrVisitor {
            type Value = MacAddr;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("MacAddr")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                panic!("TBD")
            }
        }

        return Ok(deserializer.deserialize_str(MacAddrVisitor {})?);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseMacAddrError;

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseMacAddrError);
        }
        Ok(MacAddr(res.unwrap()))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(arg: [u8; 6]) -> Self {
        Self::new(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5])
    }
}

impl From<&[u8]> for MacAddr {
    fn from(arg: &[u8]) -> Self {
        if arg.len() < 6 {
            panic!("the buffer len {} too short for MacAddr", arg.len());
        }
        Self::new(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5])
    }
}

impl From<Value<MacAddr>> for MacAddr {
    fn from(v: Value<MacAddr>) -> MacAddr {
        match v {
            Value::Auto => {
                panic!("can not return value of auto mac addr");
            }
            Value::Random => {
                unimplemented!();
            }
            Value::Set(x) => x.clone(),
            Value::Func(x) => x(),
        }
    }
}

impl From<&str> for MacAddr {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        MacAddr(res)
    }
}

impl Distribution<MacAddr> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MacAddr {
        MacAddr::new(
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6Address([u8; 16]);

impl Default for Ipv6Address {
    fn default() -> Self {
        Ipv6Address([0; 16])
    }
}

impl Ipv6Address {
    pub fn new(bytes: [u8; 16]) -> Self {
        Ipv6Address(bytes)
    }

    // Create from string representation (e.g., "2001:db8::1")
    pub fn from_str_addr(s: &str) -> Result<Self, ParseIpv6AddressError> {
        match s.parse::<std::net::Ipv6Addr>() {
            Ok(addr) => Ok(Ipv6Address(addr.octets())),
            Err(_) => Err(ParseIpv6AddressError),
        }
    }
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("FIXME {:?}", &self.0))
    }
}

impl Serialize for Ipv6Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", std::net::Ipv6Addr::from(self.0));
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Ipv6Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::de::Visitor;
        struct Ipv6Visitor {}
        impl<'de> Visitor<'de> for Ipv6Visitor {
            type Value = Ipv6Address;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Ipv6Address")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ipv6Address::from_str_addr(v).map_err(|e| {
                    E::custom(format!("Failed to parse '{}' as IPv6 address: {:?}", v, e))
                })
            }
        }

        deserializer.deserialize_str(Ipv6Visitor {})
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseIpv6AddressError;

impl FromStr for Ipv6Address {
    type Err = ParseIpv6AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_addr(s)
    }
}

impl From<&str> for Ipv6Address {
    fn from(s: &str) -> Self {
        Self::from_str(s).unwrap()
    }
}

impl Distribution<Ipv6Address> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Ipv6Address {
        let mut bytes = [0u8; 16];
        for b in &mut bytes {
            *b = rng.gen();
        }
        Ipv6Address(bytes)
    }
}

#[derive(PartialEq, Clone, Eq)]
pub struct Ipv4Address(std::net::Ipv4Addr);

impl fmt::Debug for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format!("{:?}", &self.0))
    }
}

impl Default for Ipv4Address {
    fn default() -> Self {
        Ipv4Address(Ipv4Addr::new(0, 0, 0, 0))
    }
}

impl Ipv4Address {
    pub fn new(o1: u8, o2: u8, o3: u8, o4: u8) -> Self {
        Ipv4Address(Ipv4Addr::new(o1, o2, o3, o4))
    }
}

impl Serialize for Ipv4Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("{}", self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Ipv4Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        use serde::de::Visitor;
        struct Ipv4Visitor {}
        impl<'de> Visitor<'de> for Ipv4Visitor {
            type Value = Ipv4Address;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                panic!("TBD1");
                formatter.write_str("Ipv4Address")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ipv4Address::from_str(v).map_err(|e| {
                    E::custom(format!("Failed to parse '{}' as IPv4 address: {:?}", v, e))
                })
            }
        }

        return Ok(deserializer.deserialize_str(Ipv4Visitor {})?);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseIpv4AddressError;

impl FromStr for Ipv4Address {
    type Err = ParseIpv4AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let res = s.parse();
        if res.is_err() {
            return Err(ParseIpv4AddressError);
        }
        Ok(Ipv4Address(res.unwrap()))
    }
}

impl From<[u8; 4]> for Ipv4Address {
    fn from(arg: [u8; 4]) -> Self {
        Self::new(arg[0], arg[1], arg[2], arg[3])
    }
}

impl From<&str> for Ipv4Address {
    fn from(s: &str) -> Self {
        let res = s.parse().unwrap();
        Ipv4Address(res)
    }
}

impl From<u32> for Ipv4Address {
    fn from(u: u32) -> Self {
        Ipv4Address(Ipv4Addr::from(u))
    }
}

impl Distribution<Ipv4Address> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Ipv4Address {
        Ipv4Address::new(rng.gen(), rng.gen(), rng.gen(), rng.gen())
    }
}

#[macro_use]
extern crate oside_derive;

pub trait FromStringHashmap<T>: Default {
    fn from_string_hashmap(hm: HashMap<String, String>) -> T;
}

pub fn parse_pair<T>(v: &str) -> T
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => val,
        Err(_) => panic!("unable to parse"),
    }
}

pub fn parse_pair_as_option<T>(v: &str) -> Option<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => Some(val),
        Err(_) => panic!("unable to parse"),
    }
}

pub fn parse_pair_as_value<T>(v: &str) -> Value<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => Value::Set(val),
        Err(_) => panic!("unable to parse"),
    }
}

pub fn parse_pair_as_vec<T>(v: &str) -> Vec<T>
where
    T: FromStr,
{
    let res = v.parse::<T>();
    match res {
        Ok(val) => vec![val],
        Err(_) => panic!("unable to parse"),
    }
}

#[derive(FromStringHashmap, Default)]
pub struct FunnyTest {
    pub foo: u32,
    pub bar: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct EncodingVecVec {
    data: Vec<Vec<u8>>,
    curr_idx: usize,
}

impl EncodingVecVec {
    fn len(&self) -> usize {
        // take into account the "phantom" layers
        self.data.len() + self.curr_idx + 1
    }
}
impl Index<usize> for EncodingVecVec {
    type Output = Vec<u8>;

    fn index(&self, idx: usize) -> &Self::Output {
        if idx > self.curr_idx {
            &self.data[idx - self.curr_idx - 1]
        } else {
            panic!("encoding data at layer {} not yet ready", idx);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LayerStack {
    pub filled: bool,
    pub layers: Vec<Box<dyn Layer>>,
}

/*
impl Serialize for LayerStack {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut len = self.layers.len();
        let mut seq = serializer.serialize_tuple(len)?;
        for (i, ll) in (&self.layers).into_iter().enumerate() {
            seq.serialize_element(ll)?;
        }
        seq.end()
    }
}
*/
/*
impl Serialize for dyn Layer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = format!("FIXME {:?}", self);
        serializer.serialize_str(&s)
        // eprintln!("SERIALIZE: {}\n", s);
        // self.downcast_mut::<T>().unwrap().serialize(serializer)
        // self.downcast_ref::<T>().unwrap().serialize(serializer)
    }
}
*/

impl LayerStack {
    pub fn gg<T: Layer + Clone>(layer: Box<dyn Layer>) -> T {
        if layer.type_id() == TypeId::of::<T>() {
            (*layer.downcast_ref::<T>().unwrap()).clone()
        } else {
            panic!(
                " wrong typeid {:?} and {:?}",
                layer.type_id(),
                TypeId::of::<T>()
            );
        }
    }

    pub fn g<T: Layer>(&self, idx: T) -> &T {
        self[TypeId::of::<T>()].downcast_ref().unwrap()
    }

    pub fn item_at<T: Layer>(&self, item: T, idx: usize) -> Option<&T> {
        self.layers[idx].downcast_ref()
    }

    pub fn find_layer<T: Layer>(&self, item: T) -> Option<(usize, &T)> {
        for (idx, ll) in (&self.layers).into_iter().enumerate() {
            if ll.type_id_is(TypeId::of::<T>()) {
                return Some((idx, ll.downcast_ref().unwrap()));
            }
        }
        return None;
    }

    pub fn get_layer<T: Layer>(&self, item: T) -> Option<&T> {
        for ll in &self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                return Some(ll.downcast_ref().unwrap());
            }
        }
        return None;
    }
    pub fn get_innermost_layer<T: Layer>(&self, item: T) -> Option<&T> {
        for ref layer in self.layers.iter().rev() {
            if layer.type_id_is(TypeId::of::<T>()) {
                return Some(layer.downcast_ref().unwrap());
            }
        }
        return None;
    }
    pub fn get_layer_mut<T: Layer>(&mut self, item: T) -> Option<&mut T> {
        for ll in &mut self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                return Some(ll.downcast_mut().unwrap());
            }
        }
        return None;
    }

    pub fn layers_of<T: Layer>(&self, item: T) -> Vec<&T> {
        let mut out = vec![];
        for ll in &self.layers {
            if ll.type_id_is(TypeId::of::<T>()) {
                out.push(ll.downcast_ref().unwrap())
            }
        }
        out
    }
    pub fn items_of<T: Layer>(&self, typ: T) -> Vec<&T> {
        self.layers_of(typ)
    }

    pub fn lencode(self) -> Vec<u8> {
        let target = if self.filled {
            self
        } else {
            self.clone().fill()
        };
        let mut out = EncodingVecVec {
            data: vec![],
            curr_idx: target.layers.len(),
        };
        for (i, ll) in (&target.layers).into_iter().enumerate().rev() {
            out.curr_idx = i;
            // println!("{}: {:?}", i, &ll);
            let ev = ll.lencode(&target, i, &out);
            out.data.push(ev);
        }
        out.data.reverse();
        itertools::concat(out.data)
    }

    pub fn fill(&self) -> LayerStack {
        let mut out = LayerStack {
            layers: vec![],
            filled: true,
        };
        for (i, ll) in (&self.layers).into_iter().enumerate() {
            ll.fill(&self, i, &mut out);
        }
        out
    }

    pub fn indices_of<T: Layer>(&self, typ: T) -> Vec<usize> {
        let mut out = vec![];
        for (i, ref layer) in (&self.layers).into_iter().enumerate() {
            if layer.type_id_is(typ.type_id()) {
                out.push(i)
            }
        }
        out
    }
}

impl Index<TypeId> for LayerStack {
    type Output = Box<dyn Layer>;

    fn index(&self, type_id: TypeId) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(type_id) {
                return layer.clone();
            }
        }
        panic!("Layer not found");
    }
}

impl<T> Index<T> for LayerStack
where
    T: Layer,
{
    type Output = T;
    fn index(&self, typ: T) -> &Self::Output {
        for ref layer in &self.layers {
            if layer.type_id_is(typ.type_id()) {
                return layer.clone().downcast_ref().unwrap();
            }
        }
        panic!("Layer not found");
    }
}

impl fmt::Debug for LayerStack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.layers.iter()).finish()
    }
}

impl<T: Layer> Div<T> for LayerStack {
    type Output = LayerStack;
    fn div(mut self, rhs: T) -> Self::Output {
        self.layers.push(rhs.embox());
        self
    }
}

impl Div<LayerStack> for LayerStack {
    type Output = LayerStack;
    fn div(mut self, rhs: LayerStack) -> Self::Output {
        for x in rhs.layers {
            self.layers.push(x);
        }
        self
    }
}

pub trait New {
    fn new() -> Self
    where
        Self: Default;
}

impl<T: Default> New for T {
    fn new() -> Self {
        Self::default()
    }
}
#[typetag::serde(tag = "layertype")]
pub trait Layer: Debug + mopa::Any + New {
    fn embox(self) -> Box<dyn Layer>;
    fn box_clone(&self) -> Box<dyn Layer>;
    fn to_stack(self) -> LayerStack
    where
        Self: Sized,
    {
        LayerStack {
            layers: vec![self.embox()],
            filled: false,
        }
    }
    fn type_id_is(&self, x: TypeId) -> bool {
        self.type_id() == x
    }
    fn get_layer_type_id(&self) -> TypeId {
        self.type_id()
    }
    /* fill the unknown fields based on the entire stack contents */
    fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack);

    /* default encode function encodes some dead beef */
    fn lencode(
        &self,
        stack: &LayerStack,
        my_index: usize,
        encoded_layers: &EncodingVecVec,
    ) -> Vec<u8> {
        vec![0xde, 0xad, 0xbe, 0xef]
    }

    fn decode_as_raw(&self, buf: &[u8]) -> LayerStack {
        use crate::protocols::raw::*;
        let mut layers = vec![];
        if buf.len() > 0 {
            let layer = raw {
                data: buf.clone().to_vec(),
            };
            layers.push(layer.embox());
        }
        LayerStack {
            layers,
            filled: true,
        }
    }
    fn ldecode(&self, buf: &[u8]) -> Option<(LayerStack, usize)> {
        let buflen = buf.len();
        Some((self.decode_as_raw(buf), buflen))
    }
}

mopafy!(Layer);

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Box<dyn Layer> {
        self.box_clone()
    }
}

/*
impl <'a> PartialEq for LayerStack<'a> {
    fn eq(&self, other: &Self) -> bool {
        true
    }
}

impl <'a> Eq for LayerStack<'a> {
}
*/

pub trait AutoDecodeAsSequence {}
pub trait AutoEncodeAsSequence {}

impl<T: Decode> Decode for Vec<T>
where
    Vec<T>: AutoDecodeAsSequence,
{
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let mut elts = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            if let Some((elt, len)) = T::decode::<D>(&buf[pos..]) {
                elts.push(elt);
                pos += len;
            } else {
                break;
            }
        }
        Some((elts, pos))
    }
}

impl<T: Encode> Encode for Vec<T>
where
    Vec<T>: AutoEncodeAsSequence,
{
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();

        for elt in self {
            out.extend(elt.encode::<E>());
        }
        out
    }
}

pub trait WritePcap {
    fn write_pcap(&self, fname: &str) -> Result<(), std::io::Error>;
}

impl WritePcap for Vec<LayerStack> {
    fn write_pcap(&self, fname: &str) -> Result<(), std::io::Error> {
        use crate::protocols::pcap_file::*;

        let mut pcap = PcapFile!();
        for p in self {
            let pp = PcapPacket!(data = p.clone().lencode());
            pcap.push(pp);
        }

        pcap.write(&fname)
    }
}

pub mod encdec;
pub mod protocols;
pub mod typ;

pub fn update_inet_sum(sum: u32, data: &[u8]) -> u32 {
    let mut sum: u32 = sum;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += (data[i + 1] as u32) | ((data[i] as u32) << 8);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    sum
}

pub fn get_inet_sum(data: &[u8]) -> u32 {
    update_inet_sum(0, data)
}

pub fn fold_u32(data: u32) -> u16 {
    0xffff ^ (((data >> 16) as u16) + ((data & 0xffff) as u16))
}
