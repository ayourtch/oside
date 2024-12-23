#![allow(
    dead_code,
    unused_mut,
    unused_variables,
    unused_must_use,
    non_camel_case_types,
    unused_imports,
    unused_parens
)]
use generic_array::{ArrayLength, GenericArray};
// use log::trace;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;
use std::str::Utf8Error;
/*
use serde::de::Error;
use serde::{Deserialize, Serialize};
// use typenum::{U10, U256, U32, U64};
*/

use crate::Decode;
use crate::Decoder;
use crate::Encode;
use crate::Encoder;
use crate::Value::Random;

use rand::distributions::{Distribution, Standard};
use rand::Rng;

use serde::{Deserialize, Serialize};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct FixedSizeString<N: ArrayLength>(GenericArray<u8, N>);

impl<N: ArrayLength> Encode for FixedSizeString<N> {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out: GenericArray<u8, N> = self.0.clone();
        out.to_vec()
    }
}

// FIXME: take into account the hwlen from packet
impl<N: ArrayLength> Decode for FixedSizeString<N> {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let size = N::to_usize();
        if let Some((mac_vec, count)) = D::decode_vec(buf, size) {
            let mut res: GenericArray<u8, N> = Default::default();
            let length = N::to_u32() as usize;
            for i in 0..length {
                res[i] = mac_vec[i];
            }
            Some((FixedSizeString(res), count))
        } else {
            None
        }
    }
}

impl<N: ArrayLength> fmt::Debug for FixedSizeString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = &self.0;
        let val_str = match std::str::from_utf8(v) {
            Ok(s) => format!("{:?}", &s.trim_end_matches("\u{0}")),
            Err(_) => format!("{:?}", &v),
        };
        write!(f, "FixedSizeString[{}]: {}", &N::to_u32(), &val_str)
    }
}

impl<N: ArrayLength> TryFrom<&str> for FixedSizeString<N> {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut out: GenericArray<u8, N> = Default::default();
        let max_len = out.len() - 1;
        if value.len() > max_len {
            Err(format!(
                "The source length of {:?} is {} > max {}",
                value,
                value.len(),
                max_len
            ))
        } else {
            for (i, b) in value.as_bytes().into_iter().enumerate() {
                out[i] = *b;
            }

            Ok(FixedSizeString(out))
        }
    }
}

impl<N: ArrayLength> FromStr for FixedSizeString<N> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl<N: ArrayLength> Distribution<FixedSizeString<N>> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> FixedSizeString<N> {
        let mut out: GenericArray<u8, N> = Default::default();
        let max_len = out.len() - 1;
        for i in 0..out.len() {
            out[i] = rng.gen();
        }
        FixedSizeString(out)
    }
}

impl<N> FixedSizeString<N>
where
    N: ArrayLength,
{
    pub fn equals_str(&self, compare_to: &str) -> bool {
        let v = &self.0;
        if let Ok(val_str) = std::str::from_utf8(v) {
            if compare_to == val_str.trim_end_matches("\u{0}") {
                return true;
            }
        }
        false
    }
}

impl<N> TryFrom<FixedSizeString<N>> for String
where
    N: ArrayLength,
{
    type Error = Utf8Error;

    fn try_from(value: FixedSizeString<N>) -> Result<Self, Self::Error> {
        let v = &value.0;
        let val_str = std::str::from_utf8(v)?;
        Ok(val_str.trim_end_matches("\u{0}").to_string())
    }
}

impl<N: ArrayLength> Serialize for FixedSizeString<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.0;

        let mut len = data.len();
        let mut seq = serializer.serialize_tuple(len)?;
        for b in data {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

impl<'de, N: ArrayLength> Deserialize<'de> for FixedSizeString<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeStringVisitor<N> {
            marker: PhantomData<N>,
        }
        impl<'de, N> Visitor<'de> for FixedSizeStringVisitor<N>
        where
            N: ArrayLength,
        {
            type Value = FixedSizeString<N>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("FixedSizeString")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut res: GenericArray<u8, N> = Default::default();
                let length = N::to_u32() as usize;

                for i in 0..length {
                    let b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    res[i] = b;
                }

                return Ok(FixedSizeString(res));
            }
        }

        return Ok(deserializer.deserialize_tuple(
            N::to_u32() as usize,
            FixedSizeStringVisitor {
                marker: PhantomData,
            },
        )?);
    }
}

#[derive(Clone, Default)]
pub struct VariableSizeString(Vec<u8>);

impl fmt::Debug for VariableSizeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = &self.0;
        let val_str = match std::str::from_utf8(v) {
            Ok(s) => format!("{:?}", &s),
            Err(_) => format!("{:?}", &v),
        };
        write!(f, "VariableSizeString: {}", &val_str)
    }
}

impl TryFrom<&str> for VariableSizeString {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut out: Vec<u8> = vec![];
        for b in value.as_bytes().into_iter() {
            out.push(*b);
        }

        Ok(VariableSizeString(out))
    }
}

impl Serialize for VariableSizeString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.0;

        let len: usize = data.len();
        let len_u32: u32 = len.try_into().unwrap();
        let mut seq = serializer.serialize_tuple(len)?;
        seq.serialize_element(&len_u32)?;
        for b in data {
            seq.serialize_element(&b)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for VariableSizeString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VariableSizeStringVisitor;
        impl<'de> Visitor<'de> for VariableSizeStringVisitor {
            type Value = VariableSizeString;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("VariableSizeString")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut res: Vec<u8> = vec![];
                let length: u32 = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                for i in 0..length {
                    res.push(
                        seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?,
                    );
                }

                return Ok(VariableSizeString(res));
            }
        }

        return Ok(deserializer.deserialize_tuple(1 << 31, VariableSizeStringVisitor)?);
    }
}

#[derive(Clone)]
pub struct F64(pub f64);

impl fmt::Debug for F64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = &self.0;
        write!(f, "F64({})", &v)
    }
}

impl TryFrom<&f64> for F64 {
    type Error = String;

    fn try_from(value: &f64) -> Result<Self, Self::Error> {
        Ok(F64(*value))
    }
}

impl Serialize for F64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.0;
        let out = f64::from_bits((data).to_bits().to_be());
        serializer.serialize_f64(out)
    }
}

impl<'de> Deserialize<'de> for F64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct F64Visitor;
        impl<'de> Visitor<'de> for F64Visitor {
            type Value = F64;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("F64")
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let f64_value = f64::from_bits(value.to_bits().to_be());
                Ok(F64(f64_value))
            }
        }

        return Ok(deserializer.deserialize_f64(F64Visitor)?);
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(bound = "N: ArrayLength, T: Deserialize<'de> + Default")]
pub struct FixedSizeArray<T: Default + Debug, N: ArrayLength>(pub GenericArray<T, N>);

impl<T: Debug + Default, N: ArrayLength> fmt::Debug for FixedSizeArray<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = &self.0;
        write!(f, "FixedSizeArray[{}]: [{:?}]", &N::to_u32(), &v)
    }
}

impl<T: Debug + Default + Clone, N: ArrayLength> TryFrom<Vec<T>> for FixedSizeArray<T, N> {
    type Error = String;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let mut out: GenericArray<T, N> = Default::default();
        let max_len = out.len();
        if value.len() > max_len {
            Err(format!(
                "The source length of {:?} is {} > max {}",
                value,
                value.len(),
                max_len
            ))
        } else {
            for i in 0..value.len() {
                out[i] = value[i].clone() as T;
            }

            Ok(FixedSizeArray(out))
        }
    }
}

impl<T: Serialize + Default + Debug, N: ArrayLength> Serialize for FixedSizeArray<T, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.0;

        let mut len = data.len();
        let mut seq = serializer.serialize_tuple(len)?;
        for b in data {
            seq.serialize_element(b)?;
        }
        seq.end()
    }
}

// Copying Fixed Size String Deserialize for u8
/* impl<'de,T: Deserialize<'de>+Default+Debug, N: ArrayLength<T>> Deserialize<'de> for FixedSizeArray<T,N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArrayVisitor<N> {
            marker: PhantomData<N>,
        };
        impl<'de, N> Visitor<'de> for FixedSizeArrayVisitor<N>
        where
            N: ArrayLength<u8>,
        {
            type Value = FixedSizeArray<u8,N>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("FixedSizeString")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut res: GenericArray<u8, N> = Default::default();
                let length = N::to_u32() as usize;

                for i in 0..length {
                    let b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    res[i] = b;
                }

                return Ok(FixedSizeArray(res));
            }
        }

        return Ok(deserializer.deserialize_tuple(
            N::to_u32() as usize,
            FixedSizeArrayVisitor {
                marker: PhantomData,
            },
        )?);
    }
}*/

// FIXME: implement the deserialize manually.

/* impl<'de, 'tde, T: Deserialize<'tde>, N: ArrayLength<T>> Deserialize<'de> for FixedSizeArray<T, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArrayVisitor<N> {
            marker: PhantomData<N>,
        };
        impl<'de, N, T> Visitor<'de> for FixedSizeArrayVisitor<N>
        where
            T: Deserialize+Default
            N: ArrayLength<T>,
        {
            type Value = FixedSizeArray<T, N>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("FixedSizeArray")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut res: GenericArray<T, N> = Default::default();
                let length = N::to_u32() as usize;

                for i in 0..length {
                    let b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    res[i] = b as T;
                }

                return Ok(FixedSizeArray(res));
            }
        }

        return Ok(deserializer.deserialize_tuple(
            N::to_u32() as usize,
            FixedSizeArrayVisitor {
                marker: PhantomData,
            },
        )?);
    }
}
*/
/* impl<'de, T: Deserialize<'de>+Default,N: ArrayLength<T>> Deserialize<'de> for FixedSizeArray<T,N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArrayVisitor<T:Default,N> {
            marker: PhantomData<N>,
        };
        impl<'de, T, N> Visitor<'de> for FixedSizeArrayVisitor<T,N>
        where
            T: Deserialize<'de>+Default,
            N: ArrayLength<T>,
        {
            type Value = FixedSizeArray<T,N>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("FixedSizeArray")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut res: GenericArray<T, N> = Default::default();
                let length = N::to_u32() as usize;

                for i in 0..length {
                    let b = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    res[i] = b;
                }

                return Ok(FixedSizeArray(res));
            }
        }

        return Ok(deserializer.deserialize_tuple(
            N::to_u32() as usize,
            FixedSizeArrayVisitor {
                marker: PhantomData,
            },
        )?);
    }
}
*/
#[derive(Copy, Clone, Default, Deserialize)]
#[serde(bound = "T: Deserialize<'de> + Default")]
pub struct SizedEnum<T, X>(T, PhantomData<X>); // This is the sized enum declaration, It's a unit struct

impl<T: Debug, X> fmt::Debug for SizedEnum<T, X> {
    // implement debug trait for sized enum
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = &self.0;
        write!(f, "SizedEnum[{}]: {:?}", std::any::type_name::<X>(), &v)
    }
}

impl<T: Serialize + Copy + AsU32 + Debug, X: Serialize + Debug + TryFrom<u32>> Serialize
    for SizedEnum<T, X>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = self.0.clone();
        let data_u32: u32 = AsU32::as_u32(data);

        let data_x = if let Ok(x) = X::try_from(data_u32) {
            x
        } else {
            return (Err(serde::ser::Error::custom("does not fit")));
        };

        let mut seq = serializer.serialize_tuple(1)?;
        seq.serialize_element(&data_x)?;
        seq.end()
    }
}

pub trait AsU32 {
    fn as_u32(data: Self) -> u32;
}

/* FIXME: add deserializer for SizedEnum */

#[derive(Clone, Default, Debug)]
pub struct VariableSizeArray<T>(pub Vec<T>);

use serde::ser::{SerializeSeq, SerializeTuple, Serializer};

impl<T: Debug + Serialize> Serialize for VariableSizeArray<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.0;

        let mut len = data.len();
        let mut seq = serializer.serialize_tuple(len)?;
        for b in data {
            seq.serialize_element(&b)?;
        }
        seq.end()
    }
}

use core::marker::PhantomData;
use serde::de::{self, Deserializer, SeqAccess, Visitor};
use std::fmt::Debug;
// use std::fmt;

impl<'de, T: Deserialize<'de> + Debug> Deserialize<'de> for VariableSizeArray<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct VariableSizeArrayVisitor<T> {
            marker: PhantomData<T>,
        }
        let mut size = 0;
        impl<'de, T> Visitor<'de> for VariableSizeArrayVisitor<T>
        where
            T: Deserialize<'de> + Debug,
        {
            type Value = VariableSizeArray<T>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("VariableSizeArray")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut res: Vec<T> = vec![];
                /*
                                let length: u32 = seq
                                    .next_element()?
                                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                */

                loop {
                    let nxt = seq.next_element();
                    if nxt.is_err() {
                        break;
                    }
                    let nxt = nxt?;
                    if nxt.is_some() {
                        let nxt: T = nxt.unwrap();
                        res.push(nxt);
                    }
                }
                /*
                for i in 0..length {
                    res.push(
                        seq.next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?,
                    );
                }
                */

                return Ok(VariableSizeArray::<T>(res));
            }
        }

        return Ok(deserializer.deserialize_tuple(
            1 << 31,
            VariableSizeArrayVisitor {
                marker: PhantomData,
            },
        )?);
    }
}

pub trait AsEnumFlag {
    fn as_u32(data: &Self) -> u32;
    fn from_u32(data: u32) -> Self;
    fn size_of_enum_flag() -> u32;
}

#[derive(Clone, Debug)]
pub struct EnumFlag<T: Clone + Debug + AsEnumFlag>(Vec<T>);

impl<T> EnumFlag<T>
where
    T: Clone + Debug + AsEnumFlag + std::cmp::PartialEq,
{
    pub fn contains(&self, other: T) -> bool {
        self.0.contains(&other)
    }
}

impl<T: Clone + Debug + AsEnumFlag> TryFrom<Vec<T>> for EnumFlag<T> {
    type Error = String;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        let mut out = vec![];
        for i in 0..value.len() {
            out.push(value[i].clone());
        }
        Ok(EnumFlag(out))
    }
}
impl<T: Clone + Debug + AsEnumFlag> Default for EnumFlag<T> {
    fn default() -> Self {
        vec![].try_into().unwrap()
    }
}
impl<T: Clone + Debug + AsEnumFlag> EnumFlag<T> {
    pub fn sum(&self) -> u32 {
        let mut sum: u32 = 0;
        for x in &self.0 {
            sum = sum + T::as_u32(x); // AsU8 and AsU32 trait needed for using T
        }
        sum
    }
}
impl<T: Clone + Debug + AsEnumFlag> Serialize for EnumFlag<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let size: u32 = T::size_of_enum_flag();
        match size {
            32 => serializer.serialize_u32(self.sum()),
            16 => serializer.serialize_u16(self.sum() as u16),
            8 => serializer.serialize_u8(self.sum() as u8),
            _ => panic!("EnumFlags do not support {} bit type flag", size),
        }
    }
}
impl<'de, T: Debug + Clone + AsEnumFlag + Deserialize<'de>> Deserialize<'de> for EnumFlag<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        struct EnumFlagVisitor<T> {
            marker: PhantomData<T>,
        }
        // let mut size = 0;
        impl<'de, T> Visitor<'de> for EnumFlagVisitor<T>
        where
            T: Debug + Clone + AsEnumFlag,
        {
            type Value = EnumFlag<T>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("EnumFlag")
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let mut res: Vec<T> = vec![];
                // trace!("{}", v);
                /* let number = u32::pow(2, v);
                let enum_d: T = AsU32::from_u32(number);
                res.push(enum_d);*/
                let felix = format!("{:032b}", v);
                let char_vec: Vec<char> = felix.chars().collect();
                for c in 0..char_vec.len() {
                    if char_vec[c] == '1' {
                        let size: u32 = char_vec.len() as u32 - c as u32 - 1;
                        let number = u32::pow(2, size);
                        let enum_d = T::from_u32(number);
                        res.push(enum_d);
                    }
                }
                return Ok(EnumFlag::<T>(res));
            }
            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let mut res: Vec<T> = vec![];
                // trace!("{}", v);
                /* let number = u32::pow(2, v);
                let enum_d: T = AsU32::from_u32(number);
                res.push(enum_d);*/
                let felix = format!("{:016b}", v);
                let char_vec: Vec<char> = felix.chars().collect();
                for c in 0..char_vec.len() {
                    if char_vec[c] == '1' {
                        let size: u32 = char_vec.len() as u32 - c as u32 - 1;
                        let number = u32::pow(2, size);
                        let enum_d = T::from_u32(number);
                        res.push(enum_d);
                    }
                }
                return Ok(EnumFlag::<T>(res));
            }
            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let mut res: Vec<T> = vec![];
                // trace!("{}", v);
                /* let number = u32::pow(2, v);
                let enum_d: T = AsU32::from_u32(number);
                res.push(enum_d);*/
                let felix = format!("{:08b}", v);
                let char_vec: Vec<char> = felix.chars().collect();
                for c in 0..char_vec.len() {
                    if char_vec[c] == '1' {
                        let size: u32 = char_vec.len() as u32 - c as u32 - 1;
                        let number = u32::pow(2, size);
                        let enum_d = T::from_u32(number);
                        res.push(enum_d);
                    }
                }
                return Ok(EnumFlag::<T>(res));
            }
        }
        let size: u32 = T::size_of_enum_flag();
        match size {
            32 => {
                return Ok(deserializer.deserialize_u32(EnumFlagVisitor {
                    marker: PhantomData,
                })?);
            }
            16 => {
                return Ok(deserializer.deserialize_u16(EnumFlagVisitor {
                    marker: PhantomData,
                })?);
            }
            8 => {
                return Ok(deserializer.deserialize_u8(EnumFlagVisitor {
                    marker: PhantomData,
                })?);
            }
            _ => panic!("Deserializing not supported for {} bit set flags", size),
        }
    }
}
