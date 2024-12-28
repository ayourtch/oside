use crate::asn1;
use crate::{Decoder, Encoder};

pub struct Asn1Decoder;

impl Asn1Decoder {
    pub fn parse_tag(buf: &[u8], ci: usize) -> Result<(asn1::Tag, usize), String> {
        use crate::asn1::*;
        let start = ci;
        let mut ci = ci;
        if ci >= buf.len() {
            return Err("Unexpected end of data while parsing tag".to_string());
        }

        let first_byte = buf[ci];
        ci += 1;

        // Check if it's an extended tag (>= 31)
        if (first_byte & 0x1F) == 0x1F {
            let mut tag_number: u32 = 0;

            // Parse subsequent octets
            loop {
                if ci >= buf.len() {
                    return Err("Unexpected end of data while parsing extended tag".to_string());
                }

                let byte = buf[ci];
                ci += 1;

                tag_number = (tag_number << 7) | ((byte & 0x7F) as u32);

                // Last octet has bit 8 set to zero
                if (byte & 0x80) == 0 {
                    break;
                }
            }
            Ok((Tag::Extended(tag_number), ci - start))
        } else {
            match first_byte {
                0x01 => Ok((Tag::Boolean, 1)),
                0x02 => Ok((Tag::Integer, 1)),
                0x03 => Ok((Tag::BitString, 1)),
                0x04 => Ok((Tag::OctetString, 1)),
                0x05 => Ok((Tag::Null, 1)),
                0x06 => Ok((Tag::ObjectIdentifier, 1)),
                0x30 => Ok((Tag::Sequence, 1)),
                x => Ok((Tag::UnknownTag(x), 1)),
            }
        }
    }

    pub fn parse_tag_and_len(buf: &[u8], ci: usize) -> Option<((asn1::Tag, usize), usize)> {
        if ci + 2 >= buf.len() {
            return None;
        }
        let start = ci;
        let mut ci = ci;
        let (tag, delta) = Self::parse_tag(buf, ci).ok()?;
        ci += delta;
        let (new_len, delta) = Self::parse_length(buf, ci).ok()?;
        Some(((tag, new_len), ci + delta - start))
    }
    pub fn parse(buf: &[u8], ci: usize) -> Result<(asn1::ASN1Object, usize), String> {
        let start = ci;
        let mut ci = ci;
        let (tag, delta) = Self::parse_tag(buf, ci)?;
        ci += delta;
        let (len, delta) = Self::parse_length(buf, ci)?;
        ci += delta;
        let (value, delta) = Self::parse_value(buf, ci, &tag, len)?;
        ci += delta;
        Ok((asn1::ASN1Object { tag, value }, ci - start))
    }

    pub fn parse_value(
        buf: &[u8],
        ci: usize,
        tag: &asn1::Tag,
        length: usize,
    ) -> Result<(asn1::Value, usize), String> {
        use asn1::Tag;
        let start = ci;
        let mut ci = ci;

        if ci + length > buf.len() {
            return Err("Unexpected end of data while parsing value".to_string());
        }

        let value = match tag {
            Tag::Boolean => {
                if length != 1 {
                    return Err("Invalid boolean length".to_string());
                }
                asn1::Value::Boolean(buf[ci] != 0)
            }
            Tag::Integer => {
                let mut value: i64 = 0;
                let mut is_negative = false;

                if length > 0 {
                    is_negative = (buf[ci] & 0x80) != 0;
                    for i in 0..length {
                        value = (value << 8) | (buf[ci + i] as i64);
                    }
                }
                asn1::Value::Integer(if is_negative {
                    value | !((1 << (length * 8)) - 1)
                } else {
                    value
                })
            }
            Tag::BitString => asn1::Value::BitString(buf[ci..ci + length].to_vec()),
            Tag::OctetString => asn1::Value::OctetString(buf[ci..ci + length].to_vec()),
            Tag::Null => {
                if length != 0 {
                    return Err("Invalid null length".to_string());
                }
                asn1::Value::Null
            }
            Tag::ObjectIdentifier => {
                let mut oid = Vec::new();
                let mut value: u64 = 0;
                let mut pos = ci;

                while pos < ci + length {
                    let byte = buf[pos];
                    value = (value << 7) | ((byte & 0x7F) as u64);
                    pos += 1;

                    if byte & 0x80 == 0 {
                        oid.push(value);
                        value = 0;
                    }
                }
                asn1::Value::ObjectIdentifier(oid)
            }
            Tag::Sequence => {
                let mut sequence = Vec::new();
                let mut bytes_read = 0;

                while bytes_read < length {
                    match Self::parse(buf, ci) {
                        Ok((obj, delta)) => {
                            bytes_read += delta;
                            ci += delta;
                            sequence.push(obj);
                        }
                        Err(e) => return Err(e),
                    }
                }
                asn1::Value::Sequence(sequence)
            }
            Tag::UnknownTag(x) => {
                if x & 0x20 == 0x20 {
                    let mut sequence = Vec::new();
                    let mut bytes_read = 0;

                    while bytes_read < length {
                        match Self::parse(buf, ci) {
                            Ok((obj, delta)) => {
                                bytes_read += delta;
                                ci += delta;
                                sequence.push(obj);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    asn1::Value::UnknownConstructed(*x, sequence)
                } else {
                    asn1::Value::UnknownPrimitive(*x, buf[ci..ci + length].to_vec())
                }
            }
            Tag::Extended(_) => {
                return Err("Extended tag not yet supported for value parsing".to_string())
            }
        };

        ci += length;
        Ok((value, ci - start))
    }

    pub fn parse_integer(buf: &[u8], ci: usize) -> Result<(i64, usize), String> {
        let mut value: i64 = 0;
        let mut is_negative = false;
        let mut ci = ci;
        if ci + 2 >= buf.len() {
            return Err("Buffer too short".to_string());
        }
        if buf[ci] != 0x02 {
            // tag is not integer
            return Err(format!("Wrong tag - not integer, but 0x{:02x}", buf[ci]));
        }
        ci += 1;
        let (length, delta) = Self::parse_length(buf, ci)?;
        ci += delta;

        if length > 0 {
            is_negative = (buf[ci] & 0x80) != 0;
            for i in 0..length {
                value = (value << 8) | (buf[ci + i] as i64);
            }
        }

        let out = if is_negative {
            value | !((1 << (length * 8)) - 1)
        } else {
            value
        };
        Ok((out, ci + length))
    }
    pub fn parse_integer_u64(buf: &[u8], ci: usize) -> Result<(u64, usize), String> {
        let mut value: u64 = 0;
        let mut is_negative = false;
        let mut ci = ci;
        if ci + 2 >= buf.len() {
            return Err("Buffer too short".to_string());
        }
        if buf[ci] != 0x02 {
            // tag is not integer
            return Err(format!("Wrong tag - not integer, but 0x{:02x}", buf[ci]));
        }
        ci += 1;
        let (length, delta) = Self::parse_length(buf, ci)?;
        ci += delta;

        if length > 0 {
            is_negative = (buf[ci] & 0x80) != 0;
            for i in 0..length {
                value = (value << 8) | (buf[ci + i] as u64);
            }
        }

        let out = if is_negative {
            return Err(format!("Negative number when expected an unsigned integer"));
        } else {
            value
        };
        Ok((out, ci + length))
    }
    fn parse_octetstring(buf: &[u8], ci: usize) -> Result<(&[u8], usize), String> {
        let mut value: i64 = 0;
        let mut is_negative = false;
        let mut ci = ci;
        if ci + 2 >= buf.len() {
            return Err("Buffer too short".to_string());
        }
        if buf[ci] != 0x04 {
            // tag is not octet string
            return Err(format!(
                "Wrong tag - not octet string, but 0x{:02x}",
                buf[ci]
            ));
        }
        ci += 1;
        let (length, delta) = Self::parse_length(buf, ci)?;
        ci += delta;

        Ok((&buf[ci..ci + length], ci + length))
    }

    pub fn parse_length(buf: &[u8], ci: usize) -> Result<(usize, usize), String> {
        let start = ci;
        let mut ci = ci;
        if ci >= buf.len() {
            return Err("Unexpected end of data while parsing length".to_string());
        }

        let first_byte = buf[ci];
        ci += 1;

        if first_byte & 0x80 == 0 {
            return Ok((first_byte as usize, ci - start));
        }

        let num_bytes = (first_byte & 0x7F) as usize;
        let mut length: usize = 0;

        for _ in 0..num_bytes {
            if ci >= buf.len() {
                return Err("Unexpected end of data while parsing length".to_string());
            }
            length = (length << 8) | (buf[ci] as usize);
            ci += 1;
        }

        Ok((length, ci - start))
    }

    pub fn parse_oid(buf: &[u8], ci: usize, length: usize) -> Option<(Vec<u64>, usize)> {
        let mut oid = Vec::new();
        let mut value: u64 = 0;

        let mut pos = ci;

        while pos < ci + length {
            let byte = buf[pos];
            value = (value << 7) | ((byte & 0x7F) as u64);
            pos += 1;

            if byte & 0x80 == 0 {
                oid.push(value);
                value = 0;
            }
        }
        Some((oid, pos - ci))
    }
}

impl Decoder for Asn1Decoder {
    fn decode_u8(buf: &[u8]) -> Option<(u8, usize)> {
        match Self::parse_integer(buf, 0) {
            Ok((value, delta)) => {
                if value < 0 {
                    return None;
                }
                if value > 255 {
                    return None;
                }
                Some((value as u8, delta))
            }
            Err(x) => None,
        }
    }
    fn decode_u16(buf: &[u8]) -> Option<(u16, usize)> {
        match Self::parse_integer(buf, 0) {
            Ok((value, delta)) => {
                if value < 0 {
                    return None;
                }
                if value > 65535 {
                    return None;
                }
                Some((value as u16, delta))
            }
            Err(x) => None,
        }
    }
    fn decode_u32(buf: &[u8]) -> Option<(u32, usize)> {
        match Self::parse_integer(buf, 0) {
            Ok((value, delta)) => {
                if value < 0 {
                    return None;
                }
                if value > 0x100000000i64 {
                    return None;
                }
                Some((value as u32, delta))
            }
            Err(x) => None,
        }
    }
    fn decode_u64(buf: &[u8]) -> Option<(u64, usize)> {
        match Self::parse_integer_u64(buf, 0) {
            Ok((value, delta)) => Some((value, delta)),
            Err(x) => None,
        }
    }
    fn decode_vec(buf: &[u8], len: usize) -> Option<(Vec<u8>, usize)> {
        if let Ok((octetstring, delta)) = Self::parse_octetstring(buf, 0) {
            if octetstring.len() >= len {
                Some((octetstring[0..len].to_vec(), delta))
            } else {
                Some((octetstring.to_vec(), delta))
            }
        } else {
            None
        }
    }
    fn decode_octetstring(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
        if let Ok((octetstring, delta)) = Self::parse_octetstring(buf, 0) {
            Some((octetstring.to_vec(), delta))
        } else {
            None
        }
    }
}

pub struct Asn1Encoder;
impl Encoder for Asn1Encoder {
    fn encode_u8(v1: u8) -> Vec<u8> {
        panic!("FIXME")
    }
    fn encode_u16(v1: u16) -> Vec<u8> {
        panic!("FIXME")
    }
    fn encode_u32(v1: u32) -> Vec<u8> {
        panic!("FIXME")
    }
    fn encode_u64(v1: u64) -> Vec<u8> {
        panic!("FIXME")
    }
    fn encode_vec(v1: &Vec<u8>) -> Vec<u8> {
        panic!("FIXME")
    }
}
