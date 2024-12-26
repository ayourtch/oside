use crate::*;

pub struct Asn1Decoder;

impl Asn1Decoder {
    fn parse_integer(buf: &[u8], ci: usize) -> Result<(i64, usize), String> {
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

    fn parse_length(buf: &[u8], ci: usize) -> Result<(usize, usize), String> {
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
}

impl Decoder for Asn1Decoder {
    fn pre_decode_seq(buf: &[u8], len: usize) -> Option<(usize, usize)> {
        if len < 2 {
            return None;
        }
        let tag = buf[0];
        if tag != 0x30 {
            return None;
        }
        let mut ci = 1;
        if let Ok((new_len, delta)) = Self::parse_length(buf, ci) {
            return Some((new_len, ci + delta));
        }
        // Could not parse tag + len - refuse parsing further
        None
    }

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
        if buf.len() >= 4 {
            let v = buf[0] as u32;
            let v = (v << 8) + buf[1] as u32;
            let v = (v << 8) + buf[2] as u32;
            let v = (v << 8) + buf[3] as u32;
            Some((v, 4))
        } else {
            None
        }
    }
    fn decode_u64(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.len() >= 8 {
            let v = buf[0] as u64;
            let v = (v << 8) + buf[1] as u64;
            let v = (v << 8) + buf[2] as u64;
            let v = (v << 8) + buf[3] as u64;
            let v = (v << 8) + buf[4] as u64;
            let v = (v << 8) + buf[5] as u64;
            let v = (v << 8) + buf[6] as u64;
            let v = (v << 8) + buf[7] as u64;
            Some((v, 8))
        } else {
            None
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
        let o0 = v1;
        vec![o0]
    }
    fn encode_u16(v1: u16) -> Vec<u8> {
        let o0 = (v1 >> 8) as u8;
        let o1 = (v1 & 0xff) as u8;
        vec![o0, o1]
    }
    fn encode_u32(v1: u32) -> Vec<u8> {
        let o0 = ((v1 >> 24) & 0xff) as u8;
        let o1 = ((v1 >> 16) & 0xff) as u8;
        let o2 = ((v1 >> 8) & 0xff) as u8;
        let o3 = ((v1 >> 0) & 0xff) as u8;
        vec![o0, o1, o2, o3]
    }
    fn encode_u64(v1: u64) -> Vec<u8> {
        let o0 = ((v1 >> 56) & 0xff) as u8;
        let o1 = ((v1 >> 48) & 0xff) as u8;
        let o2 = ((v1 >> 40) & 0xff) as u8;
        let o3 = ((v1 >> 32) & 0xff) as u8;
        let o4 = ((v1 >> 24) & 0xff) as u8;
        let o5 = ((v1 >> 16) & 0xff) as u8;
        let o6 = ((v1 >> 8) & 0xff) as u8;
        let o7 = ((v1 >> 0) & 0xff) as u8;
        vec![o0, o1, o2, o3, o4, o5, o6, o7]
    }
    fn encode_vec(v1: &Vec<u8>) -> Vec<u8> {
        v1.clone()
    }
}
