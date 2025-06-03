use crate::asn1;
use crate::{Decoder, Encoder};

pub struct Asn1Decoder;

impl Asn1Decoder {
    /// Decode an INTEGER and return the value and bytes consumed
    pub fn decode_integer(buf: &[u8]) -> Option<(i64, usize)> {
        let ((tag, len), tag_len_consumed) = Self::parse_tag_and_len(buf, 0)?;
        if tag != asn1::Tag::Integer {
            return None;
        }

        let value_start = tag_len_consumed;
        let value_end = value_start + len;

        if value_end > buf.len() {
            return None;
        }

        let value_bytes = &buf[value_start..value_end];
        let (value, _) = Self::parse_just_integer_unsigned(value_bytes, len).ok()?;

        Some((value as i64, value_end))
    }

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
        if ci + 2 > buf.len() {
            eprintln!("parse_tag_and_len: not enough bytes - buf: {:02x?}", buf);
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
        if ci + 2 > buf.len() {
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

    pub fn parse_just_integer_unsigned(buf: &[u8], length: usize) -> Result<(u64, usize), String> {
        if buf.len() < length {
            return Err(format!(
                "Supplied length {} but buffer '{:?}' is too short",
                length, &buf
            ));
        }
        let mut value: u64 = 0;
        let mut is_negative = false;
        let mut ci = 0;

        if length > 0 {
            is_negative = (buf[ci] & 0x80) != 0;
            for i in 0..length {
                value = (value << 8) | (buf[ci + i] as u64);
            }
        }
        assert!(is_negative == false);
        /*
        let out = if is_negative {
            value | !((1 << (length * 8)) - 1)
        } else {
            value
        };
        */
        Ok((value, ci))
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
        if ci + 2 > buf.len() {
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

impl Asn1Encoder {
    pub fn encode_null() -> Vec<u8> {
        vec![0x05, 0x00] // NULL tag + zero length
    }

    // Helper method to encode boolean values
    pub fn encode_boolean(value: bool) -> Vec<u8> {
        let mut result = vec![0x01, 0x01]; // BOOLEAN tag + length 1
        result.push(if value { 0xFF } else { 0x00 });
        result
    }

    // Method to encode a raw tag with data (useful for unknown/custom tags)
    pub fn encode_with_tag(tag: u8, data: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        result.extend(Self::encode_length(data.len()));
        result.extend_from_slice(data);
        result
    }

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
    // Encode an ASN.1 tag according to DER rules
    pub fn encode_tag(tag: &asn1::Tag) -> Vec<u8> {
        match tag {
            asn1::Tag::Boolean => vec![0x01],
            asn1::Tag::Integer => vec![0x02],
            asn1::Tag::BitString => vec![0x03],
            asn1::Tag::OctetString => vec![0x04],
            asn1::Tag::Null => vec![0x05],
            asn1::Tag::ObjectIdentifier => vec![0x06],
            asn1::Tag::Sequence => vec![0x30],
            asn1::Tag::UnknownTag(x) => vec![*x],
            asn1::Tag::Extended(x) => {
                let mut result = vec![0x1F]; // Extended tag marker
                let mut value = *x;
                let mut bytes = Vec::new();

                // Encode in base-128 with continuation bits
                loop {
                    let mut byte = (value & 0x7F) as u8;
                    value >>= 7;
                    if !bytes.is_empty() {
                        byte |= 0x80; // Set continuation bit for all but the last byte
                    }
                    bytes.insert(0, byte);
                    if value == 0 {
                        break;
                    }
                }

                result.extend(bytes);
                result
            }
        }
    }

    // Encode an entire ASN.1 object
    pub fn encode_asn1_object(obj: &asn1::ASN1Object) -> Vec<u8> {
        let mut result = Self::encode_tag(&obj.tag);
        let value_bytes = Self::encode_value(&obj.value);
        result.extend(Self::encode_length(value_bytes.len()));
        result.extend(value_bytes);
        result
    }

    pub fn encode_oid(oid: &Vec<u64>) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (i, &value) in oid.iter().enumerate() {
            let mut val = value;
            let mut val_bytes = Vec::new();

            // Encode in base-128 with continuation bits
            loop {
                let mut byte = (val & 0x7F) as u8;
                val >>= 7;
                if !val_bytes.is_empty() {
                    byte |= 0x80;
                }
                val_bytes.insert(0, byte);
                if val == 0 {
                    break;
                }
            }
            bytes.extend(val_bytes);
        }
        bytes
    }

    // Encode an ASN.1 value
    pub fn encode_value(value: &asn1::Value) -> Vec<u8> {
        match value {
            asn1::Value::Boolean(b) => vec![if *b { 0xFF } else { 0x00 }],
            asn1::Value::Integer(i) => {
                let mut bytes = Vec::new();
                let mut val = *i;

                // Convert to bytes ensuring proper sign handling
                if val == 0 {
                    bytes.push(0);
                } else {
                    let is_negative = val < 0;
                    while val != 0 && val != -1 {
                        bytes.insert(0, (val & 0xFF) as u8);
                        val >>= 8;
                    }

                    // Ensure proper sign bit
                    if is_negative && (bytes[0] & 0x80) == 0 {
                        bytes.insert(0, 0xFF);
                    } else if !is_negative && (bytes[0] & 0x80) != 0 {
                        bytes.insert(0, 0x00);
                    }
                }
                bytes
            }
            asn1::Value::BitString(bytes) => bytes.clone(),
            asn1::Value::OctetString(bytes) => bytes.clone(),
            asn1::Value::Null => Vec::new(),
            asn1::Value::ObjectIdentifier(oid) => {
                let mut bytes = Vec::new();
                for (i, &value) in oid.iter().enumerate() {
                    let mut val = value;
                    let mut val_bytes = Vec::new();

                    // Encode in base-128 with continuation bits
                    loop {
                        let mut byte = (val & 0x7F) as u8;
                        val >>= 7;
                        if !val_bytes.is_empty() {
                            byte |= 0x80;
                        }
                        val_bytes.insert(0, byte);
                        if val == 0 {
                            break;
                        }
                    }
                    bytes.extend(val_bytes);
                }
                bytes
            }
            asn1::Value::Sequence(seq) => {
                let mut bytes = Vec::new();
                for obj in seq {
                    bytes.extend(Self::encode_asn1_object(obj));
                }
                bytes
            }
            asn1::Value::UnknownConstructed(_, seq) => {
                let mut bytes = Vec::new();
                for obj in seq {
                    bytes.extend(Self::encode_asn1_object(obj));
                }
                bytes
            }
            asn1::Value::UnknownPrimitive(_, bytes) => bytes.clone(),
        }
    }
    // Helper function to encode length in DER format
    pub fn encode_length(length: usize) -> Vec<u8> {
        if length < 128 {
            // Short form
            vec![length as u8]
        } else {
            // Long form
            let mut length_bytes = Vec::new();
            let mut len = length;

            // Convert length to bytes
            while len > 0 {
                length_bytes.insert(0, (len & 0xFF) as u8);
                len >>= 8;
            }

            // Add number of length bytes with high bit set
            let mut result = vec![(0x80 | length_bytes.len() as u8)];
            result.extend(length_bytes);
            result
        }
    }

    // Helper function to encode integers
    pub fn encode_integer_bytes(value: u64, force_positive: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut val = value;

        // Convert to bytes
        while val > 0 {
            bytes.insert(0, (val & 0xFF) as u8);
            val >>= 8;
        }

        // Ensure positive numbers starting with high bit set have a leading zero
        if force_positive && !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
            bytes.insert(0, 0);
        }

        // Handle zero specially
        if bytes.is_empty() {
            bytes.push(0);
        }

        bytes
    }

    pub fn encode_context_tag(tag: u8, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();

        // Context-specific tag (class 10, primitive/constructed based on data)
        let tag_byte = 0x80 | tag; // Context-specific, primitive
        result.push(tag_byte);

        // Encode length
        if data.len() < 0x80 {
            result.push(data.len() as u8);
        } else {
            // Long form length encoding
            let len_bytes = if data.len() < 0x100 {
                vec![data.len() as u8]
            } else if data.len() < 0x10000 {
                vec![(data.len() >> 8) as u8, data.len() as u8]
            } else {
                vec![
                    (data.len() >> 16) as u8,
                    (data.len() >> 8) as u8,
                    data.len() as u8,
                ]
            };

            result.push(0x80 | len_bytes.len() as u8);
            result.extend(len_bytes);
        }

        // Add the data
        result.extend_from_slice(data);
        result
    }

    pub fn encode_sequence(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE tag

        // Encode length
        if data.len() < 0x80 {
            result.push(data.len() as u8);
        } else {
            // Long form length encoding
            let len_bytes = if data.len() < 0x100 {
                vec![data.len() as u8]
            } else if data.len() < 0x10000 {
                vec![(data.len() >> 8) as u8, data.len() as u8]
            } else {
                vec![
                    (data.len() >> 16) as u8,
                    (data.len() >> 8) as u8,
                    data.len() as u8,
                ]
            };

            result.push(0x80 | len_bytes.len() as u8);
            result.extend(len_bytes);
        }

        result.extend_from_slice(data);
        result
    }

    pub fn encode_integer(value: i64) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x02); // INTEGER tag

        // Convert to minimal bytes representation
        let bytes = if value == 0 {
            vec![0]
        } else if value > 0 {
            let mut bytes = Vec::new();
            let mut val = value as u64;
            while val > 0 {
                bytes.insert(0, (val & 0xFF) as u8);
                val >>= 8;
            }
            // If high bit is set, prepend 0x00 to indicate positive
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, 0x00);
            }
            bytes
        } else {
            // Handle negative numbers (two's complement)
            let mut bytes = Vec::new();
            let mut val = value as u64;
            while val != 0xFFFFFFFFFFFFFFFF || bytes.is_empty() {
                bytes.insert(0, (val & 0xFF) as u8);
                val >>= 8;
            }
            // If high bit is not set, prepend 0xFF to indicate negative
            if bytes[0] & 0x80 == 0 {
                bytes.insert(0, 0xFF);
            }
            bytes
        };

        // Encode length
        result.push(bytes.len() as u8);
        result.extend(bytes);
        result
    }

    pub fn encode_octetstring(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x04); // OCTET STRING tag

        // Encode length
        if data.len() < 0x80 {
            result.push(data.len() as u8);
        } else {
            // Long form length encoding
            let len_bytes = if data.len() < 0x100 {
                vec![data.len() as u8]
            } else if data.len() < 0x10000 {
                vec![(data.len() >> 8) as u8, data.len() as u8]
            } else {
                vec![
                    (data.len() >> 16) as u8,
                    (data.len() >> 8) as u8,
                    data.len() as u8,
                ]
            };

            result.push(0x80 | len_bytes.len() as u8);
            result.extend(len_bytes);
        }

        result.extend_from_slice(data);
        result
    }
}

impl Encoder for Asn1Encoder {
    fn encode_u8(v1: u8) -> Vec<u8> {
        let mut result = vec![0x02]; // Integer tag
        let value_bytes = Self::encode_integer_bytes(v1 as u64, true);
        result.extend(Self::encode_length(value_bytes.len()));
        result.extend(value_bytes);
        result
    }

    fn encode_u16(v1: u16) -> Vec<u8> {
        let mut result = vec![0x02]; // Integer tag
        let value_bytes = Self::encode_integer_bytes(v1 as u64, true);
        result.extend(Self::encode_length(value_bytes.len()));
        result.extend(value_bytes);
        result
    }

    fn encode_u32(v1: u32) -> Vec<u8> {
        let mut result = vec![0x02]; // Integer tag
        let value_bytes = Self::encode_integer_bytes(v1 as u64, true);
        eprintln!(
            "U32 0x{:08x?} length: {}, bytes: {:02x?}",
            &v1,
            value_bytes.len(),
            &value_bytes
        );
        if value_bytes.len() == 5 {
            // panic!("U32 length is 5!");
        }
        result.extend(Self::encode_length(value_bytes.len()));
        result.extend(value_bytes);
        result
    }

    fn encode_u64(v1: u64) -> Vec<u8> {
        let mut result = vec![0x02]; // Integer tag
        let value_bytes = Self::encode_integer_bytes(v1, true);
        result.extend(Self::encode_length(value_bytes.len()));
        result.extend(value_bytes);
        result
    }

    fn encode_vec(v1: &Vec<u8>) -> Vec<u8> {
        let mut result = vec![0x04]; // OctetString tag
        result.extend(Self::encode_length(v1.len()));
        result.extend(v1);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::{ASN1Object, Tag, Value};
    use crate::Decoder;

    #[test]
    fn test_encode_decode_u8() {
        let values = vec![0, 1, 127, 128, 255];
        for value in values {
            let encoded = Asn1Encoder::encode_u8(value);
            let (decoded, _) = Asn1Decoder::decode_u8(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_encode_decode_u16() {
        let values = vec![0, 1, 255, 256, 32767, 32768, 65535];
        for value in values {
            let encoded = Asn1Encoder::encode_u16(value);
            let (decoded, _) = Asn1Decoder::decode_u16(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_encode_decode_u32() {
        let values = vec![0, 1, 65535, 65536, 2147483647, 2147483648, 4294967295];
        for value in values {
            let encoded = Asn1Encoder::encode_u32(value);
            let (decoded, _) = Asn1Decoder::decode_u32(&encoded).unwrap();
            assert_eq!(value, decoded);
        }
    }

    #[test]
    fn test_encode_decode_vec() {
        let test_data = vec![1, 2, 3, 4, 5];
        let encoded = Asn1Encoder::encode_vec(&test_data);
        let (decoded, _) = Asn1Decoder::decode_octetstring(&encoded).unwrap();
        assert_eq!(test_data, decoded);
    }

    #[test]
    fn test_encode_length() {
        // Test short form
        assert_eq!(Asn1Encoder::encode_length(127), vec![127]);

        // Test long form
        assert_eq!(Asn1Encoder::encode_length(128), vec![0x81, 128]);
        assert_eq!(Asn1Encoder::encode_length(256), vec![0x82, 1, 0]);
    }

    #[test]
    fn test_encode_tag() {
        assert_eq!(Asn1Encoder::encode_tag(&Tag::Boolean), vec![0x01]);
        assert_eq!(Asn1Encoder::encode_tag(&Tag::Integer), vec![0x02]);
        assert_eq!(Asn1Encoder::encode_tag(&Tag::Sequence), vec![0x30]);

        // Test extended tag
        assert_eq!(
            Asn1Encoder::encode_tag(&Tag::Extended(255)),
            vec![0x1F, 0x81, 0x7F]
        ); // 255 encoded in base-128 with continuation bit
    }

    #[test]
    fn test_encode_decode_asn1_object() {
        // Test boolean
        let obj = ASN1Object {
            tag: Tag::Boolean,
            value: Value::Boolean(true),
        };
        let encoded = Asn1Encoder::encode_asn1_object(&obj);
        let (decoded, _) = Asn1Decoder::parse(&encoded, 0).unwrap();
        assert_eq!(obj, decoded);

        // Test integer
        let obj = ASN1Object {
            tag: Tag::Integer,
            value: Value::Integer(12345),
        };
        let encoded = Asn1Encoder::encode_asn1_object(&obj);
        let (decoded, _) = Asn1Decoder::parse(&encoded, 0).unwrap();
        assert_eq!(obj, decoded);

        // Test sequence
        let obj = ASN1Object {
            tag: Tag::Sequence,
            value: Value::Sequence(vec![
                ASN1Object {
                    tag: Tag::Integer,
                    value: Value::Integer(1),
                },
                ASN1Object {
                    tag: Tag::Boolean,
                    value: Value::Boolean(true),
                },
            ]),
        };
        let encoded = Asn1Encoder::encode_asn1_object(&obj);
        let (decoded, _) = Asn1Decoder::parse(&encoded, 0).unwrap();
        assert_eq!(obj, decoded);
    }
}
