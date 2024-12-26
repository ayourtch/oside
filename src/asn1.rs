use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Tag {
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    Sequence,
    UnknownTag(u8),
    Extended(u32), // For tags >= 31
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Value {
    Boolean(bool),
    Integer(i64),
    BitString(Vec<u8>),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Vec<u64>),
    Sequence(Vec<ASN1Object>),
    UnknownConstructed(u8, Vec<ASN1Object>),
    UnknownPrimitive(u8, Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ASN1Object {
    tag: Tag,
    value: Value,
}

pub struct Parser {
    data: Vec<u8>,
    position: usize,
}

impl Parser {
    pub fn new(data: Vec<u8>) -> Self {
        Parser { data, position: 0 }
    }

    pub fn parse(&mut self) -> Result<ASN1Object, String> {
        let tag = self.parse_tag()?;
        let length = self.parse_length()?;
        let value = self.parse_value(&tag, length)?;

        Ok(ASN1Object { tag, value })
    }

    fn parse_tag(&mut self) -> Result<Tag, String> {
        if self.position >= self.data.len() {
            return Err("Unexpected end of data while parsing tag".to_string());
        }

        let first_byte = self.data[self.position];
        self.position += 1;

        // Check if it's an extended tag (>= 31)
        if (first_byte & 0x1F) == 0x1F {
            let mut tag_number: u32 = 0;

            // Parse subsequent octets
            loop {
                if self.position >= self.data.len() {
                    return Err("Unexpected end of data while parsing extended tag".to_string());
                }

                let byte = self.data[self.position];
                self.position += 1;

                tag_number = (tag_number << 7) | ((byte & 0x7F) as u32);

                // Last octet has bit 8 set to zero
                if (byte & 0x80) == 0 {
                    break;
                }
            }

            Ok(Tag::Extended(tag_number))
        } else {
            match first_byte {
                0x01 => Ok(Tag::Boolean),
                0x02 => Ok(Tag::Integer),
                0x03 => Ok(Tag::BitString),
                0x04 => Ok(Tag::OctetString),
                0x05 => Ok(Tag::Null),
                0x06 => Ok(Tag::ObjectIdentifier),
                0x30 => Ok(Tag::Sequence),
                x => Ok(Tag::UnknownTag(x)),
            }
        }
    }

    fn parse_length(&mut self) -> Result<usize, String> {
        if self.position >= self.data.len() {
            return Err("Unexpected end of data while parsing length".to_string());
        }

        let first_byte = self.data[self.position];
        self.position += 1;

        if first_byte & 0x80 == 0 {
            return Ok(first_byte as usize);
        }

        let num_bytes = (first_byte & 0x7F) as usize;
        let mut length: usize = 0;

        for _ in 0..num_bytes {
            if self.position >= self.data.len() {
                return Err("Unexpected end of data while parsing length".to_string());
            }
            length = (length << 8) | (self.data[self.position] as usize);
            self.position += 1;
        }

        Ok(length)
    }

    fn parse_value(&mut self, tag: &Tag, length: usize) -> Result<Value, String> {
        if self.position + length > self.data.len() {
            return Err("Unexpected end of data while parsing value".to_string());
        }

        let value = match tag {
            Tag::Boolean => {
                if length != 1 {
                    return Err("Invalid boolean length".to_string());
                }
                Value::Boolean(self.data[self.position] != 0)
            }
            Tag::Integer => {
                let mut value: i64 = 0;
                let mut is_negative = false;

                if length > 0 {
                    is_negative = (self.data[self.position] & 0x80) != 0;
                    for i in 0..length {
                        value = (value << 8) | (self.data[self.position + i] as i64);
                    }
                }
                Value::Integer(if is_negative {
                    value | !((1 << (length * 8)) - 1)
                } else {
                    value
                })
            }
            Tag::BitString => {
                Value::BitString(self.data[self.position..self.position + length].to_vec())
            }
            Tag::OctetString => {
                Value::OctetString(self.data[self.position..self.position + length].to_vec())
            }
            Tag::Null => {
                if length != 0 {
                    return Err("Invalid null length".to_string());
                }
                Value::Null
            }
            Tag::ObjectIdentifier => {
                let mut oid = Vec::new();
                let mut value: u64 = 0;
                let mut pos = self.position;

                while pos < self.position + length {
                    let byte = self.data[pos];
                    value = (value << 7) | ((byte & 0x7F) as u64);
                    pos += 1;

                    if byte & 0x80 == 0 {
                        oid.push(value);
                        value = 0;
                    }
                }
                Value::ObjectIdentifier(oid)
            }
            Tag::Sequence => {
                let mut sequence = Vec::new();
                let mut bytes_read = 0;
                let mut sub_parser =
                    Parser::new(self.data[self.position..self.position + length].to_vec());

                while bytes_read < length {
                    match sub_parser.parse() {
                        Ok(obj) => {
                            bytes_read += sub_parser.position;
                            sequence.push(obj);
                        }
                        Err(e) => return Err(e),
                    }
                }
                Value::Sequence(sequence)
            }
            Tag::UnknownTag(x) => {
                if x & 0x20 == 0x20 {
                    let mut sequence = Vec::new();
                    let mut bytes_read = 0;
                    let mut sub_parser =
                        Parser::new(self.data[self.position..self.position + length].to_vec());

                    while bytes_read < length {
                        match sub_parser.parse() {
                            Ok(obj) => {
                                bytes_read = sub_parser.position;
                                sequence.push(obj);
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Value::UnknownConstructed(*x, sequence)
                } else {
                    Value::UnknownPrimitive(
                        *x,
                        self.data[self.position..self.position + length].to_vec(),
                    )
                }
            }
            Tag::Extended(_) => {
                return Err("Extended tag not yet supported for value parsing".to_string())
            }
        };

        self.position += length;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boolean() {
        let data = vec![0x01, 0x01, 0xFF];
        let mut parser = Parser::new(data);
        let result = parser.parse().unwrap();
        assert!(matches!(result.value, Value::Boolean(true)));
    }

    #[test]
    fn test_integer() {
        let data = vec![0x02, 0x01, 0x42];
        let mut parser = Parser::new(data);
        let result = parser.parse().unwrap();
        assert!(matches!(result.value, Value::Integer(66)));
    }

    #[test]
    fn test_sequence() {
        let data = vec![0x30, 0x06, 0x02, 0x01, 0x42, 0x01, 0x01, 0xFF];
        let mut parser = Parser::new(data);
        let result = parser.parse().unwrap();
        if let Value::Sequence(seq) = result.value {
            assert_eq!(seq.len(), 2);
        } else {
            panic!("Expected sequence");
        }
    }
}
