use crate::*;
use serde::{Deserialize, Serialize};

// Basic IPv6 header format
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x86DD))]
pub struct Ipv6 {
    #[nproto(default = 0x60000000)]
    pub version_class: Value<u32>, // Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    #[nproto(encode = encode_ipv6_length, fill = fill_ipv6_length)]
    pub payload_length: Value<u16>, // Payload length
    #[nproto(next: IANA_LAYERS => Proto)]
    pub next_header: Value<u8>, // Next Header (similar to IPv4 protocol field)
    #[nproto(default = 64)]
    pub hop_limit: Value<u8>, // Hop Limit (similar to IPv4 TTL)
    pub src: Value<Ipv6Address>, // Source address
    pub dst: Value<Ipv6Address>, // Destination address
}

fn encode_ipv6_length<E: Encoder>(
    me: &Ipv6,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    let mut payload_len: usize = 0;

    // Sum up the length of all layers after IPv6 header
    for i in my_index + 1..encoded_layers.len() {
        payload_len += encoded_layers[i].len();
    }

    let len: u16 = payload_len.try_into().unwrap();
    len.encode::<E>()
}

fn fill_ipv6_length(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

impl Encode for Ipv6Address {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Decode for Ipv6Address {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 16 {
            return None;
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&buf[0..16]);
        Some((Ipv6Address(addr), 16))
    }
}
