use crate::protocols::ip::*;
use crate::*;
use serde::Serialize;

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(IANA_LAYERS, Proto = 6))]
pub struct Tcp {
    #[nproto(fill = fill_tcp_sport)]
    pub sport: Value<u16>,
    #[nproto(fill = fill_tcp_dport)]
    pub dport: Value<u16>,
    #[nproto(default = 0)]
    pub seq: Value<u32>,
    #[nproto(default = 0)]
    pub ack: Value<u32>,
    // u4 really, encoded with "reserved"
    #[nproto(default = 5, encode = Skip, decode = Skip)]
    pub dataofs: Value<u8>,
    #[nproto(default = 0, encode = encode_tcp_reserved, decode = decode_tcp_reserved)]
    pub reserved: Value<u8>,
    #[nproto(default = 2)] // syn
    pub flags: Value<u8>,

    #[nproto(default = 8192)]
    pub window: Value<u16>,
    #[nproto(encode = encode_tcp_chksum, fill = fill_tcp_chksum_auto )]
    pub chksum: Value<u16>,
    #[nproto(default = 0)]
    pub urgptr: Value<u16>,
    // pub options: Vec<TcpOption>,
}

fn fill_tcp_sport(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u16 {
    0xffff
}

fn fill_tcp_dport(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u16 {
    80
}

fn encode_tcp_reserved<E: Encoder>(
    me: &Tcp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let dataofs = me.dataofs.value() & 0xf;
    let reserved = me.reserved.value() & 0xf;
    E::encode_u8((dataofs << 4) | reserved)
}

fn decode_tcp_reserved<D: Decoder>(buf: &[u8], ci: usize, me: &mut Tcp) -> Option<(u8, usize)> {
    use std::convert::TryInto;

    let buf = &buf[ci..];

    let (x, delta) = u8::decode::<D>(buf)?;
    let dataofs: u8 = x >> 4;
    let reserved: u8 = x & 0xf;
    me.dataofs = Value::Set(dataofs);
    Some((reserved, delta))
}

fn fill_tcp_chksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_tcp_chksum<E: Encoder>(
    me: &Tcp,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    if !me.chksum.is_auto() {
        return me.chksum.value().encode::<E>();
    }

    let encoded_tcp_header = if let Some(tcp) = stack.item_at(TCP!(), my_index) {
        tcp.clone().chksum(0).encode(stack, my_index, encoded_data)
    } else {
        vec![]
    };
    // println!("TCP HDR {}: {:02x?}", encoded_tcp_header.len(), &encoded_tcp_header);

    let mut sum: u32 = 0;
    let mut data_len: usize = 0;
    // fixme
    let mut tcp_hdr_len: u16 = 20;

    for i in my_index + 1..encoded_data.len() {
        data_len += encoded_data[i].len();
    }

    let total_len: u16 = u16::try_from(data_len).unwrap() + tcp_hdr_len;

    if my_index > 0 {
        if let Some(ip) = stack.item_at(IP!(), my_index - 1) {
            let mut ph: Vec<u8> = vec![];
            /*
            ph.extend_from_slice(&ip.src.value().encode::<E>());
            ph.extend_from_slice(&ip.dst.value().encode::<E>());
            ph.extend_from_slice(&((ip.proto.value() as u16).encode::<E>()));
            ph.extend_from_slice(&total_len.encode::<E>());
            eprintln!("Pseudoheader: {:02x?}", &ph);
            let sum = get_inet_sum(&ph);
            */
            let sum = get_inet_sum(&ip.src.value().encode::<E>());
            let sum = update_inet_sum(sum, &ip.dst.value().encode::<E>());
            let sum = update_inet_sum(sum, &((ip.proto.value() as u16).encode::<E>()));
            let sum = update_inet_sum(sum, &total_len.encode::<E>());

            let mut sum = update_inet_sum(sum, &encoded_tcp_header);
            // eprintln!("CHECKSUM B4 data: {:04x}", sum);
            for i in my_index + 1..encoded_data.len() {
                sum = update_inet_sum(sum, &encoded_data[i]);
            }
            let sum = fold_u32(sum);
            // eprintln!("CHECKSUM: {:04x}", sum);
            sum.encode::<E>()
        } else {
            vec![0xdd, 0xdd]
        }
    } else {
        vec![0xee, 0xea]
    }
}

pub enum TcpOption {}
