use crate::protocols::ip::*;
use crate::protocols::ipv6::*;
use crate::*;
use serde::Serialize;

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(IANA_LAYERS, Proto = 17))]
pub struct Udp {
    #[nproto(fill = fill_udp_sport)]
    #[nproto(next: UDP_SRC_PORT_APPS => SrcPort )]
    pub sport: Value<u16>,
    #[nproto(next: UDP_DST_PORT_APPS => DstPort )]
    pub dport: Value<u16>,
    #[nproto(encode = encode_udp_len, fill = fill_udp_len_auto )]
    pub len: Value<u16>,
    // #[nproto(auto = encode_csum)]
    #[nproto(encode = encode_udp_chksum, fill = fill_udp_chksum_auto )]
    pub chksum: Value<u16>,
}

fn fill_udp_len_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_udp_len<E: Encoder>(
    me: &Udp,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    let mut data_len: usize = 0;

    for i in my_index + 1..encoded_data.len() {
        data_len += encoded_data[i].len();
    }
    data_len += 8; // UDP HDR
    let len: u16 = data_len.try_into().unwrap();

    len.encode::<E>()
}

fn fill_udp_chksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_udp_chksum<E: Encoder>(
    me: &Udp,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    if !me.chksum.is_auto() {
        return me.chksum.value().encode::<E>();
    }

    let encoded_udp_header = if let Some(udp) = stack.item_at(UDP!(), my_index) {
        udp.clone().chksum(0).lencode(stack, my_index, encoded_data)
    } else {
        vec![]
    };

    let mut sum: u32 = 0;
    let mut data_len: usize = 0;
    // fixme
    let mut udp_hdr_len: u16 = 8;

    for i in my_index + 1..encoded_data.len() {
        data_len += encoded_data[i].len();
    }

    let total_len: u16 = u16::try_from(data_len).unwrap() + udp_hdr_len;

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

            let mut sum = update_inet_sum(sum, &encoded_udp_header);
            // eprintln!("CHECKSUM B4 data: {:04x}", sum);
            let mut carry: Option<u8> = None;
            // Have to do from outermost to innermost payload, to account for a carry byte
            for i in (my_index + 1..encoded_data.len()).rev() {
                (sum, carry) = update_inet_sum_with_carry(sum, &encoded_data[i], carry);
            }
            (sum, carry) = update_inet_sum_with_carry(sum, &vec![], carry);
            assert!(carry.is_none());
            let sum = fold_u32(sum);
            // eprintln!("CHECKSUM: {:04x}", sum);
            sum.encode::<E>()
        } else if let Some(ip6) = stack.item_at(IPV6!(), my_index - 1) {
            let sum = get_inet_sum(&ip6.src.value().encode::<E>());
            let sum = update_inet_sum(sum, &ip6.dst.value().encode::<E>());
            let sum = update_inet_sum(sum, &((ip6.next_header.value() as u16).encode::<E>()));
            let sum = update_inet_sum(sum, &total_len.encode::<E>());

            let mut sum = update_inet_sum(sum, &encoded_udp_header);
            let mut carry: Option<u8> = None;
            // Have to do from outermost to innermost payload, to account for a carry byte
            for i in (my_index + 1..encoded_data.len()).rev() {
                (sum, carry) = update_inet_sum_with_carry(sum, &encoded_data[i], carry);
            }
            (sum, carry) = update_inet_sum_with_carry(sum, &vec![], carry);
            assert!(carry.is_none());
            let sum = fold_u32(sum);
            sum.encode::<E>()
        } else {
            vec![0xdd, 0xdd]
        }
    } else {
        vec![0xee, 0xea]
    }
}

fn fill_udp_sport(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> u16 {
    0xffff
}
