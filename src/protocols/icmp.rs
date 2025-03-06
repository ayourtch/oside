use crate::*;
use serde::{Deserialize, Serialize};

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(register(IANA_LAYERS, Proto = 1))]
pub struct Icmp {
    #[nproto(next: ICMP_TYPES => Type)]
    pub typ: Value<u8>,
    pub code: Value<u8>,
    #[nproto(encode = encode_icmp_chksum, fill = fill_icmp_chksum_auto)]
    pub chksum: Value<u16>,
}

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(register(ICMP_TYPES, Type = 8))]
pub struct echo {
    pub identifier: Value<u16>,
    pub sequence: Value<u16>,
}

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(register(ICMP_TYPES, Type = 0))]
pub struct echoReply {
    pub identifier: Value<u16>,
    pub sequence: Value<u16>,
}

fn fill_icmp_chksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_icmp_chksum<E: Encoder>(
    me: &Icmp,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;
    if !me.chksum.is_auto() {
        return me.chksum.value().encode::<E>();
    }

    let encoded_icmp_header = if let Some(icmp) = stack.item_at(ICMP!(), my_index) {
        icmp.clone()
            .chksum(0)
            .lencode(stack, my_index, encoded_data)
    } else {
        vec![]
    };
    // eprintln!("Encoded ICMP header: {:02x?}", &encoded_icmp_header);
    let mut sum = get_inet_sum(&encoded_icmp_header);
    let mut carry: Option<u8> = None;
    // Have to do from outermost to innermost payload, to account for a carry byte
    for i in (my_index + 1..encoded_data.len()).rev() {
        (sum, carry) = update_inet_sum_with_carry(sum, &encoded_data[i], carry);
    }
    (sum, carry) = update_inet_sum_with_carry(sum, &vec![], carry);
    assert!(carry.is_none());
    let sum = fold_u32(sum);
    sum.encode::<E>()
}
