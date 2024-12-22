use crate::*;
use serde::{Deserialize, Serialize};
/*
 * VXLAN encapsulation
 */

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 4789))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 4789))]
pub struct Vxlan {
    #[nproto(default = 0x08)] // just set the "I" bit
    pub flags: Value<u8>,
    pub reserved_u8: Value<u8>,
    pub reserved_u16: Value<u16>,
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "reserved_u8_2" encoder/decoder
    pub vni: Value<u32>, // u24
    #[nproto(encode = encode_vni_and_ru82, decode = decode_vni_and_ru82)]
    pub reserved_u8_2: Value<u8>,
}

fn encode_vni_and_ru82<E: Encoder>(
    me: &Vxlan,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    use std::convert::TryInto;

    let mut out: Vec<u8> = vec![];
    out.push(((me.vni.value() >> 16) & 0xff).try_into().unwrap());
    out.push(((me.vni.value() >> 8) & 0xff).try_into().unwrap());
    out.push((me.vni.value() & 0xff).try_into().unwrap());
    out.push(me.reserved_u8_2.value());
    out
}

/*
 * decode the vni and "reserved_u8_2".
 * It returns "u8" because it is formally decoding the "reserved_u8_2" field which is u8.
 */
fn decode_vni_and_ru82<D: Decoder>(buf: &[u8], ci: usize, me: &mut Vxlan) -> Option<(u8, usize)> {
    use crate::Value::Set;

    let buf = &buf[ci..];

    let mut ci = 0;
    let (the_u8, _) = D::decode_vec(buf, 4)?;
    me.vni = Set(((the_u8[0] as u32) << 16) | ((the_u8[1] as u32) << 8) | (the_u8[2] as u32));
    Some((the_u8[3], 4))
}
