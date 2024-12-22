use crate::*;
use serde::{Deserialize, Serialize};

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x8100))]
pub struct dot1Q {
    #[nproto(default = 0, encode = Skip, decode = Skip)]
    pub prio: Value<u8>,
    #[nproto(default = 0, encode = Skip, decode = Skip)]
    pub id: Value<u8>,
    #[nproto(default = 1, encode = encode_dot1q_tci, decode = decode_dot1q_tci, fill = fill_tci_auto)]
    pub vlan: Value<u16>,
    #[nproto(next: ETHERTYPE_LAYERS => Ethertype)]
    pub etype: Value<u16>,
}

fn encode_dot1q_tci<E: Encoder>(
    me: &dot1Q,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let vlan: u16 = me.vlan.value() & 0xfff;
    let dei: u16 = ((me.id.value() as u16) & 1) << 12;
    let pcp: u16 = ((me.prio.value() as u16) & 7) << 13;
    E::encode_u16(vlan | dei | pcp)
}

fn decode_dot1q_tci<D: Decoder>(buf: &[u8], ci: usize, me: &mut dot1Q) -> Option<(u16, usize)> {
    use std::convert::TryInto;

    let buf = &buf[ci..];

    let (tci, delta) = u16::decode::<D>(buf)?;
    let vlan: u16 = tci & 0xfff;
    let dei: u8 = ((tci >> 12) & 1).try_into().unwrap();
    let pcp: u8 = ((tci >> 13) & 7).try_into().unwrap();
    me.id = Value::Set(dei);
    me.prio = Value::Set(pcp);
    Some((vlan, delta))
}

fn fill_tci_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u8> {
    Value::Auto
}
