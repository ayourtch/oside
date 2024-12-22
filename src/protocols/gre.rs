use crate::*;
use serde::{Deserialize, Serialize};

/*
 * GRE packets have an interesting story - https://en.wikipedia.org/wiki/Generic_Routing_Encapsulation
 *
 * There are multiple mostly backwards-compatible versions. Here I attempt to have
 * a superset of all valid fields, with the main smarts being inside the (encode|decode)_first_u16
 * function.
 *
 */

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(IANA_LAYERS, Proto = 47))]
pub struct Gre {
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub chksum_present: Value<bool>,
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub routing_present: Value<bool>,
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub key_present: Value<bool>,
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub seqnum_present: Value<bool>,
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub strict_source_route: Value<bool>,
    // 3 bits
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub recursion_control: Value<u8>,
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub acknum_present: Value<bool>,
    // 4 bits remaining after pptp header definition
    #[nproto(encode = Skip, decode = Skip)] // encoded/decoded by "version" field decoder
    pub flags: Value<u8>,
    // 3 bits
    // This encoder/decoder takes care of all of the fields above.
    #[nproto(encode = encode_first_u16_fields, decode = decode_first_u16_fields)]
    pub version: Value<u8>,
    #[nproto(next: ETHERTYPE_LAYERS => Ethertype)]
    pub proto: Value<u16>,
    // taken into account only if chksum_present is true
    #[nproto(skip_encdec_unless(layer.chksum_present.value()))]
    pub chksum: Value<u16>,
    // both chksum and routing_offset places in the packet must be decoded
    // if either of the flags are set
    #[nproto(skip_encdec_unless(layer.routing_present.value() && !layer.chksum_present.value()))]
    pub ignored_chksum: Value<u16>,
    #[nproto(skip_encdec_unless(layer.chksum_present.value() && !layer.routing_present.value()))]
    pub reserved1: Value<u16>,
    // taken into account only if R bit is set - else if only C bit is set use "reserved1"
    #[nproto(skip_encdec_unless(layer.routing_present.value()))]
    pub routing_offset: Value<u16>,
    // taken into account only if key_present is true
    #[nproto(skip_encdec_unless(layer.key_present.value()))]
    pub key: Value<u32>,
    // taken into account only if seqnum_present is true
    #[nproto(skip_encdec_unless(layer.seqnum_present.value()))]
    pub sequence_number: Value<u32>,
    // taken into account only if acknum_present is true
    #[nproto(skip_encdec_unless(layer.acknum_present.value()))]
    pub ack_number: Value<u32>,
    // TBD
    #[nproto(encode = Skip, decode = Skip)]
    pub routing: Vec<u8>,
}

fn encode_first_u16_fields<E: Encoder>(
    me: &Gre,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    let mut the_u16: u16 = u16::from(me.chksum_present.value()) << 15
        | u16::from(me.routing_present.value()) << 14
        | u16::from(me.key_present.value()) << 13
        | u16::from(me.seqnum_present.value()) << 12
        | u16::from(me.strict_source_route.value()) << 11
        | u16::from(me.recursion_control.value() & 7) << 8
        | u16::from(me.acknum_present.value()) << 7
        | u16::from(me.flags.value() & 0x0f) << 3
        | u16::from(me.version.value() & 7);

    E::encode_u16(the_u16)
}

/*
 * decode the first u16 and set the flags.
 * It returns "u8" because it is also decoding the "version" field which is u8.
 */
fn decode_first_u16_fields<D: Decoder>(buf: &[u8], ci: usize, me: &mut Gre) -> Option<(u8, usize)> {
    use crate::Value::Set;

    let buf = &buf[ci..];

    let mut ci = 0;
    let (the_u16, _) = D::decode_u16(buf)?;

    me.chksum_present = Set((1 & (the_u16 >> 15)) == 1);
    me.routing_present = Set((1 & (the_u16 >> 14)) == 1);
    me.key_present = Set((1 & (the_u16 >> 13)) == 1);
    me.seqnum_present = Set((1 & (the_u16 >> 12)) == 1);
    me.strict_source_route = Set((1 & (the_u16 >> 11)) == 1);
    me.recursion_control = Set((7 & (the_u16 >> 8)) as u8);
    me.acknum_present = Set((1 & (the_u16 >> 7)) == 1);
    me.flags = Set((0x0f & (the_u16 >> 3)) as u8);

    let version = (7 & (the_u16)) as u8;
    Some((version, 2))
}
