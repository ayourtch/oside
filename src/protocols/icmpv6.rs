use crate::protocols::all::Ipv6;
use crate::*;
use serde::{Deserialize, Serialize};
use std::num::ParseIntError;

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(IANA_LAYERS, Proto = 58))] // ICMPv6 Protocol number
pub struct Icmpv6 {
    #[nproto(next: ICMPV6_TYPES => Type)]
    pub type_: Value<u8>,
    pub code: Value<u8>,
    #[nproto(encode = encode_icmpv6_checksum, fill = fill_icmpv6_checksum_auto)]
    pub checksum: Value<u16>,
}

// Message Types
#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Icmpv6Type {
    // Error Messages
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,

    // Informational Messages
    EchoRequest = 128,
    EchoReply = 129,

    // NDP Messages
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    Redirect = 137,
}

impl Default for Icmpv6Type {
    fn default() -> Self {
        Icmpv6Type::EchoRequest
    }
}

// Message-specific structures
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 1))]
pub struct Icmpv6DestUnreach {
    pub unused: Value<u32>,
    #[nproto(encode = encode_invoking_packet, decode = decode_invoking_packet)]
    pub invoking_packet: Vec<u8>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 2))]
pub struct Icmpv6PacketTooBig {
    pub mtu: Value<u32>,
    #[nproto(encode = encode_invoking_packet, decode = decode_invoking_packet)]
    pub invoking_packet: Vec<u8>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 3))]
pub struct Icmpv6TimeExceeded {
    pub unused: Value<u32>,
    #[nproto(encode = encode_invoking_packet, decode = decode_invoking_packet)]
    pub invoking_packet: Vec<u8>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 4))]
pub struct Icmpv6ParameterProblem {
    pub pointer: Value<u32>,
    #[nproto(encode = encode_invoking_packet, decode = decode_invoking_packet)]
    pub invoking_packet: Vec<u8>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 128))]
pub struct Icmpv6EchoRequest {
    pub identifier: Value<u16>,
    pub sequence: Value<u16>,
    pub data: Vec<u8>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 129))]
pub struct Icmpv6EchoReply {
    pub identifier: Value<u16>,
    pub sequence: Value<u16>,
    pub data: Vec<u8>,
}

// NDP Messages
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 133))]
pub struct Icmpv6RouterSolicitation {
    pub reserved: Value<u32>,
    #[nproto(encode = encode_ndp_options, decode = decode_ndp_options)]
    pub options: Vec<NdpOption>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 134))]
pub struct Icmpv6RouterAdvertisement {
    pub cur_hop_limit: Value<u8>,
    pub flags: Value<u8>,
    pub router_lifetime: Value<u16>,
    pub reachable_time: Value<u32>,
    pub retrans_timer: Value<u32>,
    #[nproto(encode = encode_ndp_options, decode = decode_ndp_options)]
    pub options: Vec<NdpOption>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 135))]
pub struct Icmpv6NeighborSolicitation {
    pub reserved: Value<u32>,
    pub target_address: Value<Ipv6Address>,
    #[nproto(encode = encode_ndp_options, decode = decode_ndp_options)]
    pub options: Vec<NdpOption>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 136))]
pub struct Icmpv6NeighborAdvertisement {
    pub flags: Value<u32>, // Router, Solicited, Override flags
    pub target_address: Value<Ipv6Address>,
    #[nproto(encode = encode_ndp_options, decode = decode_ndp_options)]
    pub options: Vec<NdpOption>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(ICMPV6_TYPES, Type = 137))]
pub struct Icmpv6Redirect {
    pub reserved: Value<u32>,
    pub target_address: Value<Ipv6Address>,
    pub destination_address: Value<Ipv6Address>,
    #[nproto(encode = encode_ndp_options, decode = decode_ndp_options)]
    pub options: Vec<NdpOption>,
}

// NDP Option Types
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum NdpOption {
    SourceLinkLayerAddress(MacAddr),
    TargetLinkLayerAddress(MacAddr),
    PrefixInformation {
        prefix_length: u8,
        flags: u8,
        valid_lifetime: u32,
        preferred_lifetime: u32,
        prefix: Ipv6Address,
    },
    MTU(u32),
}

impl Encode for NdpOption {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            NdpOption::SourceLinkLayerAddress(addr) => {
                out.push(1); // Type
                out.push(1); // Length (in units of 8 octets)
                out.extend(addr.encode::<E>());
            }
            NdpOption::TargetLinkLayerAddress(addr) => {
                out.push(2); // Type
                out.push(1); // Length (in units of 8 octets)
                out.extend(addr.encode::<E>());
            }
            NdpOption::PrefixInformation {
                prefix_length,
                flags,
                valid_lifetime,
                preferred_lifetime,
                prefix,
            } => {
                out.push(3); // Type
                out.push(4); // Length (in units of 8 octets)
                out.push(*prefix_length);
                out.push(*flags);
                out.extend(valid_lifetime.encode::<E>());
                out.extend(preferred_lifetime.encode::<E>());
                out.extend(vec![0; 4]); // Reserved
                out.extend(prefix.encode::<E>());
            }
            NdpOption::MTU(mtu) => {
                out.push(5); // Type
                out.push(1); // Length (in units of 8 octets)
                out.extend(vec![0; 2]); // Reserved
                out.extend(mtu.encode::<E>());
            }
        }
        out
    }
}

impl Distribution<NdpOption> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> NdpOption {
        // Default to a random source link layer address option
        NdpOption::SourceLinkLayerAddress(rng.gen())
    }
}

// Helper functions for encoding/decoding
fn encode_invoking_packet<E: Encoder>(
    me: &dyn Layer,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    // Return the invoking packet data
    match me {
        x if x.type_id() == TypeId::of::<Icmpv6DestUnreach>() => x
            .downcast_ref::<Icmpv6DestUnreach>()
            .unwrap()
            .invoking_packet
            .clone(),
        x if x.type_id() == TypeId::of::<Icmpv6PacketTooBig>() => x
            .downcast_ref::<Icmpv6PacketTooBig>()
            .unwrap()
            .invoking_packet
            .clone(),
        x if x.type_id() == TypeId::of::<Icmpv6TimeExceeded>() => x
            .downcast_ref::<Icmpv6TimeExceeded>()
            .unwrap()
            .invoking_packet
            .clone(),
        x if x.type_id() == TypeId::of::<Icmpv6ParameterProblem>() => x
            .downcast_ref::<Icmpv6ParameterProblem>()
            .unwrap()
            .invoking_packet
            .clone(),
        _ => vec![],
    }
}

fn decode_invoking_packet<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut dyn Layer,
) -> Option<(Vec<u8>, usize)> {
    let remaining = &buf[ci..];
    Some((remaining.to_vec(), remaining.len()))
}

fn encode_ndp_options<E: Encoder>(
    me: &dyn Layer,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();
    let options = match me {
        x if x.type_id() == TypeId::of::<Icmpv6RouterSolicitation>() => {
            &x.downcast_ref::<Icmpv6RouterSolicitation>()
                .unwrap()
                .options
        }
        x if x.type_id() == TypeId::of::<Icmpv6RouterAdvertisement>() => {
            &x.downcast_ref::<Icmpv6RouterAdvertisement>()
                .unwrap()
                .options
        }
        x if x.type_id() == TypeId::of::<Icmpv6NeighborSolicitation>() => {
            &x.downcast_ref::<Icmpv6NeighborSolicitation>()
                .unwrap()
                .options
        }
        x if x.type_id() == TypeId::of::<Icmpv6NeighborAdvertisement>() => {
            &x.downcast_ref::<Icmpv6NeighborAdvertisement>()
                .unwrap()
                .options
        }
        x if x.type_id() == TypeId::of::<Icmpv6Redirect>() => {
            &x.downcast_ref::<Icmpv6Redirect>().unwrap().options
        }
        _ => return vec![],
    };

    for option in options {
        out.extend(option.encode::<E>());
    }
    out
}

fn decode_ndp_options<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut dyn Layer,
) -> Option<(Vec<NdpOption>, usize)> {
    let mut options = Vec::new();
    let mut offset = ci;

    while offset + 2 <= buf.len() {
        let option_type = buf[offset];
        let option_length = buf[offset + 1] as usize * 8; // Length is in units of 8 octets

        if offset + option_length > buf.len() {
            break;
        }

        match option_type {
            1 => {
                // Source Link-layer Address
                if let Some((mac, _)) = MacAddr::decode::<D>(&buf[offset + 2..]) {
                    options.push(NdpOption::SourceLinkLayerAddress(mac));
                }
            }
            2 => {
                // Target Link-layer Address
                if let Some((mac, _)) = MacAddr::decode::<D>(&buf[offset + 2..]) {
                    options.push(NdpOption::TargetLinkLayerAddress(mac));
                }
            }
            3 => {
                // Prefix Information
                if offset + 32 <= buf.len() {
                    let prefix_length = buf[offset + 2];
                    let flags = buf[offset + 3];
                    if let Some((valid_lifetime, _)) = u32::decode::<D>(&buf[offset + 4..]) {
                        if let Some((preferred_lifetime, _)) = u32::decode::<D>(&buf[offset + 8..])
                        {
                            if let Some((prefix, _)) = Ipv6Address::decode::<D>(&buf[offset + 16..])
                            {
                                options.push(NdpOption::PrefixInformation {
                                    prefix_length,
                                    flags,
                                    valid_lifetime,
                                    preferred_lifetime,
                                    prefix,
                                });
                            }
                        }
                    }
                }
            }
            5 => {
                // MTU
                if let Some((mtu, _)) = u32::decode::<D>(&buf[offset + 4..]) {
                    options.push(NdpOption::MTU(mtu));
                }
            }
            _ => {} // Skip unknown options
        }
        offset += option_length;
    }

    Some((options, offset - ci))
}

// Checksum calculation for ICMPv6
fn fill_icmpv6_checksum_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn encode_icmpv6_checksum<E: Encoder>(
    me: &Icmpv6,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    if !me.checksum.is_auto() {
        return me.checksum.value().encode::<E>();
    }

    let encoded_icmpv6_header = me
        .clone()
        .checksum(0)
        .lencode(stack, my_index, encoded_data);

    // Calculate pseudoheader checksum
    let mut sum = 0u32;

    if my_index > 0 {
        if let Some(ipv6) = stack.item_at(IPV6!(), my_index - 1) {
            // Add source and destination addresses
            sum = get_inet_sum(&ipv6.src.value().encode::<E>());
            sum = update_inet_sum(sum, &ipv6.dst.value().encode::<E>());

            // Add upper-layer packet length
            let mut icmp_len = encoded_icmpv6_header.len();
            for i in my_index + 1..encoded_data.len() {
                icmp_len += encoded_data[i].len();
            }
            sum = update_inet_sum(sum, &(icmp_len as u32).encode::<E>());

            // Add next header (58 for ICMPv6)
            sum = update_inet_sum(sum, &[0, 0, 0, 58]);
        }
    }

    // Add ICMPv6 header and data
    sum = update_inet_sum(sum, &encoded_icmpv6_header);
    for i in my_index + 1..encoded_data.len() {
        sum = update_inet_sum(sum, &encoded_data[i]);
    }

    // Fold and complement
    let checksum = fold_u32(sum);
    checksum.encode::<E>()
}

// Implementation of FromStr for ICMPv6Type
impl FromStr for Icmpv6Type {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "echo_request" => Ok(Icmpv6Type::EchoRequest),
            "echo_reply" => Ok(Icmpv6Type::EchoReply),
            "dest_unreach" => Ok(Icmpv6Type::DestinationUnreachable),
            "packet_too_big" => Ok(Icmpv6Type::PacketTooBig),
            "time_exceeded" => Ok(Icmpv6Type::TimeExceeded),
            "parameter_problem" => Ok(Icmpv6Type::ParameterProblem),
            "router_solicitation" => Ok(Icmpv6Type::RouterSolicitation),
            "router_advertisement" => Ok(Icmpv6Type::RouterAdvertisement),
            "neighbor_solicitation" => Ok(Icmpv6Type::NeighborSolicitation),
            "neighbor_advertisement" => Ok(Icmpv6Type::NeighborAdvertisement),
            "redirect" => Ok(Icmpv6Type::Redirect),
            _ => s
                .parse::<u8>()
                .map(|n| Icmpv6Type::from_repr(n).unwrap_or(Icmpv6Type::EchoRequest)),
        }
    }
}

// Distribution implementation for random value generation
impl Distribution<Icmpv6Type> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Icmpv6Type {
        match rng.gen_range(0..11) {
            0 => Icmpv6Type::DestinationUnreachable,
            1 => Icmpv6Type::PacketTooBig,
            2 => Icmpv6Type::TimeExceeded,
            3 => Icmpv6Type::ParameterProblem,
            4 => Icmpv6Type::EchoRequest,
            5 => Icmpv6Type::EchoReply,
            6 => Icmpv6Type::RouterSolicitation,
            7 => Icmpv6Type::RouterAdvertisement,
            8 => Icmpv6Type::NeighborSolicitation,
            9 => Icmpv6Type::NeighborAdvertisement,
            _ => Icmpv6Type::Redirect,
        }
    }
}
