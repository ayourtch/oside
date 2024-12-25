use crate::typ::string::FixedSizeString;
use crate::*;
use serde::{Deserialize, Serialize};
use typenum::U8; // FixedSizeString;

// OSPF Packet Types - https://www.ietf.org/rfc/rfc2328.txt
#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OspfType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl Default for OspfType {
    fn default() -> Self {
        OspfType::Hello
    }
}

// OSPF Common Header
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(IANA_LAYERS, Proto = 89))] // OSPF Protocol number
pub struct OspfHeader {
    #[nproto(default = 2)] // Version 2 for OSPFv2
    pub version: Value<u8>,
    #[nproto(next: OSPF_PACKET_TYPES => PacketType, next_len=(get_next_len(__packet_length)))]
    pub packet_type: Value<u8>, // OspfType
    pub packet_length: Value<u16>,
    pub router_id: Value<Ipv4Address>,
    pub area_id: Value<Ipv4Address>,
    pub checksum: Value<u16>,
    pub auth_type: Value<u16>,
    pub auth_data: Value<FixedSizeString<U8>>,
}

fn get_next_len(len: u16) -> usize {
    len as usize
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 1))]
pub struct OspfHello {
    pub network_mask: Value<Ipv4Address>,
    pub hello_interval: Value<u16>,
    pub options: Value<u8>,
    pub router_priority: Value<u8>,
    pub router_dead_interval: Value<u32>,
    pub designated_router: Value<Ipv4Address>,
    pub backup_designated_router: Value<Ipv4Address>,
    #[nproto(decode = decode_ospf_neighbors, encode = encode_ospf_neighbors)]
    pub neighbors: Vec<Ipv4Address>,
}

fn decode_ospf_neighbors<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut OspfHello,
) -> Option<(Vec<Ipv4Address>, usize)> {
    let buf = &buf[ci..];

    let mut addresses = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        if let Some((ip, len)) = Ipv4Address::decode::<D>(&buf[pos..]) {
            addresses.push(ip);
            pos += len;
        } else {
            break;
        }
    }
    Some((addresses, pos))
}

fn encode_ospf_neighbors<E: Encoder>(
    my_layer: &OspfHello,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    for addr in &my_layer.neighbors {
        out.extend(addr.encode::<E>());
    }
    out
}

// OSPF Database Description Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 2))]
pub struct OspfDatabaseDescription {
    pub interface_mtu: Value<u16>,
    pub options: Value<u8>,
    pub flags: Value<u8>, // Init, More, Master/Slave bits
    pub sequence_number: Value<u32>,
    pub lsa_headers: Vec<LsaHeader>,
}

// LSA Header structure used in multiple packet types
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LsaHeader {
    pub age: u16,
    pub options: u8,
    pub lsa_type: u8,
    pub link_state_id: Ipv4Address,
    pub advertising_router: Ipv4Address,
    pub sequence_number: u32,
    pub checksum: u16,
    pub length: u16,
}
impl AutoEncodeAsSequence for Vec<LsaHeader> {}
impl AutoDecodeAsSequence for Vec<LsaHeader> {}

// OSPF Link State Request Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 3))]
pub struct OspfLinkStateRequest {
    pub requests: Vec<LsaRequest>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LsaRequest {
    pub lsa_type: u32,
    pub link_state_id: Ipv4Address,
    pub advertising_router: Ipv4Address,
}
impl AutoEncodeAsSequence for Vec<LsaRequest> {}
impl AutoDecodeAsSequence for Vec<LsaRequest> {}

// OSPF Link State Update Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 4))]
pub struct OspfLinkStateUpdate {
    pub number_of_lsas: Value<u32>,
    pub lsas: Vec<LinkStateAdvertisement>,
}

// Different types of LSAs
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LinkStateAdvertisement {
    RouterLsa(RouterLsa),
    NetworkLsa(NetworkLsa),
    SummaryLsa(SummaryLsa),
    AsExternalLsa(AsExternalLsa),
}

impl AutoEncodeAsSequence for Vec<LinkStateAdvertisement> {}
impl AutoDecodeAsSequence for Vec<LinkStateAdvertisement> {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouterLsa {
    pub header: LsaHeader,
    pub flags: u8,
    pub links: Vec<RouterLink>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RouterLink {
    pub link_id: Ipv4Address,
    pub link_data: Ipv4Address,
    pub link_type: u8,
    pub metrics: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkLsa {
    pub header: LsaHeader,
    pub network_mask: Ipv4Address,
    pub attached_routers: Vec<Ipv4Address>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SummaryLsa {
    pub header: LsaHeader,
    pub network_mask: Ipv4Address,
    pub metric: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AsExternalLsa {
    pub header: LsaHeader,
    pub network_mask: Ipv4Address,
    pub external_metric: u32,
    pub forwarding_address: Ipv4Address,
    pub external_route_tag: u32,
}

// Implementation of Encode/Decode for RouterLink
impl Encode for RouterLink {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.link_id.encode::<E>());
        out.extend(self.link_data.encode::<E>());
        out.push(self.link_type);
        out.push(self.metrics);
        // Pad to ensure 32-bit alignment
        out.extend_from_slice(&[0, 0]);
        out
    }
}

impl Decode for RouterLink {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (link_id, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
        offset += len;

        let (link_data, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
        offset += len;

        if offset + 4 > buf.len() {
            return None;
        }

        let link_type = buf[offset];
        let metrics = buf[offset + 1];
        // Skip padding
        offset += 4;

        Some((
            RouterLink {
                link_id,
                link_data,
                link_type,
                metrics,
            },
            offset,
        ))
    }
}

// Implementation of Encode/Decode for LinkStateAdvertisement
impl Encode for LinkStateAdvertisement {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            LinkStateAdvertisement::RouterLsa(lsa) => {
                let mut out = Vec::new();
                out.extend(lsa.header.encode::<E>());
                out.extend_from_slice(&[lsa.flags, 0]); // Include padding
                let len: u16 = lsa.links.len() as u16;
                out.extend(len.encode::<E>());
                for link in &lsa.links {
                    out.extend(link.encode::<E>());
                }
                out
            }
            LinkStateAdvertisement::NetworkLsa(lsa) => {
                let mut out = Vec::new();
                out.extend(lsa.header.encode::<E>());
                out.extend(lsa.network_mask.encode::<E>());
                for router in &lsa.attached_routers {
                    out.extend(router.encode::<E>());
                }
                out
            }
            LinkStateAdvertisement::SummaryLsa(lsa) => {
                let mut out = Vec::new();
                out.extend(lsa.header.encode::<E>());
                out.extend(lsa.network_mask.encode::<E>());
                out.extend(lsa.metric.encode::<E>());
                out
            }
            LinkStateAdvertisement::AsExternalLsa(lsa) => {
                let mut out = Vec::new();
                out.extend(lsa.header.encode::<E>());
                out.extend(lsa.network_mask.encode::<E>());
                out.extend(lsa.external_metric.encode::<E>());
                out.extend(lsa.forwarding_address.encode::<E>());
                out.extend(lsa.external_route_tag.encode::<E>());
                out
            }
        }
    }
}

impl Decode for LinkStateAdvertisement {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let (header, mut offset) = LsaHeader::decode::<D>(buf)?;

        match header.lsa_type {
            1 => {
                // Router LSA
                if offset + 4 > buf.len() {
                    return None;
                }
                let flags = buf[offset];
                offset += 4; // Skip padding

                let mut links = Vec::new();
                let remaining_len = (header.length as usize) - offset;
                let mut pos = offset;
                while pos < offset + remaining_len {
                    let (link, len) = RouterLink::decode::<D>(&buf[pos..])?;
                    links.push(link);
                    pos += len;
                }

                Some((
                    LinkStateAdvertisement::RouterLsa(RouterLsa {
                        header,
                        flags,
                        links,
                    }),
                    pos,
                ))
            }
            2 => {
                // Network LSA
                let (network_mask, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
                offset += len;

                let mut attached_routers = Vec::new();
                let remaining_len = (header.length as usize) - offset;
                let mut pos = offset;
                while pos < offset + remaining_len {
                    let (router, len) = Ipv4Address::decode::<D>(&buf[pos..])?;
                    attached_routers.push(router);
                    pos += len;
                }

                Some((
                    LinkStateAdvertisement::NetworkLsa(NetworkLsa {
                        header,
                        network_mask,
                        attached_routers,
                    }),
                    pos,
                ))
            }
            3 | 4 => {
                // Summary LSA
                let (network_mask, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
                offset += len;

                let (metric, len) = u32::decode::<D>(&buf[offset..])?;
                offset += len;

                Some((
                    LinkStateAdvertisement::SummaryLsa(SummaryLsa {
                        header,
                        network_mask,
                        metric,
                    }),
                    offset,
                ))
            }
            5 => {
                // AS External LSA
                let (network_mask, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
                offset += len;

                let (external_metric, len) = u32::decode::<D>(&buf[offset..])?;
                offset += len;

                let (forwarding_address, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
                offset += len;

                let (external_route_tag, len) = u32::decode::<D>(&buf[offset..])?;
                offset += len;

                Some((
                    LinkStateAdvertisement::AsExternalLsa(AsExternalLsa {
                        header,
                        network_mask,
                        external_metric,
                        forwarding_address,
                        external_route_tag,
                    }),
                    offset,
                ))
            }
            _ => None,
        }
    }
}

// OSPF Link State Acknowledgment Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 5))]
pub struct OspfLinkStateAck {
    pub lsa_headers: Vec<LsaHeader>,
}
