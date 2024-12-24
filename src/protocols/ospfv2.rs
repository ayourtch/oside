use crate::typ::string::FixedSizeString;
use crate::*;
use serde::{Deserialize, Serialize};
use typenum::U8; // FixedSizeString;

// OSPF Packet Types
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
    #[nproto(next: OSPF_PACKET_TYPES => PacketType)]
    pub packet_type: Value<u8>, // OspfType
    pub packet_length: Value<u16>,
    pub router_id: Value<Ipv4Address>,
    pub area_id: Value<Ipv4Address>,
    pub checksum: Value<u16>,
    pub auth_type: Value<u16>,
    pub auth_data: Value<FixedSizeString<U8>>,
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
    #[nproto(decode = dbd_decode_lsa_headers, encode = dbd_encode_lsa_headers)]
    pub lsa_headers: Vec<LsaHeader>,
}

// LSA Header structure used in multiple packet types
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

// Helper traits and implementations for LSA types
impl Encode for LsaHeader {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.age.encode::<E>());
        out.push(self.options);
        out.push(self.lsa_type);
        out.extend(self.link_state_id.encode::<E>());
        out.extend(self.advertising_router.encode::<E>());
        out.extend(self.sequence_number.encode::<E>());
        out.extend(self.checksum.encode::<E>());
        out.extend(self.length.encode::<E>());
        out
    }
}

impl Decode for LsaHeader {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (age, len) = u16::decode::<D>(buf)?;
        offset += len;

        if offset + 2 > buf.len() {
            return None;
        }
        let options = buf[offset];
        let lsa_type = buf[offset + 1];
        offset += 2;

        let (link_state_id, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
        offset += len;

        let (advertising_router, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
        offset += len;

        let (sequence_number, len) = u32::decode::<D>(&buf[offset..])?;
        offset += len;

        let (checksum, len) = u16::decode::<D>(&buf[offset..])?;
        offset += len;

        let (length, len) = u16::decode::<D>(&buf[offset..])?;
        offset += len;

        Some((
            LsaHeader {
                age,
                options,
                lsa_type,
                link_state_id,
                advertising_router,
                sequence_number,
                checksum,
                length,
            },
            offset,
        ))
    }
}

fn dbd_decode_lsa_headers<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut OspfDatabaseDescription,
) -> Option<(Vec<LsaHeader>, usize)> {
    let buf = &buf[ci..];

    let mut cursor = 0;

    let mut headers = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        if let Some((hdr, len)) = LsaHeader::decode::<D>(&buf[pos..]) {
            headers.push(hdr);
            pos += len;
        } else {
            break;
        }
    }
    Some((headers, pos))
}

fn dbd_encode_lsa_headers<E: Encoder>(
    my_layer: &OspfDatabaseDescription,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    for header in &my_layer.lsa_headers {
        out.extend(header.encode::<E>());
    }
    out
}

// OSPF Link State Request Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 3))]
pub struct OspfLinkStateRequest {
    #[nproto(decode = decode_lsa_requests, encode = encode_lsa_requests)]
    pub requests: Vec<LsaRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LsaRequest {
    pub lsa_type: u32,
    pub link_state_id: Ipv4Address,
    pub advertising_router: Ipv4Address,
}

impl Encode for LsaRequest {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.lsa_type.encode::<E>());
        out.extend(self.link_state_id.encode::<E>());
        out.extend(self.advertising_router.encode::<E>());
        out
    }
}

impl Decode for LsaRequest {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;

        let (lsa_type, len) = u32::decode::<D>(&buf[offset..])?;
        offset += len;

        let (link_state_id, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
        offset += len;

        let (advertising_router, len) = Ipv4Address::decode::<D>(&buf[offset..])?;
        offset += len;

        Some((
            LsaRequest {
                lsa_type,
                link_state_id,
                advertising_router,
            },
            offset,
        ))
    }
}

fn decode_lsa_requests<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut OspfLinkStateRequest,
) -> Option<(Vec<LsaRequest>, usize)> {
    let buf = &buf[ci..];

    let mut cursor = 0;

    let mut requests = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        if let Some((req, len)) = LsaRequest::decode::<D>(&buf[pos..]) {
            requests.push(req);
            pos += len;
        } else {
            break;
        }
    }
    Some((requests, pos))
}

fn encode_lsa_requests<E: Encoder>(
    my_layer: &OspfLinkStateRequest,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    for req in &my_layer.requests {
        out.extend(req.encode::<E>());
    }
    out
}
// OSPF Link State Update Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 4))]
pub struct OspfLinkStateUpdate {
    pub number_of_lsas: Value<u32>,
    #[nproto(decode = decode_lsas, encode = encode_lsas)]
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
                out.extend_from_slice(&[lsa.flags, 0, 0, 0]); // Include padding
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

fn decode_lsas<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut OspfLinkStateUpdate,
) -> Option<(Vec<LinkStateAdvertisement>, usize)> {
    let buf = &buf[ci..];
    let num_lsas = me.number_of_lsas.value() as usize;
    let mut lsas = Vec::with_capacity(num_lsas);
    let mut pos = 0;

    for _ in 0..num_lsas {
        let (lsa, len) = LinkStateAdvertisement::decode::<D>(&buf[pos..])?;
        lsas.push(lsa);
        pos += len;
    }

    Some((lsas, pos))
}

fn encode_lsas<E: Encoder>(
    my_layer: &OspfLinkStateUpdate,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();
    for lsa in &my_layer.lsas {
        out.extend(lsa.encode::<E>());
    }
    out
}

// OSPF Link State Acknowledgment Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(OSPF_PACKET_TYPES, PacketType = 5))]
pub struct OspfLinkStateAck {
    #[nproto(decode = lsack_decode_lsa_headers, encode = lsack_encode_lsa_headers)]
    pub lsa_headers: Vec<LsaHeader>,
}

fn lsack_decode_lsa_headers<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut OspfLinkStateAck,
) -> Option<(Vec<LsaHeader>, usize)> {
    let buf = &buf[ci..];

    let mut cursor = 0;

    let mut headers = Vec::new();
    let mut pos = 0;
    while pos + 4 <= buf.len() {
        if let Some((hdr, len)) = LsaHeader::decode::<D>(&buf[pos..]) {
            headers.push(hdr);
            pos += len;
        } else {
            break;
        }
    }
    Some((headers, pos))
}

fn lsack_encode_lsa_headers<E: Encoder>(
    my_layer: &OspfLinkStateAck,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    for header in &my_layer.lsa_headers {
        out.extend(header.encode::<E>());
    }
    out
}
