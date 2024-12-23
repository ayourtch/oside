use crate::*;
use serde::{Deserialize, Serialize};

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForw = 12,
    RelayRepl = 13,
}

impl Default for Dhcpv6MessageType {
    fn default() -> Self {
        Dhcpv6MessageType::Solicit
    }
}

use crate::*;
use std::str::FromStr;

#[derive(Debug, PartialEq, Eq)]
pub struct ParseDhcpv6MessageTypeError;

impl FromStr for Dhcpv6MessageType {
    type Err = ParseDhcpv6MessageTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "solicit" => Ok(Dhcpv6MessageType::Solicit),
            "advertise" => Ok(Dhcpv6MessageType::Advertise),
            "request" => Ok(Dhcpv6MessageType::Request),
            "confirm" => Ok(Dhcpv6MessageType::Confirm),
            "renew" => Ok(Dhcpv6MessageType::Renew),
            "rebind" => Ok(Dhcpv6MessageType::Rebind),
            "reply" => Ok(Dhcpv6MessageType::Reply),
            "release" => Ok(Dhcpv6MessageType::Release),
            "decline" => Ok(Dhcpv6MessageType::Decline),
            "reconfigure" => Ok(Dhcpv6MessageType::Reconfigure),
            "information-request" | "informationrequest" => {
                Ok(Dhcpv6MessageType::InformationRequest)
            }
            "relay-forw" | "relayforw" => Ok(Dhcpv6MessageType::RelayForw),
            "relay-repl" | "relayrepl" => Ok(Dhcpv6MessageType::RelayRepl),
            // Also support parsing numeric values
            s => {
                if let Ok(num) = s.parse::<u8>() {
                    Dhcpv6MessageType::from_repr(num).ok_or(ParseDhcpv6MessageTypeError)
                } else {
                    Err(ParseDhcpv6MessageTypeError)
                }
            }
        }
    }
}

impl std::fmt::Display for Dhcpv6MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dhcpv6MessageType::Solicit => write!(f, "Solicit"),
            Dhcpv6MessageType::Advertise => write!(f, "Advertise"),
            Dhcpv6MessageType::Request => write!(f, "Request"),
            Dhcpv6MessageType::Confirm => write!(f, "Confirm"),
            Dhcpv6MessageType::Renew => write!(f, "Renew"),
            Dhcpv6MessageType::Rebind => write!(f, "Rebind"),
            Dhcpv6MessageType::Reply => write!(f, "Reply"),
            Dhcpv6MessageType::Release => write!(f, "Release"),
            Dhcpv6MessageType::Decline => write!(f, "Decline"),
            Dhcpv6MessageType::Reconfigure => write!(f, "Reconfigure"),
            Dhcpv6MessageType::InformationRequest => write!(f, "Information-Request"),
            Dhcpv6MessageType::RelayForw => write!(f, "Relay-Forward"),
            Dhcpv6MessageType::RelayRepl => write!(f, "Relay-Reply"),
        }
    }
}

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Dhcpv6OptionCode {
    // RFC 8415 - Basic Options
    ClientId = 1,
    ServerId = 2,
    IaNa = 3,
    IaTa = 4,
    IaAddr = 5,
    OptionRequest = 6,
    Preference = 7,
    ElapsedTime = 8,
    RelayMessage = 9,
    Auth = 11,
    ServerUnicast = 12,
    StatusCode = 13,
    RapidCommit = 14,
    UserClass = 15,
    VendorClass = 16,
    VendorOpts = 17,
    InterfaceId = 18,
    ReconfMessage = 19,
    ReconfAccept = 20,

    // RFC 3319 - SIP Servers
    SipServersDomainList = 21,
    SipServersAddressList = 22,

    // RFC 3646 - DNS Configuration
    DnsServers = 23,
    DomainSearchList = 24,

    // RFC 3633 - Prefix Delegation
    IaPd = 25,
    IaPrefix = 26,
    // IaPrefixDelegation = 25,
    // IapdPrefix = 26,

    // RFC 3898 - Network Information Service (NIS) Configuration
    NisServers = 27,
    NisPlusServers = 28,
    NisDomainName = 29,
    NisPlusDomainName = 30,

    // RFC 4075 - Simple Network Time Protocol (SNTP) Configuration
    SntpServers = 31,

    // RFC 4242 - Information Refresh Time Option
    InformationRefreshTime = 32,

    // RFC 4280 - Broadcast and Multicast Control Servers
    BcmcsControllerDomainList = 33,
    BcmcsControllerIpv6AddressList = 34,

    // RFC 4704 - Client Fully Qualified Domain Name (FQDN)
    ClientFqdn = 39,

    // RFC 5007 - DHCPv6 Leasequery
    ClientDataOption = 45,
    CltTime = 46,
    LqQuery = 44,
    LqClientLink = 48,

    // RFC 5460 - DHCPv6 Bulk Leasequery
    LqRelayData = 47,

    // RFC 5970 - DHCPv6 Options for Network Boot
    BootfileUrl = 59,
    BootfileParam = 60,
    ClientArchType = 61,
    Nii = 62,

    // RFC 6225 - Dynamic Host Configuration Protocol Options for Coordinate-Based Location Configuration Information
    GeoconfCivic = 36,
    GeoLoc = 63,

    // RFC 6334 - Dual-Stack Lite
    AftrName = 64,

    // RFC 6440 - The EAP Authentication Option
    EapMessage = 65,

    // RFC 6422 - Relay-Supplied DHCP Options
    RelaySuppliedOptions = 66,

    // RFC 6603 - Prefix Exclude Option for DHCPv6-based Prefix Delegation
    PrefixExclude = 67,

    // RFC 7083 - Modification to Default Values of SOL_MAX_RT and INF_MAX_RT
    SolMaxRt = 82,
    InfMaxRt = 83,

    // RFC 7291 - DHCP Options for the Port Control Protocol (PCP)
    PcpServer = 86,

    // RFC 7598 - DHCPv6 Options for Configuration of Softwire Address and Port-Mapped Clients
    S46Rule = 89,
    S46Br = 90,
    S46Dmr = 91,
    S46V4V6Bind = 92,
    S46PortParams = 93,
    S46ContMape = 94,
    S46ContMapt = 95,
    S46ContLw = 96,

    // RFC 7600 - IPv4 Residual Deployment via IPv6
    Ipv4Address = 97,

    // RFC 7653 - DHCPv6 Active Leasequery
    Dhcpv6ActiveLeasequery = 100,

    // RFC 8156 - DHCPv6 Failover Protocol
    DhcpFailoverEndpoint = 114,

    // Unknown Option
    Unknown(u16),
}

impl Default for Dhcpv6OptionCode {
    fn default() -> Self {
        Dhcpv6OptionCode::ClientId
    }
}

impl Dhcpv6OptionCode {
    fn discriminant(&self) -> u16 {
        // SAFETY: Because `Self` is marked `repr(u16)`, its layout is a `repr(C)` `union`
        // between `repr(C)` structs, each of which has the `u16` discriminant as its first
        // field, so we can read the discriminant without offsetting the pointer.
        unsafe { *<*const _>::from(self).cast::<u16>() }
    }

    pub fn as_u16(&self) -> u16 {
        match self {
            Dhcpv6OptionCode::Unknown(value) => *value,
            _ => self.discriminant(),
        }
    }
}

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Dhcpv6StatusCode {
    Success = 0,
    UnspecFail = 1,
    NoAddrsAvail = 2,
    NoBinding = 3,
    NotOnLink = 4,
    UseMulticast = 5,
    NoPrefixAvail = 6,
    UnknownQueryType = 7,
    MalformedQuery = 8,
    NotConfigured = 9,
    NotAllowed = 10,
    QueryTerminated = 11,
    DataMissing = 12,
    CatchUpComplete = 13,
    NotSupported = 14,
    TlsConnectionRefused = 15,
    AddressInUse = 16,
    ConfigurationConflict = 17,
    MissingBindingInformation = 18,
    OutdatedBindingInformation = 19,
    ServerShuttingDown = 20,
    DnsUpdateNotSupported = 21,
    ExcessiveTimeSkew = 22,
}

impl Default for Dhcpv6StatusCode {
    fn default() -> Self {
        Dhcpv6StatusCode::Success
    }
}

// DUID Types as per RFC 8415
#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum DuidType {
    LinkLayerTimePlusTime = 1, // DUID-LLT
    VendorAssigned = 2,        // DUID-EN
    LinkLayer = 3,             // DUID-LL
    Uuid = 4,                  // DUID-UUID
}

impl Default for DuidType {
    fn default() -> Self {
        DuidType::LinkLayer
    }
}

// Hardware types for DUID-LLT and DUID-LL
#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum HardwareType {
    Ethernet = 1,
    ExperimentalEthernet = 2,
    AmateurRadioAx25 = 3,
    ProteonTokenRing = 4,
    Chaos = 5,
    Ieee802 = 6,
    Arcnet = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddress = 10,
    LocalTalk = 11,
    LocalNet = 12,
    UltraLink = 13,
    Smds = 14,
    FrameRelay = 15,
    Atm = 16,
    Hdlc = 17,
    FibreChannel = 18,
    Atm2 = 19,
    SerialLine = 20,
    Atm3 = 21,
    Mil_Std_188_220 = 22,
    Metricom = 23,
    Ieee1394 = 24,
    Mapos = 25,
    Twinaxial = 26,
    Eui64 = 27,
    Hiparp = 28,
    Ip_Over_Iso7816_3 = 29,
    ArpSec = 30,
    IpsecTunnel = 31,
    Infiniband = 32,
    Cai = 33,
    Wiegand = 34,
    PureIp = 35,
    Hw_Exp1 = 36,
    Hw_Exp2 = 37,
}

impl Default for HardwareType {
    fn default() -> Self {
        HardwareType::Ethernet
    }
}

// Constants for DHCPv6 operation
pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;

pub const DHCPV6_SOL_MAX_DELAY: u32 = 1;
pub const DHCPV6_SOL_TIMEOUT: u32 = 1;
pub const DHCPV6_SOL_MAX_RT: u32 = 120;
pub const DHCPV6_REQ_TIMEOUT: u32 = 1;
pub const DHCPV6_REQ_MAX_RT: u32 = 30;
pub const DHCPV6_REQ_MAX_RC: u32 = 10;
pub const DHCPV6_CNF_MAX_DELAY: u32 = 1;
pub const DHCPV6_CNF_TIMEOUT: u32 = 1;
pub const DHCPV6_CNF_MAX_RT: u32 = 4;
pub const DHCPV6_CNF_MAX_RD: u32 = 10;
pub const DHCPV6_REN_TIMEOUT: u32 = 10;
pub const DHCPV6_REN_MAX_RT: u32 = 600;
pub const DHCPV6_REB_TIMEOUT: u32 = 10;
pub const DHCPV6_REB_MAX_RT: u32 = 600;
pub const DHCPV6_INF_MAX_DELAY: u32 = 1;
pub const DHCPV6_INF_TIMEOUT: u32 = 1;
pub const DHCPV6_INF_MAX_RT: u32 = 120;
pub const DHCPV6_REL_TIMEOUT: u32 = 1;
pub const DHCPV6_REL_MAX_RC: u32 = 5;
pub const DHCPV6_DEC_TIMEOUT: u32 = 1;
pub const DHCPV6_DEC_MAX_RC: u32 = 5;
pub const DHCPV6_REC_TIMEOUT: u32 = 2;
pub const DHCPV6_REC_MAX_RC: u32 = 8;
pub const DHCPV6_HOP_COUNT_LIMIT: u8 = 32;

use crate::*;
// use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

// DUID (DHCP Unique Identifier) Structures

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DuidLlt {
    pub hardware_type: HardwareType,
    pub time: u32, // Time value in seconds since January 1, 2000
    pub link_layer_addr: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DuidEn {
    pub enterprise_number: u32,
    pub identifier: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DuidLl {
    pub hardware_type: HardwareType,
    pub link_layer_addr: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DuidUuid {
    pub uuid: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Duid {
    Llt(DuidLlt),
    En(DuidEn),
    Ll(DuidLl),
    Uuid(DuidUuid),
}

impl Default for Duid {
    fn default() -> Self {
        Duid::Ll(DuidLl {
            hardware_type: HardwareType::Ethernet,
            link_layer_addr: vec![0; 6],
        })
    }
}

// IA Address Option
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IaAddr {
    pub ipv6_addr: Ipv6Address,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub options: Vec<Dhcpv6Option>,
}

// IA Prefix Option
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IaPrefix {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub prefix_length: u8,
    pub prefix: Ipv6Address,
    pub options: Vec<Dhcpv6Option>,
}

// Status Code Option
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatusCode {
    pub status: Dhcpv6StatusCode,
    pub message: String,
}

// Server ID Option
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VendorInfo {
    pub enterprise_number: u32,
    pub data: Vec<u8>,
}

// Main DHCPv6 Option enum
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Dhcpv6Option {
    ClientId(Duid),
    ServerId(Duid),
    IaNa {
        iaid: u32,
        t1: u32,
        t2: u32,
        options: Vec<Dhcpv6Option>,
    },
    IaTa {
        iaid: u32,
        options: Vec<Dhcpv6Option>,
    },
    IaAddr(IaAddr),
    OptionRequest(Vec<Dhcpv6OptionCode>),
    Preference(u8),
    ElapsedTime(u16),
    RelayMessage(Vec<u8>),
    Auth {
        protocol: u8,
        algorithm: u8,
        rdm: u8,
        replay_detection: Vec<u8>,
        auth_info: Vec<u8>,
    },
    ServerUnicast(Ipv6Address),
    StatusCode(StatusCode),
    RapidCommit,
    UserClass(Vec<Vec<u8>>),
    VendorClass {
        enterprise_number: u32,
        vendor_classes: Vec<Vec<u8>>,
    },
    VendorOpts {
        enterprise_number: u32,
        options: Vec<(u16, Vec<u8>)>,
    },
    InterfaceId(Vec<u8>),
    ReconfMessage(Dhcpv6MessageType),
    ReconfAccept,
    SipServersDomainList(Vec<String>),
    SipServersAddressList(Vec<Ipv6Address>),
    DnsServers(Vec<Ipv6Address>),
    DomainSearchList(Vec<String>),
    IaPd {
        iaid: u32,
        t1: u32,
        t2: u32,
        options: Vec<Dhcpv6Option>,
    },
    IaPrefix(IaPrefix),
    NisServers(Vec<Ipv6Address>),
    NisPlusServers(Vec<Ipv6Address>),
    NisDomainName(String),
    NisPlusDomainName(String),
    SntpServers(Vec<Ipv6Address>),
    InformationRefreshTime(u32),
    BcmcsControllerDomainList(Vec<String>),
    BcmcsControllerIpv6AddressList(Vec<Ipv6Address>),
    ClientFqdn {
        flags: u8,
        fqdn: String,
    },
    ClientDataOption(Vec<u8>),
    CltTime(u32),
    LqQuery {
        query_type: u8,
        link_address: Ipv6Address,
        query_options: Vec<Dhcpv6Option>,
    },
    LqClientLink(Vec<Ipv6Address>),
    LqRelayData {
        peer_address: Ipv6Address,
        relay_data: Vec<u8>,
    },
    BootfileUrl(String),
    BootfileParam(Vec<String>),
    ClientArchType(Vec<u16>),
    Nii {
        undi_type: u8,
        arch_type: u8,
        undi_major: u8,
        undi_minor: u8,
    },
    GeoconfCivic {
        what: u8,
        country_code: String,
        civic_address_elements: Vec<(u8, Vec<u8>)>,
    },
    /*
    GeoLoc {
        latitude_resolution: u8,
        latitude: f64,
        longitude_resolution: u8,
        longitude: f64,
        altitude_type: u8,
        altitude_resolution: u8,
        altitude: f64,
        datum: u8,
    },
    */
    AftrName(String),
    EapMessage(Vec<u8>),
    RelaySuppliedOptions(Vec<Dhcpv6Option>),
    PrefixExclude(Vec<u8>),
    SolMaxRt(u32),
    InfMaxRt(u32),
    PcpServer(Vec<Ipv6Address>),
    S46Rule(Vec<u8>),
    S46Br(Vec<u8>),
    S46Dmr(Vec<u8>),
    S46V4V6Bind(Vec<u8>),
    S46PortParams(Vec<u8>),
    S46ContMape(Vec<u8>),
    S46ContMapt(Vec<u8>),
    S46ContLw(Vec<u8>),
    Ipv4Address(Vec<u8>),
    Dhcpv6ActiveLeasequery(Vec<u8>),
    DhcpFailoverEndpoint(Vec<u8>),
    UnknownOption {
        option_code: u16,
        data: Vec<u8>,
    },
}

impl Default for Dhcpv6Option {
    fn default() -> Self {
        Dhcpv6Option::ClientId(Duid::default())
    }
}

use crate::*;

impl Duid {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Duid::Llt(duid) => {
                out.extend_from_slice(&(DuidType::LinkLayerTimePlusTime as u16).to_be_bytes());
                out.extend_from_slice(&(duid.hardware_type.clone() as u16).to_be_bytes());
                out.extend_from_slice(&duid.time.to_be_bytes());
                out.extend_from_slice(&duid.link_layer_addr);
            }
            Duid::En(duid) => {
                out.extend_from_slice(&(DuidType::VendorAssigned as u16).to_be_bytes());
                out.extend_from_slice(&duid.enterprise_number.to_be_bytes());
                out.extend_from_slice(&duid.identifier);
            }
            Duid::Ll(duid) => {
                out.extend_from_slice(&(DuidType::LinkLayer as u16).to_be_bytes());
                out.extend_from_slice(&(duid.hardware_type.clone() as u16).to_be_bytes());
                out.extend_from_slice(&duid.link_layer_addr);
            }
            Duid::Uuid(duid) => {
                out.extend_from_slice(&(DuidType::Uuid as u16).to_be_bytes());
                out.extend_from_slice(&duid.uuid);
            }
        }
        out
    }

    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let duid_type = u16::from_be_bytes([buf[0], buf[1]]);
        let mut offset = 2;

        match DuidType::from_repr(duid_type)? {
            DuidType::LinkLayerTimePlusTime => {
                if buf.len() < offset + 6 {
                    return None;
                }
                let hardware_type =
                    HardwareType::from_repr(u16::from_be_bytes([buf[offset], buf[offset + 1]]))?;
                offset += 2;
                let time = u32::from_be_bytes([
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ]);
                offset += 4;
                let link_layer_addr = buf[offset..].to_vec();
                Some((
                    Duid::Llt(DuidLlt {
                        hardware_type,
                        time,
                        link_layer_addr,
                    }),
                    buf.len(),
                ))
            }
            DuidType::VendorAssigned => {
                if buf.len() < offset + 4 {
                    return None;
                }
                let enterprise_number = u32::from_be_bytes([
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ]);
                offset += 4;
                let identifier = buf[offset..].to_vec();
                Some((
                    Duid::En(DuidEn {
                        enterprise_number,
                        identifier,
                    }),
                    buf.len(),
                ))
            }
            DuidType::LinkLayer => {
                if buf.len() < offset + 2 {
                    return None;
                }
                let hardware_type =
                    HardwareType::from_repr(u16::from_be_bytes([buf[offset], buf[offset + 1]]))?;
                offset += 2;
                let link_layer_addr = buf[offset..].to_vec();
                Some((
                    Duid::Ll(DuidLl {
                        hardware_type,
                        link_layer_addr,
                    }),
                    buf.len(),
                ))
            }
            DuidType::Uuid => {
                if buf.len() < offset + 16 {
                    return None;
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&buf[offset..offset + 16]);
                Some((Duid::Uuid(DuidUuid { uuid }), offset + 16))
            }
        }
    }
}

impl IaAddr {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(self.ipv6_addr.encode::<E>());
        out.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        out.extend_from_slice(&self.valid_lifetime.to_be_bytes());

        // Encode all sub-options
        for option in &self.options {
            let encoded = option.encode::<E>();
            out.extend_from_slice(&encoded);
        }
        out
    }

    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 24 {
            // IPv6 (16) + preferred lifetime (4) + valid lifetime (4)
            return None;
        }

        let mut offset = 0;

        // Decode IPv6 address
        let (ipv6_addr, addr_len) = Ipv6Address::decode::<D>(&buf[offset..])?;
        offset += addr_len;

        // Decode lifetimes
        let preferred_lifetime = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        let valid_lifetime = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        // Decode any remaining options
        let mut options = Vec::new();
        while offset < buf.len() {
            if let Some((option, option_len)) = Dhcpv6Option::decode::<D>(&buf[offset..]) {
                options.push(option);
                offset += option_len;
            } else {
                break;
            }
        }

        Some((
            IaAddr {
                ipv6_addr,
                preferred_lifetime,
                valid_lifetime,
                options,
            },
            offset,
        ))
    }
}

impl IaPrefix {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.preferred_lifetime.to_be_bytes());
        out.extend_from_slice(&self.valid_lifetime.to_be_bytes());
        out.push(self.prefix_length);
        out.extend(self.prefix.encode::<E>());

        // Encode all sub-options
        for option in &self.options {
            let encoded = option.encode::<E>();
            out.extend_from_slice(&encoded);
        }
        out
    }

    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 25 {
            // preferred lifetime (4) + valid lifetime (4) + prefix length (1) + IPv6 (16)
            return None;
        }

        let mut offset = 0;

        let preferred_lifetime = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        let valid_lifetime = u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        offset += 4;

        let prefix_length = buf[offset];
        offset += 1;

        let (prefix, prefix_len) = Ipv6Address::decode::<D>(&buf[offset..])?;
        offset += prefix_len;

        // Decode any remaining options
        let mut options = Vec::new();
        while offset < buf.len() {
            if let Some((option, option_len)) = Dhcpv6Option::decode::<D>(&buf[offset..]) {
                options.push(option);
                offset += option_len;
            } else {
                break;
            }
        }

        Some((
            IaPrefix {
                preferred_lifetime,
                valid_lifetime,
                prefix_length,
                prefix,
                options,
            },
            offset,
        ))
    }
}

impl StatusCode {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.status.clone() as u16).to_be_bytes());
        out.extend(self.message.as_bytes());
        out
    }

    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 2 {
            return None;
        }

        let status = Dhcpv6StatusCode::from_repr(u16::from_be_bytes([buf[0], buf[1]]))?;
        let message = String::from_utf8_lossy(&buf[2..]).to_string();

        Some((StatusCode { status, message }, buf.len()))
    }
}

use crate::*;

impl Dhcpv6Option {
    // Helper function to encode a vector of IPv6 addresses
    fn encode_ipv6_addresses<E: Encoder>(addrs: &[Ipv6Address]) -> Vec<u8> {
        let mut content = Vec::new();
        for addr in addrs {
            content.extend(addr.encode::<E>());
        }
        content
    }

    // Helper function to encode a vector of domain names
    fn encode_domain_list(domains: &[String]) -> Vec<u8> {
        let mut content = Vec::new();
        for domain in domains {
            // DNS name encoding: length byte followed by name components
            for component in domain.split('.') {
                content.push(component.len() as u8);
                content.extend(component.as_bytes());
            }
            content.push(0); // Terminating zero
        }
        content
    }

    pub fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut content = Vec::new();
        let option_code = match self {
            Dhcpv6Option::ClientId(duid) => {
                content.extend(duid.encode::<E>());
                Dhcpv6OptionCode::ClientId
            }
            Dhcpv6Option::ServerId(duid) => {
                content.extend(duid.encode::<E>());
                Dhcpv6OptionCode::ServerId
            }
            Dhcpv6Option::IaNa {
                iaid,
                t1,
                t2,
                options,
            } => {
                content.extend_from_slice(&iaid.to_be_bytes());
                content.extend_from_slice(&t1.to_be_bytes());
                content.extend_from_slice(&t2.to_be_bytes());
                for option in options {
                    let encoded = option.encode::<E>();
                    content.extend_from_slice(&(option.get_option_code() as u16).to_be_bytes());
                    content.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                    content.extend(encoded);
                }
                Dhcpv6OptionCode::IaNa
            }
            Dhcpv6Option::IaTa { iaid, options } => {
                content.extend_from_slice(&iaid.to_be_bytes());
                for option in options {
                    let encoded = option.encode::<E>();
                    content.extend_from_slice(&(option.get_option_code() as u16).to_be_bytes());
                    content.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                    content.extend(encoded);
                }
                Dhcpv6OptionCode::IaTa
            }
            Dhcpv6Option::IaAddr(addr) => {
                content.extend(addr.encode::<E>());
                Dhcpv6OptionCode::IaAddr
            }
            Dhcpv6Option::OptionRequest(options) => {
                for option in options {
                    content.extend_from_slice(&(option.as_u16()).to_be_bytes());
                }
                Dhcpv6OptionCode::OptionRequest
            }
            Dhcpv6Option::Preference(pref) => {
                content.push(*pref);
                Dhcpv6OptionCode::Preference
            }
            Dhcpv6Option::ElapsedTime(time) => {
                content.extend_from_slice(&time.to_be_bytes());
                Dhcpv6OptionCode::ElapsedTime
            }
            Dhcpv6Option::RelayMessage(msg) => {
                content.extend(msg);
                Dhcpv6OptionCode::RelayMessage
            }
            Dhcpv6Option::Auth {
                protocol,
                algorithm,
                rdm,
                replay_detection,
                auth_info,
            } => {
                content.push(*protocol);
                content.push(*algorithm);
                content.push(*rdm);
                content.extend(replay_detection);
                content.extend(auth_info);
                Dhcpv6OptionCode::Auth
            }
            Dhcpv6Option::ServerUnicast(addr) => {
                content.extend(addr.encode::<E>());
                Dhcpv6OptionCode::ServerUnicast
            }
            Dhcpv6Option::StatusCode(status) => {
                content.extend(status.encode::<E>());
                Dhcpv6OptionCode::StatusCode
            }
            Dhcpv6Option::RapidCommit => Dhcpv6OptionCode::RapidCommit,
            Dhcpv6Option::UserClass(classes) => {
                for class in classes {
                    content.extend_from_slice(&(class.len() as u16).to_be_bytes());
                    content.extend(class);
                }
                Dhcpv6OptionCode::UserClass
            }
            Dhcpv6Option::VendorClass {
                enterprise_number,
                vendor_classes,
            } => {
                content.extend_from_slice(&enterprise_number.to_be_bytes());
                for class in vendor_classes {
                    content.extend_from_slice(&(class.len() as u16).to_be_bytes());
                    content.extend(class);
                }
                Dhcpv6OptionCode::VendorClass
            }
            Dhcpv6Option::VendorOpts {
                enterprise_number,
                options,
            } => {
                content.extend_from_slice(&enterprise_number.to_be_bytes());
                for (code, data) in options {
                    content.extend_from_slice(&code.to_be_bytes());
                    content.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    content.extend(data);
                }
                Dhcpv6OptionCode::VendorOpts
            }
            Dhcpv6Option::InterfaceId(id) => {
                content.extend(id);
                Dhcpv6OptionCode::InterfaceId
            }
            Dhcpv6Option::ReconfMessage(msg_type) => {
                content.push(msg_type.clone() as u8);
                Dhcpv6OptionCode::ReconfMessage
            }
            Dhcpv6Option::ReconfAccept => Dhcpv6OptionCode::ReconfAccept,
            Dhcpv6Option::SipServersDomainList(domains) => {
                content.extend(Self::encode_domain_list(domains));
                Dhcpv6OptionCode::SipServersDomainList
            }
            Dhcpv6Option::SipServersAddressList(addrs) => {
                content.extend(Self::encode_ipv6_addresses::<E>(addrs));
                Dhcpv6OptionCode::SipServersAddressList
            }
            Dhcpv6Option::DnsServers(addrs) => {
                content.extend(Self::encode_ipv6_addresses::<E>(addrs));
                Dhcpv6OptionCode::DnsServers
            }
            Dhcpv6Option::DomainSearchList(domains) => {
                content.extend(Self::encode_domain_list(domains));
                Dhcpv6OptionCode::DomainSearchList
            }
            Dhcpv6Option::IaPd {
                iaid,
                t1,
                t2,
                options,
            } => {
                content.extend_from_slice(&iaid.to_be_bytes());
                content.extend_from_slice(&t1.to_be_bytes());
                content.extend_from_slice(&t2.to_be_bytes());
                for option in options {
                    let encoded = option.encode::<E>();
                    content.extend_from_slice(&(option.get_option_code() as u16).to_be_bytes());
                    content.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                    content.extend(encoded);
                }
                Dhcpv6OptionCode::IaPd
            }
            Dhcpv6Option::IaPrefix(prefix) => {
                content.extend(prefix.encode::<E>());
                Dhcpv6OptionCode::IaPrefix
            }
            // Add remaining option encodings here following the same pattern
            _ => {
                // For options that haven't been fully implemented yet or unknown options
                Dhcpv6OptionCode::Unknown(0)
            }
        };

        // Construct the complete option with header
        let mut option = Vec::new();
        option.extend_from_slice(&(option_code.as_u16()).to_be_bytes());
        option.extend_from_slice(&(content.len() as u16).to_be_bytes());
        option.extend(content);
        option
    }

    pub fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 4 {
            return None;
        }

        let option_code = u16::from_be_bytes([buf[0], buf[1]]);
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let mut offset = 4;

        if buf.len() < offset + length {
            return None;
        }

        let option_data = &buf[offset..offset + length];
        let option = match Dhcpv6OptionCode::from_repr(option_code)
            .unwrap_or(Dhcpv6OptionCode::Unknown(option_code))
        {
            Dhcpv6OptionCode::ClientId => {
                if let Some((duid, _)) = Duid::decode::<D>(option_data) {
                    Some(Dhcpv6Option::ClientId(duid))
                } else {
                    None
                }
            }
            Dhcpv6OptionCode::ServerId => {
                if let Some((duid, _)) = Duid::decode::<D>(option_data) {
                    Some(Dhcpv6Option::ServerId(duid))
                } else {
                    None
                }
            }
            // Add remaining option decodings here
            _ => Some(Dhcpv6Option::UnknownOption {
                option_code,
                data: option_data.to_vec(),
            }),
        }?;

        Some((option, offset + length))
    }

    // Helper method to get the option code for a given option
    pub fn get_option_code(&self) -> u16 {
        match self {
            Dhcpv6Option::UnknownOption { option_code, .. } => *option_code,
            other => {
                let ocode = match other {
                    Dhcpv6Option::ClientId(_) => Dhcpv6OptionCode::ClientId,
                    Dhcpv6Option::ServerId(_) => Dhcpv6OptionCode::ServerId,
                    Dhcpv6Option::IaNa { .. } => Dhcpv6OptionCode::IaNa,
                    // Add remaining option codes here
                    _ => panic!("FIXME - implement the rest"), // Default for unimplemented options
                };
                ocode.as_u16()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dhcpv6RelayMessage {
    pub hop_count: u8,
    pub link_address: Ipv6Address,
    pub peer_address: Ipv6Address,
    pub options: Vec<Dhcpv6Option>,
}

impl Default for Dhcpv6RelayMessage {
    fn default() -> Self {
        Self {
            hop_count: 0,
            link_address: Ipv6Address::default(),
            peer_address: Ipv6Address::default(),
            options: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Dhcpv6MessageContent {
    Normal {
        transaction_id: [u8; 3],
        options: Vec<Dhcpv6Option>,
    },
    Relay(Dhcpv6RelayMessage),
}

impl Default for Dhcpv6MessageContent {
    fn default() -> Self {
        Self::Normal {
            transaction_id: [0, 0, 0],
            options: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseDhcpv6MessageContentError;

impl FromStr for Dhcpv6MessageContent {
    type Err = ParseDhcpv6MessageContentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // For simple string representation, we'll accept hexadecimal transaction ID
        // for normal messages and IPv6 addresses for relay messages
        let s = s.trim();
        if s.starts_with("xid:") {
            // Parse as normal message with transaction ID
            let xid_str = &s[4..].trim();
            if xid_str.len() != 6 {
                // Need 6 hex chars for 3 bytes
                return Err(ParseDhcpv6MessageContentError);
            }

            // Try to parse the hex string into 3 bytes
            let mut transaction_id = [0u8; 3];
            for i in 0..3 {
                let byte_str = &xid_str[i * 2..(i + 1) * 2];
                transaction_id[i] =
                    u8::from_str_radix(byte_str, 16).map_err(|_| ParseDhcpv6MessageContentError)?;
            }

            Ok(Dhcpv6MessageContent::Normal {
                transaction_id,
                options: Vec::new(),
            })
        } else if s.starts_with("relay:") {
            // Parse as relay message with link and peer addresses
            let parts: Vec<&str> = s[6..].split(',').collect();
            if parts.len() != 2 {
                return Err(ParseDhcpv6MessageContentError);
            }

            let link_address = Ipv6Address::from_str(parts[0].trim())
                .map_err(|_| ParseDhcpv6MessageContentError)?;
            let peer_address = Ipv6Address::from_str(parts[1].trim())
                .map_err(|_| ParseDhcpv6MessageContentError)?;

            Ok(Dhcpv6MessageContent::Relay(Dhcpv6RelayMessage {
                hop_count: 0,
                link_address,
                peer_address,
                options: Vec::new(),
            }))
        } else {
            // Default to normal message with zero transaction ID
            Ok(Dhcpv6MessageContent::Normal {
                transaction_id: [0, 0, 0],
                options: Vec::new(),
            })
        }
    }
}

impl std::fmt::Display for Dhcpv6MessageContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dhcpv6MessageContent::Normal {
                transaction_id,
                options,
            } => {
                write!(
                    f,
                    "xid:{:02x}{:02x}{:02x}",
                    transaction_id[0], transaction_id[1], transaction_id[2]
                )?;
                if !options.is_empty() {
                    write!(f, " ({} options)", options.len())?;
                }
                Ok(())
            }
            Dhcpv6MessageContent::Relay(relay) => {
                write!(f, "relay:{},{}", relay.link_address, relay.peer_address)?;
                if !relay.options.is_empty() {
                    write!(f, " ({} options)", relay.options.len())?;
                }
                Ok(())
            }
        }
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 546))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 546))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 547))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 547))]
pub struct Dhcpv6 {
    pub msg_type: Value<Dhcpv6MessageType>,
    #[nproto(decode = decode_dhcpv6_content, encode = encode_dhcpv6_content)]
    pub content: Value<Dhcpv6MessageContent>,
}

fn encode_dhcpv6_content<E: Encoder>(
    me: &Dhcpv6,
    stack: &LayerStack,
    my_index: usize,
    encoded_data: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();

    match me.content.value() {
        Dhcpv6MessageContent::Normal {
            transaction_id,
            options,
        } => {
            out.extend_from_slice(&transaction_id);
            for option in options {
                out.extend(option.encode::<E>());
            }
        }
        Dhcpv6MessageContent::Relay(relay) => {
            out.push(relay.hop_count);
            out.extend(relay.link_address.encode::<E>());
            out.extend(relay.peer_address.encode::<E>());
            for option in &relay.options {
                out.extend(option.encode::<E>());
            }
        }
    }
    out
}

fn decode_dhcpv6_content<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dhcpv6,
) -> Option<(Dhcpv6MessageContent, usize)> {
    let buf = &buf[ci..];
    let mut offset = 0;

    match me.msg_type.value() {
        Dhcpv6MessageType::RelayForw | Dhcpv6MessageType::RelayRepl => {
            // Decode relay message
            if buf.len() < 34 {
                // 1 byte hop count + 16 bytes link-addr + 16 bytes peer-addr + at least 1 option
                return None;
            }

            let hop_count = buf[0];
            offset += 1;

            let (link_address, link_addr_len) = Ipv6Address::decode::<D>(&buf[offset..])?;
            offset += link_addr_len;

            let (peer_address, peer_addr_len) = Ipv6Address::decode::<D>(&buf[offset..])?;
            offset += peer_addr_len;

            let mut options = Vec::new();
            while offset < buf.len() {
                if let Some((option, option_len)) = Dhcpv6Option::decode::<D>(&buf[offset..]) {
                    options.push(option);
                    offset += option_len;
                } else {
                    break;
                }
            }

            Some((
                Dhcpv6MessageContent::Relay(Dhcpv6RelayMessage {
                    hop_count,
                    link_address,
                    peer_address,
                    options,
                }),
                offset,
            ))
        }
        _ => {
            // Decode normal message
            if buf.len() < 3 {
                // 3 bytes transaction ID
                return None;
            }

            let mut transaction_id = [0u8; 3];
            transaction_id.copy_from_slice(&buf[..3]);
            offset += 3;

            let mut options = Vec::new();
            while offset < buf.len() {
                if let Some((option, option_len)) = Dhcpv6Option::decode::<D>(&buf[offset..]) {
                    options.push(option);
                    offset += option_len;
                } else {
                    break;
                }
            }

            Some((
                Dhcpv6MessageContent::Normal {
                    transaction_id,
                    options,
                },
                offset,
            ))
        }
    }
}

impl Dhcpv6 {
    // Helper method to create a new client message
    pub fn new_client_message(msg_type: Dhcpv6MessageType, transaction_id: [u8; 3]) -> Self {
        Dhcpv6 {
            msg_type: Value::Set(msg_type),
            content: Value::Set(Dhcpv6MessageContent::Normal {
                transaction_id,
                options: Vec::new(),
            }),
        }
    }

    // Helper method to create a new relay message
    pub fn new_relay_message(
        msg_type: Dhcpv6MessageType,
        hop_count: u8,
        link_address: Ipv6Address,
        peer_address: Ipv6Address,
    ) -> Self {
        Dhcpv6 {
            msg_type: Value::Set(msg_type),
            content: Value::Set(Dhcpv6MessageContent::Relay(Dhcpv6RelayMessage {
                hop_count,
                link_address,
                peer_address,
                options: Vec::new(),
            })),
        }
    }

    // Helper method to add an option to a message
    pub fn add_option(&mut self, option: Dhcpv6Option) {
        match &mut self.content {
            Value::Set(Dhcpv6MessageContent::Normal { options, .. }) => {
                options.push(option);
            }
            Value::Set(Dhcpv6MessageContent::Relay(relay)) => {
                relay.options.push(option);
            }
            _ => {} // Handle Auto/Random cases if needed
        }
    }

    // Helper method to get all options of a specific type
    pub fn get_options_of_type<T>(&self, option_code: Dhcpv6OptionCode) -> Vec<&Dhcpv6Option> {
        match &self.content {
            Value::Set(Dhcpv6MessageContent::Normal { options, .. }) => options
                .iter()
                .filter(|opt| opt.get_option_code() == option_code.as_u16())
                .collect(),
            Value::Set(Dhcpv6MessageContent::Relay(relay)) => relay
                .options
                .iter()
                .filter(|opt| opt.get_option_code() == option_code.as_u16())
                .collect(),
            _ => Vec::new(),
        }
    }

    // Helper method to validate message according to RFC 8415 rules
    pub fn validate(&self) -> bool {
        match &self.content {
            Value::Set(Dhcpv6MessageContent::Normal { options, .. }) => {
                match self.msg_type.value() {
                    Dhcpv6MessageType::Solicit => {
                        // Must include Client ID and ORO
                        let has_client_id = options
                            .iter()
                            .any(|opt| matches!(opt, Dhcpv6Option::ClientId(_)));
                        let has_oro = options
                            .iter()
                            .any(|opt| matches!(opt, Dhcpv6Option::OptionRequest(_)));
                        has_client_id && has_oro
                    }
                    Dhcpv6MessageType::Advertise | Dhcpv6MessageType::Reply => {
                        // Must include Client ID and Server ID
                        let has_client_id = options
                            .iter()
                            .any(|opt| matches!(opt, Dhcpv6Option::ClientId(_)));
                        let has_server_id = options
                            .iter()
                            .any(|opt| matches!(opt, Dhcpv6Option::ServerId(_)));
                        has_client_id && has_server_id
                    }
                    // Add validation for other message types
                    _ => true,
                }
            }
            Value::Set(Dhcpv6MessageContent::Relay(relay)) => {
                match self.msg_type.value() {
                    Dhcpv6MessageType::RelayForw | Dhcpv6MessageType::RelayRepl => {
                        // Must have relay message option
                        relay
                            .options
                            .iter()
                            .any(|opt| matches!(opt, Dhcpv6Option::RelayMessage(_)))
                            && relay.hop_count <= DHCPV6_HOP_COUNT_LIMIT
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }
}

use crate::*;
use rand::distributions::{Distribution, Standard};
use rand::Rng;

// Implement random value generation for Dhcpv6MessageType
impl Distribution<Dhcpv6MessageType> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Dhcpv6MessageType {
        // Generate a random value between 1 and 13 (inclusive)
        // as these are the valid message types defined in the standard
        match rng.gen_range(1..=13) {
            1 => Dhcpv6MessageType::Solicit,
            2 => Dhcpv6MessageType::Advertise,
            3 => Dhcpv6MessageType::Request,
            4 => Dhcpv6MessageType::Confirm,
            5 => Dhcpv6MessageType::Renew,
            6 => Dhcpv6MessageType::Rebind,
            7 => Dhcpv6MessageType::Reply,
            8 => Dhcpv6MessageType::Release,
            9 => Dhcpv6MessageType::Decline,
            10 => Dhcpv6MessageType::Reconfigure,
            11 => Dhcpv6MessageType::InformationRequest,
            12 => Dhcpv6MessageType::RelayForw,
            13 => Dhcpv6MessageType::RelayRepl,
            _ => unreachable!(), // This can't happen due to the range constraint
        }
    }
}

// Implement random value generation for Dhcpv6MessageContent
impl Distribution<Dhcpv6MessageContent> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Dhcpv6MessageContent {
        if rng.gen_bool(0.8) {
            // 80% chance of normal message, 20% chance of relay
            let mut transaction_id = [0u8; 3];
            rng.fill_bytes(&mut transaction_id);
            Dhcpv6MessageContent::Normal {
                transaction_id,
                options: Vec::new(), // Start with empty options
            }
        } else {
            Dhcpv6MessageContent::Relay(Dhcpv6RelayMessage {
                hop_count: rng.gen_range(0..=DHCPV6_HOP_COUNT_LIMIT),
                link_address: rng.gen(), // Uses the Distribution impl for Ipv6Address
                peer_address: rng.gen(), // Uses the Distribution impl for Ipv6Address
                options: Vec::new(),     // Start with empty options
            })
        }
    }
}

// Implement encoding for Dhcpv6MessageType
impl Encode for Dhcpv6MessageType {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        vec![self.clone() as u8]
    }
}

// Implement decoding for Dhcpv6MessageType
impl Decode for Dhcpv6MessageType {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return None;
        }

        // Try to convert the first byte into a message type
        Dhcpv6MessageType::from_repr(buf[0]).map(|msg_type| (msg_type, 1))
    }
}

// Implement encoding for Dhcpv6MessageContent
impl Encode for Dhcpv6MessageContent {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Dhcpv6MessageContent::Normal {
                transaction_id,
                options,
            } => {
                out.extend_from_slice(transaction_id);
                for option in options {
                    out.extend(option.encode::<E>());
                }
            }
            Dhcpv6MessageContent::Relay(relay) => {
                out.push(relay.hop_count);
                out.extend(relay.link_address.encode::<E>());
                out.extend(relay.peer_address.encode::<E>());
                for option in &relay.options {
                    out.extend(option.encode::<E>());
                }
            }
        }
        out
    }
}

// Implement decoding for Dhcpv6MessageContent
impl Decode for Dhcpv6MessageContent {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.len() < 3 {
            return None;
        }

        // For simplicity, assume normal message - actual decoding will be handled by the
        // specific decode_dhcpv6_content function which has access to the message type
        let mut transaction_id = [0u8; 3];
        transaction_id.copy_from_slice(&buf[..3]);

        Some((
            Dhcpv6MessageContent::Normal {
                transaction_id,
                options: Vec::new(),
            },
            3,
        ))
    }
}
