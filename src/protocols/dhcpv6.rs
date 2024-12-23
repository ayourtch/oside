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
    LinkLayerTimePlusTime = 1,  // DUID-LLT
    VendorAssigned = 2,         // DUID-EN
    LinkLayer = 3,              // DUID-LL
    Uuid = 4,                   // DUID-UUID
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
    pub time: u32,  // Time value in seconds since January 1, 2000
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
