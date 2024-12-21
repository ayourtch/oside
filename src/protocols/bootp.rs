use crate::typ::string::*;
use crate::*;
use serde::{Deserialize, Serialize};
// use strum::{Display};
use typenum::{U128, U16, U60, U64}; // FixedSizeString;
                                    /*
                                     * Bootp encapsulation
                                     */

const DHCP_COOKIE_VAL: u32 = 0x63825363;

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
enum VendorOptions {
    Pad = 0,
    End = 255,
}

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
enum DhcpOption {
    End = 255,                                     // 255 - no length
    Pad = 0,                                       // 0 - no length
    SubnetMask(Ipv4Address),                       // 1
    TimeOffset(i32),                               // 2
    Router(Vec<Ipv4Address>),                      // 3
    TimeServer(Vec<Ipv4Address>),                  // 4
    NameServer(Vec<Ipv4Address>),                  // 5
    DnsServer(Vec<Ipv4Address>),                   // 6
    LogServer(Vec<Ipv4Address>),                   // 7
    CookieServer(Vec<Ipv4Address>),                // 8
    LprServer(Vec<Ipv4Address>),                   // 9
    ImpressServer(Vec<Ipv4Address>),               // 10
    RlocServer(Vec<Ipv4Address>),                  // 11
    HostName(String),                              // 12
    BootFileSize(u16),                             // 13
    MeritDumpFile(String),                         // 14
    DomainName(String),                            // 15
    SwapServer(Ipv4Address),                       // 16
    RootPath(String),                              // 17
    ExtensionsPath(String),                        // 18
    IpForwarding(u8),                              // 19
    NonLocalSrcRouting(u8),                        // 20
    PolicyFilter(Vec<(Ipv4Address, Ipv4Address)>), // 21
    MaxReassemblySize(u16),                        // 22
    DefaultTTL(u8),                                // 23
    PmtudAgingTimeout(u32),                        // 24
    PmtudPlateauTable(Vec<u16>),                   // 25
    InterfaceMtu(u16),                             // 26
    AllSubnetsAreLocal(u8),                        // 27
    BroadcastAddress(Ipv4Address),                 // 28
    PerformMaskDiscovery(u8),                      // 29
    MaskSupplier(u8),                              // 30
    PerformRouterDiscovery(u8),                    // 31
    RouterSolicitationAddress(Ipv4Address),        // 32
    StaticRoute(Vec<(Ipv4Address, Ipv4Address)>),  // 33
    TrailerEncapsulation(u8),                      // 34
    ArpCacheTimeout(u32),                          // 35
    EthernetEncapsulation(u8),                     // 36
    TcpDefaultTtl(u8),                             // 37
    TcpKeepaliveInterval(u32),                     // 38
    TcpKeepaliveGarbage(u8),                       // 39
    NisDomain(String),                             // 40
    NisServers(Vec<Ipv4Address>),                  // 41
    NtpServers(Vec<Ipv4Address>),                  // 42
    VendorSpecific(Vec<VendorOptions>),            // 43
    NetBiosNameServer(Vec<Ipv4Address>),           // 44
    NetBiosDatagramServer(Vec<Ipv4Address>),       // 45
    NetBiosNodeType(u8),                           // 46
    NetBiosScope(String),                          // 47
    XWindowsFontServer(Vec<Ipv4Address>),          // 48
    XWindowsDisplayManager(Vec<Ipv4Address>),      // 49
    RequestedIpAddress(Ipv4Address),               // 50
    AddressLeaseTime(u32),                         // 51
    OptionOverload(u8),                            // 52
    DhcpMessageType(DhcpMessageType),              // 53
    ServerIdentifier(Ipv4Address),                 // 54
    ParameterRequestList(Vec<u8>),                 // 55
    NakMessage(String),                            // 56
    MaxDhcpMessageSize(u16),                       // 57
    RenewalT1Value(u32),                           // 58
    RebindT2Value(u32),                            // 59
    ClientClass(Vec<u8>),                          // 60
    ClientIdentifier((u8, Vec<u8>)),               // 61
}

impl Default for DhcpOption {
    fn default() -> Self {
        DhcpOption::Pad
    }
}

#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DhcpMessageType {
    DhcpDiscover = 1,
    DhcpOffer,
    DhcpRequest,
    DhcpDecline,
    DhcpAck,
    DhcpNak,
    DhcpRelease,
}

impl Default for DhcpMessageType {
    fn default() -> Self {
        DhcpMessageType::DhcpDiscover
    }
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(BOOTP_VENDORS, VendorCookie = DHCP_COOKIE_VAL))]
pub struct Dhcp {
    #[nproto(decode = decode_dhcp_opts, encode = encode_dhcp_opts)]
    pub options: Vec<DhcpOption>,
}
use crate::*;
use std::convert::TryFrom;

fn decode_dhcp_opts<D: Decoder>(buf: &[u8], me: &mut Dhcp) -> Option<(Vec<DhcpOption>, usize)> {
    let mut cursor = 0;
    let mut options: Vec<DhcpOption> = vec![];

    while cursor < buf.len() {
        match buf[cursor] {
            0 => {
                // Pad option
                options.push(DhcpOption::Pad);
                cursor += 1;
            }
            255 => {
                // End option
                options.push(DhcpOption::End);
                cursor += 1;
                break;
            }
            option_code => {
                if cursor + 1 >= buf.len() {
                    break; // Not enough bytes for length
                }

                let length = buf[cursor + 1] as usize;
                if cursor + 2 + length > buf.len() {
                    break; // Not enough bytes for value
                }

                let value_start = cursor + 2;
                let value_end = value_start + length;
                let value_buf = &buf[value_start..value_end];

                let option = match option_code {
                    1 => {
                        // Subnet Mask
                        if let Some((ip, _)) = Ipv4Address::decode::<D>(value_buf) {
                            Some(DhcpOption::SubnetMask(ip))
                        } else {
                            None
                        }
                    }
                    2 => {
                        // Time Offset
                        if let Some((offset, _)) = i32::decode::<D>(value_buf) {
                            Some(DhcpOption::TimeOffset(offset))
                        } else {
                            None
                        }
                    }
                    3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 => {
                        // Various IP address lists
                        let mut addresses = Vec::new();
                        let mut pos = 0;
                        while pos + 4 <= value_buf.len() {
                            if let Some((ip, len)) = Ipv4Address::decode::<D>(&value_buf[pos..]) {
                                addresses.push(ip);
                                pos += len;
                            } else {
                                break;
                            }
                        }
                        match option_code {
                            3 => Some(DhcpOption::Router(addresses)),
                            4 => Some(DhcpOption::TimeServer(addresses)),
                            5 => Some(DhcpOption::NameServer(addresses)),
                            6 => Some(DhcpOption::DnsServer(addresses)),
                            7 => Some(DhcpOption::LogServer(addresses)),
                            8 => Some(DhcpOption::CookieServer(addresses)),
                            9 => Some(DhcpOption::LprServer(addresses)),
                            10 => Some(DhcpOption::ImpressServer(addresses)),
                            11 => Some(DhcpOption::RlocServer(addresses)),
                            _ => None,
                        }
                    }
                    12 | 14 | 15 | 17 | 18 | 40 | 47 | 56 => {
                        // String options
                        if let Ok(s) = std::str::from_utf8(value_buf) {
                            match option_code {
                                12 => Some(DhcpOption::HostName(s.to_string())),
                                14 => Some(DhcpOption::MeritDumpFile(s.to_string())),
                                15 => Some(DhcpOption::DomainName(s.to_string())),
                                17 => Some(DhcpOption::RootPath(s.to_string())),
                                18 => Some(DhcpOption::ExtensionsPath(s.to_string())),
                                40 => Some(DhcpOption::NisDomain(s.to_string())),
                                47 => Some(DhcpOption::NetBiosScope(s.to_string())),
                                56 => Some(DhcpOption::NakMessage(s.to_string())),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    13 | 22 | 26 | 57 => {
                        // u16 options
                        if let Some((val, _)) = u16::decode::<D>(value_buf) {
                            match option_code {
                                13 => Some(DhcpOption::BootFileSize(val)),
                                22 => Some(DhcpOption::MaxReassemblySize(val)),
                                26 => Some(DhcpOption::InterfaceMtu(val)),
                                57 => Some(DhcpOption::MaxDhcpMessageSize(val)),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    16 | 28 | 32 | 50 | 54 => {
                        // Single IP address options
                        if let Some((ip, _)) = Ipv4Address::decode::<D>(value_buf) {
                            match option_code {
                                16 => Some(DhcpOption::SwapServer(ip)),
                                28 => Some(DhcpOption::BroadcastAddress(ip)),
                                32 => Some(DhcpOption::RouterSolicitationAddress(ip)),
                                50 => Some(DhcpOption::RequestedIpAddress(ip)),
                                54 => Some(DhcpOption::ServerIdentifier(ip)),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    19 | 20 | 23 | 27 | 29 | 30 | 31 | 34 | 36 | 37 | 39 | 46 | 52 => {
                        // u8 options
                        if value_buf.len() >= 1 {
                            let val = value_buf[0];
                            match option_code {
                                19 => Some(DhcpOption::IpForwarding(val)),
                                20 => Some(DhcpOption::NonLocalSrcRouting(val)),
                                23 => Some(DhcpOption::DefaultTTL(val)),
                                27 => Some(DhcpOption::AllSubnetsAreLocal(val)),
                                29 => Some(DhcpOption::PerformMaskDiscovery(val)),
                                30 => Some(DhcpOption::MaskSupplier(val)),
                                31 => Some(DhcpOption::PerformRouterDiscovery(val)),
                                34 => Some(DhcpOption::TrailerEncapsulation(val)),
                                36 => Some(DhcpOption::EthernetEncapsulation(val)),
                                37 => Some(DhcpOption::TcpDefaultTtl(val)),
                                39 => Some(DhcpOption::TcpKeepaliveGarbage(val)),
                                46 => Some(DhcpOption::NetBiosNodeType(val)),
                                52 => Some(DhcpOption::OptionOverload(val)),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    24 | 35 | 38 | 51 | 58 | 59 => {
                        // u32 options
                        if let Some((val, _)) = u32::decode::<D>(value_buf) {
                            match option_code {
                                24 => Some(DhcpOption::PmtudAgingTimeout(val)),
                                35 => Some(DhcpOption::ArpCacheTimeout(val)),
                                38 => Some(DhcpOption::TcpKeepaliveInterval(val)),
                                51 => Some(DhcpOption::AddressLeaseTime(val)),
                                58 => Some(DhcpOption::RenewalT1Value(val)),
                                59 => Some(DhcpOption::RebindT2Value(val)),
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                    21 | 33 => {
                        // IP address pair lists
                        let mut pairs = Vec::new();
                        let mut pos = 0;
                        while pos + 8 <= value_buf.len() {
                            if let Some((ip1, len1)) = Ipv4Address::decode::<D>(&value_buf[pos..]) {
                                pos += len1;
                                if let Some((ip2, len2)) =
                                    Ipv4Address::decode::<D>(&value_buf[pos..])
                                {
                                    pairs.push((ip1, ip2));
                                    pos += len2;
                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        match option_code {
                            21 => Some(DhcpOption::PolicyFilter(pairs)),
                            33 => Some(DhcpOption::StaticRoute(pairs)),
                            _ => None,
                        }
                    }
                    25 => {
                        // PMTUPlateauTable (Vec<u16>)
                        let mut values = Vec::new();
                        let mut pos = 0;
                        while pos + 2 <= value_buf.len() {
                            if let Some((val, len)) = u16::decode::<D>(&value_buf[pos..]) {
                                values.push(val);
                                pos += len;
                            } else {
                                break;
                            }
                        }
                        Some(DhcpOption::PmtudPlateauTable(values))
                    }
                    41 | 42 | 44 | 45 | 48 | 49 => {
                        // IP address lists
                        let mut addresses = Vec::new();
                        let mut pos = 0;
                        while pos + 4 <= value_buf.len() {
                            if let Some((ip, len)) = Ipv4Address::decode::<D>(&value_buf[pos..]) {
                                addresses.push(ip);
                                pos += len;
                            } else {
                                break;
                            }
                        }
                        match option_code {
                            41 => Some(DhcpOption::NisServers(addresses)),
                            42 => Some(DhcpOption::NtpServers(addresses)),
                            44 => Some(DhcpOption::NetBiosNameServer(addresses)),
                            45 => Some(DhcpOption::NetBiosDatagramServer(addresses)),
                            48 => Some(DhcpOption::XWindowsFontServer(addresses)),
                            49 => Some(DhcpOption::XWindowsDisplayManager(addresses)),
                            _ => None,
                        }
                    }
                    43 => {
                        // Vendor specific
                        let mut vendor_opts = Vec::new();
                        for b in value_buf {
                            if let Some(opt) = VendorOptions::from_repr(*b) {
                                vendor_opts.push(opt);
                            }
                        }
                        Some(DhcpOption::VendorSpecific(vendor_opts))
                    }
                    53 => {
                        // DHCP Message Type
                        if value_buf.len() >= 1 {
                            if let Some(msg_type) = DhcpMessageType::from_repr(value_buf[0]) {
                                Some(DhcpOption::DhcpMessageType(msg_type))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    55 => {
                        // Parameter Request List
                        Some(DhcpOption::ParameterRequestList(value_buf.to_vec()))
                    }
                    60 => {
                        // Client Class
                        Some(DhcpOption::ClientClass(value_buf.to_vec()))
                    }
                    61 => {
                        // Client Identifier
                        if value_buf.len() >= 1 {
                            let hw_type = value_buf[0];
                            let hw_addr = value_buf[1..].to_vec();
                            Some(DhcpOption::ClientIdentifier((hw_type, hw_addr)))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(opt) = option {
                    options.push(opt);
                }

                cursor = value_end;
            }
        }
    }

    Some((options, cursor))
}

fn encode_dhcp_opts<E: Encoder>(
    my_layer: &Dhcp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();

    for option in &my_layer.options {
        match option {
            DhcpOption::End => {
                out.push(255); // Option code for End
            }
            DhcpOption::Pad => {
                out.push(0); // Option code for Pad
            }
            DhcpOption::SubnetMask(addr) => {
                out.push(1); // Option code
                out.push(4); // Length
                out.extend(addr.encode::<E>());
            }
            DhcpOption::TimeOffset(offset) => {
                out.push(2);
                out.push(4);
                out.extend(offset.encode::<E>());
            }
            DhcpOption::Router(addrs)
            | DhcpOption::TimeServer(addrs)
            | DhcpOption::NameServer(addrs)
            | DhcpOption::DnsServer(addrs)
            | DhcpOption::LogServer(addrs)
            | DhcpOption::CookieServer(addrs)
            | DhcpOption::LprServer(addrs)
            | DhcpOption::ImpressServer(addrs)
            | DhcpOption::RlocServer(addrs) => {
                let code = match option {
                    DhcpOption::Router(_) => 3,
                    DhcpOption::TimeServer(_) => 4,
                    DhcpOption::NameServer(_) => 5,
                    DhcpOption::DnsServer(_) => 6,
                    DhcpOption::LogServer(_) => 7,
                    DhcpOption::CookieServer(_) => 8,
                    DhcpOption::LprServer(_) => 9,
                    DhcpOption::ImpressServer(_) => 10,
                    DhcpOption::RlocServer(_) => 11,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push((addrs.len() * 4) as u8); // Length = number of addresses * 4
                for addr in addrs {
                    out.extend(addr.encode::<E>());
                }
            }
            DhcpOption::HostName(name)
            | DhcpOption::MeritDumpFile(name)
            | DhcpOption::DomainName(name)
            | DhcpOption::RootPath(name)
            | DhcpOption::ExtensionsPath(name) => {
                let code = match option {
                    DhcpOption::HostName(_) => 12,
                    DhcpOption::MeritDumpFile(_) => 14,
                    DhcpOption::DomainName(_) => 15,
                    DhcpOption::RootPath(_) => 17,
                    DhcpOption::ExtensionsPath(_) => 18,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push(name.len() as u8);
                out.extend(name.as_bytes());
            }
            DhcpOption::BootFileSize(size) => {
                out.push(13);
                out.push(2);
                out.extend(size.encode::<E>());
            }
            DhcpOption::SwapServer(addr) => {
                out.push(16);
                out.push(4);
                out.extend(addr.encode::<E>());
            }
            DhcpOption::IpForwarding(val)
            | DhcpOption::NonLocalSrcRouting(val)
            | DhcpOption::DefaultTTL(val)
            | DhcpOption::AllSubnetsAreLocal(val)
            | DhcpOption::PerformMaskDiscovery(val)
            | DhcpOption::MaskSupplier(val)
            | DhcpOption::PerformRouterDiscovery(val)
            | DhcpOption::TrailerEncapsulation(val)
            | DhcpOption::EthernetEncapsulation(val)
            | DhcpOption::TcpDefaultTtl(val)
            | DhcpOption::TcpKeepaliveGarbage(val)
            | DhcpOption::NetBiosNodeType(val) => {
                let code = match option {
                    DhcpOption::IpForwarding(_) => 19,
                    DhcpOption::NonLocalSrcRouting(_) => 20,
                    DhcpOption::DefaultTTL(_) => 23,
                    DhcpOption::AllSubnetsAreLocal(_) => 27,
                    DhcpOption::PerformMaskDiscovery(_) => 29,
                    DhcpOption::MaskSupplier(_) => 30,
                    DhcpOption::PerformRouterDiscovery(_) => 31,
                    DhcpOption::TrailerEncapsulation(_) => 34,
                    DhcpOption::EthernetEncapsulation(_) => 36,
                    DhcpOption::TcpDefaultTtl(_) => 37,
                    DhcpOption::TcpKeepaliveGarbage(_) => 39,
                    DhcpOption::NetBiosNodeType(_) => 46,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push(1);
                out.push(*val);
            }
            DhcpOption::PolicyFilter(pairs) => {
                out.push(21);
                out.push((pairs.len() * 8) as u8); // Each pair is 8 bytes (2 IPv4 addresses)
                for (addr1, addr2) in pairs {
                    out.extend(addr1.encode::<E>());
                    out.extend(addr2.encode::<E>());
                }
            }
            DhcpOption::MaxReassemblySize(size)
            | DhcpOption::InterfaceMtu(size)
            | DhcpOption::MaxDhcpMessageSize(size) => {
                let code = match option {
                    DhcpOption::MaxReassemblySize(_) => 22,
                    DhcpOption::InterfaceMtu(_) => 26,
                    DhcpOption::MaxDhcpMessageSize(_) => 57,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push(2);
                out.extend(size.encode::<E>());
            }
            DhcpOption::PmtudAgingTimeout(time)
            | DhcpOption::ArpCacheTimeout(time)
            | DhcpOption::TcpKeepaliveInterval(time)
            | DhcpOption::AddressLeaseTime(time)
            | DhcpOption::RenewalT1Value(time)
            | DhcpOption::RebindT2Value(time) => {
                let code = match option {
                    DhcpOption::PmtudAgingTimeout(_) => 24,
                    DhcpOption::ArpCacheTimeout(_) => 35,
                    DhcpOption::TcpKeepaliveInterval(_) => 38,
                    DhcpOption::AddressLeaseTime(_) => 51,
                    DhcpOption::RenewalT1Value(_) => 58,
                    DhcpOption::RebindT2Value(_) => 59,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push(4);
                out.extend(time.encode::<E>());
            }
            DhcpOption::PmtudPlateauTable(values) => {
                out.push(25);
                out.push((values.len() * 2) as u8);
                for value in values {
                    out.extend(value.encode::<E>());
                }
            }
            DhcpOption::BroadcastAddress(addr)
            | DhcpOption::RouterSolicitationAddress(addr)
            | DhcpOption::RequestedIpAddress(addr)
            | DhcpOption::ServerIdentifier(addr) => {
                let code = match option {
                    DhcpOption::BroadcastAddress(_) => 28,
                    DhcpOption::RouterSolicitationAddress(_) => 32,
                    DhcpOption::RequestedIpAddress(_) => 50,
                    DhcpOption::ServerIdentifier(_) => 54,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push(4);
                out.extend(addr.encode::<E>());
            }
            DhcpOption::StaticRoute(routes) => {
                out.push(33);
                out.push((routes.len() * 8) as u8);
                for (dest, router) in routes {
                    out.extend(dest.encode::<E>());
                    out.extend(router.encode::<E>());
                }
            }
            DhcpOption::NisDomain(s) | DhcpOption::NetBiosScope(s) | DhcpOption::NakMessage(s) => {
                let code = match option {
                    DhcpOption::NisDomain(_) => 40,
                    DhcpOption::NetBiosScope(_) => 47,
                    DhcpOption::NakMessage(_) => 56,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push(s.len() as u8);
                out.extend(s.as_bytes());
            }
            DhcpOption::NisServers(addrs)
            | DhcpOption::NtpServers(addrs)
            | DhcpOption::NetBiosNameServer(addrs)
            | DhcpOption::NetBiosDatagramServer(addrs)
            | DhcpOption::XWindowsFontServer(addrs)
            | DhcpOption::XWindowsDisplayManager(addrs) => {
                let code = match option {
                    DhcpOption::NisServers(_) => 41,
                    DhcpOption::NtpServers(_) => 42,
                    DhcpOption::NetBiosNameServer(_) => 44,
                    DhcpOption::NetBiosDatagramServer(_) => 45,
                    DhcpOption::XWindowsFontServer(_) => 48,
                    DhcpOption::XWindowsDisplayManager(_) => 49,
                    _ => unreachable!(),
                };
                out.push(code);
                out.push((addrs.len() * 4) as u8);
                for addr in addrs {
                    out.extend(addr.encode::<E>());
                }
            }
            DhcpOption::VendorSpecific(options) => {
                out.push(43);
                out.push(options.len() as u8);
                for opt in options {
                    out.push(0 as u8);
                }
                panic!("FIXME");
            }
            DhcpOption::OptionOverload(val) => {
                out.push(52);
                out.push(1);
                out.push(*val);
            }
            DhcpOption::DhcpMessageType(msg_type) => {
                out.push(53);
                out.push(1);
                out.push((*msg_type).clone() as u8);
            }
            DhcpOption::ParameterRequestList(params) => {
                out.push(55);
                out.push(params.len() as u8);
                out.extend(params);
            }
            DhcpOption::ClientClass(data) => {
                out.push(60);
                out.push(data.len() as u8);
                out.extend(data);
            }
            DhcpOption::ClientIdentifier((hw_type, data)) => {
                out.push(61);
                out.push((1 + data.len()) as u8);
                out.push(*hw_type);
                out.extend(data);
            }
        }
    }

    // If the last option is not End, append it
    if !matches!(my_layer.options.last(), Some(DhcpOption::End)) {
        out.push(255); // End option
    }

    out
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 67))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 67))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 68))]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 68))]
pub struct Bootp {
    #[nproto(default = 0x01)] // "Request" by default
    pub op: Value<u8>,
    pub htype: Value<u8>,  // hardware address type
    pub hlen: Value<u8>,   // hardware address length
    pub hops: Value<u8>,   // client sets to zero
    pub xid: Value<u32>,   // transaction ID
    pub secs: Value<u16>,  // seconds since client started trying to boot
    pub flags: Value<u16>, // 0x8000 = broadcast
    #[nproto(default = "0.0.0.0")]
    pub ciaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub yiaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub siaddr: Value<Ipv4Address>,
    #[nproto(default = "0.0.0.0")]
    pub giaddr: Value<Ipv4Address>,
    chaddr: Value<FixedSizeString<U16>>, // client hardware address filled by client
    sname: Value<FixedSizeString<U64>>,  // optional server host name, null terminated str
    file: Value<FixedSizeString<U128>>,  // boot file name, null terminated string
    #[nproto(default = 0x123456)]
    #[nproto(next: BOOTP_VENDORS => VendorCookie)]
    cookie: Value<u32>,
    #[nproto(decode = decode_vend, encode = encode_vend)]
    vend: Value<BootpVendorData>, // Optional vendor specific area
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum BootpVendorData {
    Unset,
    Set(FixedSizeString<U60>),
}

impl Distribution<BootpVendorData> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BootpVendorData {
        // FIXME: rng.gen(),
        BootpVendorData::Unset
    }
}

impl Default for BootpVendorData {
    fn default() -> Self {
        Self::Unset
    }
}

impl FromStr for BootpVendorData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 0 {
            Ok(BootpVendorData::Unset)
        } else {
            Ok(BootpVendorData::Set(FixedSizeString::<U60>::from_str(s)?))
        }
    }
}

fn decode_vend<D: Decoder>(buf: &[u8], me: &mut Bootp) -> Option<(BootpVendorData, usize)> {
    let mut ci = 0;
    if me.cookie == Value::Set(DHCP_COOKIE_VAL) {
        Some((BootpVendorData::Unset, 0))
    } else {
        let (the_vec, _) = D::decode_vec(buf, 60)?;
        // FIXME
        Some((BootpVendorData::Unset, 0))
        // Some((BootpVendorData::Set(the_vec), 60))
    }
}

fn encode_vend<E: Encoder>(
    my_layer: &Bootp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    // FIXME
    vec![]
}
