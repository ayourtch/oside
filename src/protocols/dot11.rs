use crate::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use crate::typ::string::FixedSizeString;
use typenum::U32;

// Frame Control field components
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrameControl {
    pub protocol_version: u8,
    pub frame_type: u8,
    pub frame_subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_fragments: bool,
    pub retry: bool,
    pub power_management: bool,
    pub more_data: bool,
    pub protected: bool,
    pub order: bool,
}

impl FrameControl {
    pub fn new(
        protocol_version: u8,
        frame_type: u8,
        frame_subtype: u8,
        to_ds: bool,
        from_ds: bool,
        more_fragments: bool,
        retry: bool,
        power_management: bool,
        more_data: bool,
        protected: bool,
        order: bool,
    ) -> Self {
        Self {
            protocol_version,
            frame_type,
            frame_subtype,
            to_ds,
            from_ds,
            more_fragments,
            retry,
            power_management,
            more_data,
            protected,
            order,
        }
    }

    pub fn to_raw(&self) -> u16 {
        let mut result: u16 = 0;
        result |= (self.protocol_version as u16) & 0x03;
        result |= ((self.frame_type as u16) & 0x03) << 2;
        result |= ((self.frame_subtype as u16) & 0x0F) << 4;
        result |= (self.to_ds as u16) << 8;
        result |= (self.from_ds as u16) << 9;
        result |= (self.more_fragments as u16) << 10;
        result |= (self.retry as u16) << 11;
        result |= (self.power_management as u16) << 12;
        result |= (self.more_data as u16) << 13;
        result |= (self.protected as u16) << 14;
        result |= (self.order as u16) << 15;
        result
    }

    pub fn from_raw(value: u16) -> Self {
        Self {
            protocol_version: (value & 0x03) as u8,
            frame_type: ((value >> 2) & 0x03) as u8,
            frame_subtype: ((value >> 4) & 0x0F) as u8,
            to_ds: ((value >> 8) & 0x01) != 0,
            from_ds: ((value >> 9) & 0x01) != 0,
            more_fragments: ((value >> 10) & 0x01) != 0,
            retry: ((value >> 11) & 0x01) != 0,
            power_management: ((value >> 12) & 0x01) != 0,
            more_data: ((value >> 13) & 0x01) != 0,
            protected: ((value >> 14) & 0x01) != 0,
            order: ((value >> 15) & 0x01) != 0,
        }
    }
}

// Frame type constants
pub mod frame_types {
    // Main frame types
    pub const MANAGEMENT: u8 = 0;
    pub const CONTROL: u8 = 1;
    pub const DATA: u8 = 2;
    pub const EXTENSION: u8 = 3;

    // Management frame subtypes
    pub const ASSOC_REQ: u8 = 0;
    pub const ASSOC_RESP: u8 = 1;
    pub const REASSOC_REQ: u8 = 2;
    pub const REASSOC_RESP: u8 = 3;
    pub const PROBE_REQ: u8 = 4;
    pub const PROBE_RESP: u8 = 5;
    pub const TIMING_ADV: u8 = 6;
    pub const BEACON: u8 = 8;
    pub const ATIM: u8 = 9;
    pub const DISASSOC: u8 = 10;
    pub const AUTH: u8 = 11;
    pub const DEAUTH: u8 = 12;
    pub const ACTION: u8 = 13;
    pub const ACTION_NO_ACK: u8 = 14;
}

// Capabilities Info field
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitiesInfo {
    pub ess: bool,
    pub ibss: bool,
    pub cf_pollable: bool,
    pub cf_poll_request: bool,
    pub privacy: bool,
    pub short_preamble: bool,
    pub pbcc: bool,
    pub channel_agility: bool,
    pub spectrum_management: bool,
    pub qos: bool,
    pub short_slot_time: bool,
    pub apsd: bool,
    pub radio_measurement: bool,
    pub dsss_ofdm: bool,
    pub delayed_block_ack: bool,
    pub immediate_block_ack: bool,
}

impl CapabilitiesInfo {
    pub fn to_raw(&self) -> u16 {
        let mut result: u16 = 0;
        result |= (self.ess as u16) << 0;
        result |= (self.ibss as u16) << 1;
        result |= (self.cf_pollable as u16) << 2;
        result |= (self.cf_poll_request as u16) << 3;
        result |= (self.privacy as u16) << 4;
        result |= (self.short_preamble as u16) << 5;
        result |= (self.pbcc as u16) << 6;
        result |= (self.channel_agility as u16) << 7;
        result |= (self.spectrum_management as u16) << 8;
        result |= (self.qos as u16) << 9;
        result |= (self.short_slot_time as u16) << 10;
        result |= (self.apsd as u16) << 11;
        result |= (self.radio_measurement as u16) << 12;
        result |= (self.dsss_ofdm as u16) << 13;
        result |= (self.delayed_block_ack as u16) << 14;
        result |= (self.immediate_block_ack as u16) << 15;
        result
    }

    pub fn from_raw(value: u16) -> Self {
        Self {
            ess: (value & (1 << 0)) != 0,
            ibss: (value & (1 << 1)) != 0,
            cf_pollable: (value & (1 << 2)) != 0,
            cf_poll_request: (value & (1 << 3)) != 0,
            privacy: (value & (1 << 4)) != 0,
            short_preamble: (value & (1 << 5)) != 0,
            pbcc: (value & (1 << 6)) != 0,
            channel_agility: (value & (1 << 7)) != 0,
            spectrum_management: (value & (1 << 8)) != 0,
            qos: (value & (1 << 9)) != 0,
            short_slot_time: (value & (1 << 10)) != 0,
            apsd: (value & (1 << 11)) != 0,
            radio_measurement: (value & (1 << 12)) != 0,
            dsss_ofdm: (value & (1 << 13)) != 0,
            delayed_block_ack: (value & (1 << 14)) != 0,
            immediate_block_ack: (value & (1 << 15)) != 0,
        }
    }
}

// IEEE 802.11 Element IDs
#[derive(FromRepr, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ElementID {
    SSID = 0,
    SupportedRates = 1,
    DSParameter = 3,
    TIM = 5,
    IBSS = 6,
    Country = 7,
    HoppingParameters = 8,
    HoppingPatternTable = 9,
    Request = 10,
    BSSSwitchTime = 11,
    EBSSSwitchAnnouncment = 12,
    PowerConstraint = 32,
    PowerCapability = 33,
    TPC = 34,
    ChannelSwitch = 37,
    QuietTime = 40,
    IBSSCC = 41,
    ExtendedRates = 50,
    RSNE = 48,
    ExtendedCapabilities = 127,
    VendorSpecific = 221,
    // Many more element IDs exist in the standard
}

impl Default for ElementID {
    fn default() -> Self {
        ElementID::SSID
    }
}

// Base IEEE 802.11 Element structure
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Element {
    pub id: u8,
    pub data: Vec<u8>,
}

impl Element {
    pub fn new(id: u8, data: Vec<u8>) -> Self {
        Self { id, data }
    }
}

// Common types of elements found in beacons
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParsedElement {
    SSID(String),
    SupportedRates(Vec<u8>),
    DSParameter(u8), // Channel
    TIM(TIMElement),
    Country(CountryElement),
    ExtendedRates(Vec<u8>),
    RSN(RSNElement),
    ExtendedCapabilities(Vec<u8>),
    VendorSpecific(VendorSpecificElement),
    Unknown(Element),
}

// Traffic Indication Map (TIM) Element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TIMElement {
    pub dtim_count: u8,
    pub dtim_period: u8,
    pub bitmap_control: u8,
    pub partial_virtual_bitmap: Vec<u8>,
}

// Country Information Element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryElement {
    pub country_code: [u8; 2],
    pub environment: u8,
    pub triplets: Vec<CountryTriplet>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryTriplet {
    pub first_channel: u8,
    pub num_channels: u8,
    pub max_tx_power: u8,
}

// Robust Security Network Element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RSNElement {
    pub version: u16,
    pub group_cipher_suite: CipherSuite,
    pub pairwise_cipher_suites: Vec<CipherSuite>,
    pub akm_suites: Vec<AKMSuite>,
    pub rsn_capabilities: u16,
    pub pmkid_count: Option<u16>,
    pub pmkid_list: Vec<[u8; 16]>,
    pub group_management_cipher_suite: Option<CipherSuite>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSuite {
    pub oui: [u8; 3],
    pub suite_type: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AKMSuite {
    pub oui: [u8; 3],
    pub suite_type: u8,
}

// Vendor Specific Element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorSpecificElement {
    pub oui: [u8; 3],
    pub vendor_type: u8,
    pub data: Vec<u8>,
}

// IEEE 802.11 MAC Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11 {
    #[nproto(encode = encode_frame_control, decode = decode_frame_control)]
    pub frame_control: Value<FrameControl>,
    pub duration: Value<u16>,
    pub addr1: Value<MacAddr>, // Destination
    pub addr2: Value<MacAddr>, // Source
    pub addr3: Value<MacAddr>, // BSSID
    #[nproto(encode = encode_seq_control, decode = decode_seq_control)]
    pub seq_control: Value<u16>,
    // Optional addr4 field for frames with ToDS and FromDS set is handled in subclasses
}

fn encode_frame_control<E: Encoder>(
    my_layer: &Dot11,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let fc = my_layer.frame_control.value();
    fc.to_raw().encode::<E>()
}

fn decode_frame_control<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11,
) -> Option<(FrameControl, usize)> {
    let buf = &buf[ci..];
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let fc = FrameControl::from_raw(raw_value);
    Some((fc, delta))
}

fn encode_seq_control<E: Encoder>(
    my_layer: &Dot11,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.seq_control.value().encode::<E>()
}

fn decode_seq_control<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11,
) -> Option<(u16, usize)> {
    let buf = &buf[ci..];
    u16::decode::<D>(buf)
}

// IEEE 802.11 Beacon Frame Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Beacon {
    pub timestamp: Value<u64>,
    pub beacon_interval: Value<u16>,
    #[nproto(encode = encode_capabilities, decode = decode_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

fn encode_capabilities<E: Encoder>(
    my_layer: &Dot11Beacon,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.capabilities.value().to_raw().encode::<E>()
}

fn decode_capabilities<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11Beacon,
) -> Option<(CapabilitiesInfo, usize)> {
    let buf = &buf[ci..];
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let caps = CapabilitiesInfo::from_raw(raw_value);
    Some((caps, delta))
}

fn decode_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11Beacon,
) -> Option<(Vec<ParsedElement>, usize)> {
    let buf = &buf[ci..];
    let mut offset = 0;
    let mut elements = Vec::new();

    while offset + 2 <= buf.len() {
        let element_id = buf[offset];
        let element_len = buf[offset + 1] as usize;
        offset += 2;

        // Make sure we have enough data for the element
        if offset + element_len > buf.len() {
            break;
        }

        let element_data = buf[offset..offset + element_len].to_vec();
        offset += element_len;

        // Parse the element based on its ID
        let parsed_element = match element_id {
            0 => { // SSID
                let ssid = String::from_utf8_lossy(&element_data).to_string();
                ParsedElement::SSID(ssid)
            },
            1 => { // Supported Rates
                ParsedElement::SupportedRates(element_data)
            },
            3 => { // DS Parameter Set
                if element_data.len() == 1 {
                    ParsedElement::DSParameter(element_data[0])
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            },
            5 => { // TIM
                if element_data.len() >= 3 {
                    let dtim_count = element_data[0];
                    let dtim_period = element_data[1];
                    let bitmap_control = element_data[2];
                    let partial_virtual_bitmap = element_data[3..].to_vec();
                    
                    ParsedElement::TIM(TIMElement {
                        dtim_count,
                        dtim_period,
                        bitmap_control,
                        partial_virtual_bitmap,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            },
            7 => { // Country
                if element_data.len() >= 3 {
                    let mut country = CountryElement {
                        country_code: [element_data[0], element_data[1]],
                        environment: element_data[2],
                        triplets: Vec::new(),
                    };
                    
                    let mut i = 3;
                    while i + 2 < element_data.len() {
                        country.triplets.push(CountryTriplet {
                            first_channel: element_data[i],
                            num_channels: element_data[i+1],
                            max_tx_power: element_data[i+2],
                        });
                        i += 3;
                    }
                    
                    ParsedElement::Country(country)
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            },
            48 => { // RSN
                if element_data.len() >= 4 {
                    let mut rsn = RSNElement::default();
                    let mut pos = 0;
                    
                    // Version (2 bytes)
                    if pos + 2 <= element_data.len() {
                        rsn.version = u16::from_le_bytes([element_data[pos], element_data[pos+1]]);
                        pos += 2;
                    }
                    
                    // Group Cipher Suite (4 bytes)
                    if pos + 4 <= element_data.len() {
                        rsn.group_cipher_suite = CipherSuite {
                            oui: [element_data[pos], element_data[pos+1], element_data[pos+2]],
                            suite_type: element_data[pos+3],
                        };
                        pos += 4;
                    }
                    
                    // Pairwise Cipher Suite Count (2 bytes)
                    if pos + 2 <= element_data.len() {
                        let count = u16::from_le_bytes([element_data[pos], element_data[pos+1]]) as usize;
                        pos += 2;
                        
                        // Pairwise Cipher Suites (count * 4 bytes)
                        for _ in 0..count {
                            if pos + 4 <= element_data.len() {
                                rsn.pairwise_cipher_suites.push(CipherSuite {
                                    oui: [element_data[pos], element_data[pos+1], element_data[pos+2]],
                                    suite_type: element_data[pos+3],
                                });
                                pos += 4;
                            }
                        }
                    }
                    
                    // AKM Suite Count (2 bytes)
                    if pos + 2 <= element_data.len() {
                        let count = u16::from_le_bytes([element_data[pos], element_data[pos+1]]) as usize;
                        pos += 2;
                        
                        // AKM Suites (count * 4 bytes)
                        for _ in 0..count {
                            if pos + 4 <= element_data.len() {
                                rsn.akm_suites.push(AKMSuite {
                                    oui: [element_data[pos], element_data[pos+1], element_data[pos+2]],
                                    suite_type: element_data[pos+3],
                                });
                                pos += 4;
                            }
                        }
                    }
                    
                    // RSN Capabilities (2 bytes)
                    if pos + 2 <= element_data.len() {
                        rsn.rsn_capabilities = u16::from_le_bytes([element_data[pos], element_data[pos+1]]);
                        pos += 2;
                    }
                    
                    // Optional PMKID Count (2 bytes)
                    if pos + 2 <= element_data.len() {
                        let pmkid_count = u16::from_le_bytes([element_data[pos], element_data[pos+1]]);
                        rsn.pmkid_count = Some(pmkid_count);
                        pos += 2;
                        
                        // PMKID List (count * 16 bytes)
                        for _ in 0..pmkid_count {
                            if pos + 16 <= element_data.len() {
                                let mut pmkid = [0u8; 16];
                                pmkid.copy_from_slice(&element_data[pos..pos+16]);
                                rsn.pmkid_list.push(pmkid);
                                pos += 16;
                            }
                        }
                    }
                    
                    // Optional Group Management Cipher Suite (4 bytes)
                    if pos + 4 <= element_data.len() {
                        rsn.group_management_cipher_suite = Some(CipherSuite {
                            oui: [element_data[pos], element_data[pos+1], element_data[pos+2]],
                            suite_type: element_data[pos+3],
                        });
                    }
                    
                    ParsedElement::RSN(rsn)
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            },
            50 => { // Extended Supported Rates
                ParsedElement::ExtendedRates(element_data)
            },
            127 => { // Extended Capabilities
                ParsedElement::ExtendedCapabilities(element_data)
            },
            221 => { // Vendor Specific
                if element_data.len() >= 4 {
                    let vendor = VendorSpecificElement {
                        oui: [element_data[0], element_data[1], element_data[2]],
                        vendor_type: element_data[3],
                        data: element_data[4..].to_vec(),
                    };
                    ParsedElement::VendorSpecific(vendor)
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            },
            _ => ParsedElement::Unknown(Element::new(element_id, element_data)),
        };
        
        elements.push(parsed_element);
    }

    Some((elements, offset))
}

fn encode_elements<E: Encoder>(
    my_layer: &Dot11Beacon,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out = Vec::new();

    for element in &my_layer.elements {
        match element {
            ParsedElement::SSID(ssid) => {
                out.push(0); // SSID ID
                out.push(ssid.len() as u8); // Length
                out.extend_from_slice(ssid.as_bytes());
            },
            ParsedElement::SupportedRates(rates) => {
                out.push(1); // Supported Rates ID
                out.push(rates.len() as u8); // Length
                out.extend_from_slice(rates);
            },
            ParsedElement::DSParameter(channel) => {
                out.push(3); // DS Parameter ID
                out.push(1); // Length
                out.push(*channel);
            },
            ParsedElement::TIM(tim) => {
                out.push(5); // TIM ID
                let len = 3 + tim.partial_virtual_bitmap.len();
                out.push(len as u8); // Length
                out.push(tim.dtim_count);
                out.push(tim.dtim_period);
                out.push(tim.bitmap_control);
                out.extend_from_slice(&tim.partial_virtual_bitmap);
            },
            ParsedElement::Country(country) => {
                out.push(7); // Country ID
                let len = 3 + (country.triplets.len() * 3);
                out.push(len as u8); // Length
                out.extend_from_slice(&country.country_code);
                out.push(country.environment);
                for triplet in &country.triplets {
                    out.push(triplet.first_channel);
                    out.push(triplet.num_channels);
                    out.push(triplet.max_tx_power);
                }
            },
            ParsedElement::RSN(rsn) => {
                out.push(48); // RSN ID
                
                // Calculate length first
                let mut len = 2; // Version
                len += 4; // Group Cipher Suite
                len += 2; // Pairwise Cipher Suite Count
                len += 4 * rsn.pairwise_cipher_suites.len(); // Pairwise Cipher Suites
                len += 2; // AKM Suite Count
                len += 4 * rsn.akm_suites.len(); // AKM Suites
                len += 2; // RSN Capabilities
                
                if rsn.pmkid_count.is_some() {
                    len += 2; // PMKID Count
                    len += 16 * rsn.pmkid_list.len(); // PMKID List
                }
                
                if rsn.group_management_cipher_suite.is_some() {
                    len += 4; // Group Management Cipher Suite
                }
                
                out.push(len as u8); // Length
                
                // Now encode the data
                out.extend_from_slice(&rsn.version.to_le_bytes());
                
                // Group Cipher Suite
                out.extend_from_slice(&rsn.group_cipher_suite.oui);
                out.push(rsn.group_cipher_suite.suite_type);
                
                // Pairwise Cipher Suites
                out.extend_from_slice(&(rsn.pairwise_cipher_suites.len() as u16).to_le_bytes());
                for suite in &rsn.pairwise_cipher_suites {
                    out.extend_from_slice(&suite.oui);
                    out.push(suite.suite_type);
                }
                
                // AKM Suites
                out.extend_from_slice(&(rsn.akm_suites.len() as u16).to_le_bytes());
                for suite in &rsn.akm_suites {
                    out.extend_from_slice(&suite.oui);
                    out.push(suite.suite_type);
                }
                
                // RSN Capabilities
                out.extend_from_slice(&rsn.rsn_capabilities.to_le_bytes());
                
                // Optional PMKID Count and List
                if let Some(pmkid_count) = rsn.pmkid_count {
                    out.extend_from_slice(&pmkid_count.to_le_bytes());
                    for pmkid in &rsn.pmkid_list {
                        out.extend_from_slice(pmkid);
                    }
                }
                
                // Optional Group Management Cipher Suite
                if let Some(suite) = &rsn.group_management_cipher_suite {
                    out.extend_from_slice(&suite.oui);
                    out.push(suite.suite_type);
                }
            },
            ParsedElement::ExtendedRates(rates) => {
                out.push(50); // Extended Supported Rates ID
                out.push(rates.len() as u8); // Length
                out.extend_from_slice(rates);
            },
            ParsedElement::ExtendedCapabilities(capabilities) => {
                out.push(127); // Extended Capabilities ID
                out.push(capabilities.len() as u8); // Length
                out.extend_from_slice(capabilities);
            },
            ParsedElement::VendorSpecific(vendor) => {
                out.push(221); // Vendor Specific ID
                let len = 4 + vendor.data.len();
                out.push(len as u8); // Length
                out.extend_from_slice(&vendor.oui);
                out.push(vendor.vendor_type);
                out.extend_from_slice(&vendor.data);
            },
            ParsedElement::Unknown(element) => {
                out.push(element.id);
                out.push(element.data.len() as u8);
                out.extend_from_slice(&element.data);
            },
        }
    }

    out
}

// IEEE 802.11 Probe Request Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11ProbeReq {
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement
