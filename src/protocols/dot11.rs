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

// IEEE 802.11 Probe Response Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11ProbeResp {
    pub timestamp: Value<u64>,
    pub beacon_interval: Value<u16>,
    #[nproto(encode = encode_capabilities, decode = decode_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Association Request Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11AssocReq {
    #[nproto(encode = encode_capabilities, decode = decode_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    pub listen_interval: Value<u16>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Association Response Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11AssocResp {
    #[nproto(encode = encode_capabilities, decode = decode_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    pub status_code: Value<u16>,
    pub association_id: Value<u16>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Reassociation Request Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11ReassocReq {
    #[nproto(encode = encode_capabilities, decode = decode_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    pub listen_interval: Value<u16>,
    pub current_ap: Value<MacAddr>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Authentication Frame Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Auth {
    pub auth_algorithm: Value<u16>,
    pub auth_seq: Value<u16>,
    pub status_code: Value<u16>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Deauthentication Frame Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Deauth {
    pub reason_code: Value<u16>,
}

// IEEE 802.11 Action Frame Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Action {
    pub category: Value<u8>,
    pub action: Value<u8>,
    #[nproto(decode = decode_elements, encode = encode_elements)]
    pub elements: Vec<ParsedElement>,
}

// Helpers for working with IEEE 802.11 frames

// IEEE 802.11 Radiotap Header Implementation
// Used for capturing 802.11 frames with additional radio information in pcap files
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Radiotap {
    pub version: Value<u8>,
    pub pad: Value<u8>,
    #[nproto(encode = encode_radiotap_length, decode = decode_radiotap_length)]
    pub length: Value<u16>,
    #[nproto(encode = encode_radiotap_present, decode = decode_radiotap_present)]
    pub present_flags: Value<u32>,
    #[nproto(decode = decode_radiotap_fields)]
    pub fields: Vec<RadiotapField>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RadiotapField {
    TSFT(u64),
    Flags(u8),
    Rate(u8),
    Channel(u16, u16), // Frequency and flags
    FHSS(u8, u8),
    AntennaSignal(i8),
    AntennaNoise(i8),
    LockQuality(u16),
    TxAttenuation(u16),
    DBTxAttenuation(u16),
    DBmTxPower(i8),
    Antenna(u8),
    DBAntennaSignal(u8),
    DBAntennaNoise(u8),
    RxFlags(u16),
    TxFlags(u16),
    RtsRetries(u8),
    DataRetries(u8),
    XChannel(u32, u16, u8), // flags, freq, channel
    MCS(u8, u8, u8), // known, flags, mcs
    AMPDUStatus(u32, u16, u8, u8), // reference number, flags, delimiter CRC, reserved
    VHT(u16, u8, u8, Vec<u8>), // known, flags, bandwidth, mcs_nss, coding
    HEData1(u16, u16), // data1, data2
    HEData2(u16, u16), // data3, data4
    HEData3(u16, u16), // data5, data6
    HEData4(u8, u8, u8, u8), // data7-data10
    HEData5(u8, u8, u8, u8), // data11-data14
    HEData6(u8, u8), // data15-data16
    RadiotapNamespace(),
    VendorNamespace(Vec<u8>),
    ExtendedBitmap(u32),
    Unknown(u32, Vec<u8>), // bit position, data
}

// Radiotap present flags
pub mod radiotap_flags {
    pub const TSFT: u32 = 1 << 0;
    pub const FLAGS: u32 = 1 << 1;
    pub const RATE: u32 = 1 << 2;
    pub const CHANNEL: u32 = 1 << 3;
    pub const FHSS: u32 = 1 << 4;
    pub const DBM_ANTSIGNAL: u32 = 1 << 5;
    pub const DBM_ANTNOISE: u32 = 1 << 6;
    pub const LOCK_QUALITY: u32 = 1 << 7;
    pub const TX_ATTENUATION: u32 = 1 << 8;
    pub const DB_TX_ATTENUATION: u32 = 1 << 9;
    pub const DBM_TX_POWER: u32 = 1 << 10;
    pub const ANTENNA: u32 = 1 << 11;
    pub const DB_ANTSIGNAL: u32 = 1 << 12;
    pub const DB_ANTNOISE: u32 = 1 << 13;
    pub const RX_FLAGS: u32 = 1 << 14;
    pub const TX_FLAGS: u32 = 1 << 15;
    pub const RTS_RETRIES: u32 = 1 << 16;
    pub const DATA_RETRIES: u32 = 1 << 17;
    pub const XCHANNEL: u32 = 1 << 18;
    pub const MCS: u32 = 1 << 19;
    pub const AMPDU_STATUS: u32 = 1 << 20;
    pub const VHT: u32 = 1 << 21;
    pub const HE: u32 = 1 << 22;
    pub const HE_MU: u32 = 1 << 23;
    pub const HE_MU_OTHER_USER: u32 = 1 << 24;
    pub const ZERO_LEN_PSDU: u32 = 1 << 25;
    pub const L_SIG: u32 = 1 << 26;
    pub const TLV: u32 = 1 << 27;
    pub const RADIOTAP_NAMESPACE: u32 = 1 << 29;
    pub const VENDOR_NAMESPACE: u32 = 1 << 30;
    pub const EXT: u32 = 1 << 31;
}

fn encode_radiotap_length<E: Encoder>(
    my_layer: &Radiotap,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.length.value().encode::<E>()
}

fn decode_radiotap_length<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Radiotap,
) -> Option<(u16, usize)> {
    let buf = &buf[ci..];
    u16::decode::<D>(buf)
}

fn encode_radiotap_present<E: Encoder>(
    my_layer: &Radiotap,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.present_flags.value().encode::<E>()
}

fn decode_radiotap_present<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Radiotap,
) -> Option<(u32, usize)> {
    let buf = &buf[ci..];
    u32::decode::<D>(buf)
}

fn decode_radiotap_fields<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Radiotap,
) -> Option<(Vec<RadiotapField>, usize)> {
    let buf = &buf[ci..];
    let radiotap_len = me.length.value() as usize;
    
    if radiotap_len <= 8 || ci + radiotap_len > buf.len() {
        // Not enough data for radiotap header
        return Some((Vec::new(), 0));
    }

    let mut fields = Vec::new();
    let mut present = me.present_flags.value();
    let mut present_bitmaps = vec![present];
    let mut bitmap_idx = 0;
    
    // Check for extended bitmaps
    while present & radiotap_flags::EXT != 0 && bitmap_idx < 8 {
        bitmap_idx += 1;
        let offset = 4 + (bitmap_idx * 4);
        if ci + offset + 4 > buf.len() {
            break;
        }
        
        let next_present = u32::from_le_bytes([
            buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]
        ]);
        present_bitmaps.push(next_present);
    }
    
    // Start parsing after the last present flag bitmap
    let mut offset = 8 + (bitmap_idx * 4);
    
    // 4-byte alignment for certain fields
    let align_offset = |off: usize| -> usize {
        (off + 3) & !3
    };
    
    // Parse each bitmap
    for (idx, present) in present_bitmaps.iter().enumerate() {
        let base_bit = idx * 32;
        
        // Skip the extended bit
        let parse_bits = if *present & radiotap_flags::EXT != 0 {
            31
        } else {
            32
        };
        
        for bit in 0..parse_bits {
            // Skip extended bitmap bit
            if bit == 31 {
                continue;
            }
            
            let flag = 1 << bit;
            if present & flag == 0 {
                continue;
            }
            
            // Parse based on the bit position
            let global_bit = base_bit + bit;
            
            match global_bit {
                0 => { // TSFT
                    offset = align_offset(offset);
                    if offset + 8 <= radiotap_len {
                        let tsft = u64::from_le_bytes([
                            buf[offset], buf[offset+1], buf[offset+2], buf[offset+3],
                            buf[offset+4], buf[offset+5], buf[offset+6], buf[offset+7]
                        ]);
                        fields.push(RadiotapField::TSFT(tsft));
                        offset += 8;
                    }
                },
                1 => { // FLAGS
                    if offset < radiotap_len {
                        fields.push(RadiotapField::Flags(buf[offset]));
                        offset += 1;
                    }
                },
                2 => { // RATE
                    if offset < radiotap_len {
                        fields.push(RadiotapField::Rate(buf[offset]));
                        offset += 1;
                    }
                },
                3 => { // CHANNEL
                    offset = align_offset(offset);
                    if offset + 4 <= radiotap_len {
                        let freq = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        let flags = u16::from_le_bytes([buf[offset+2], buf[offset+3]]);
                        fields.push(RadiotapField::Channel(freq, flags));
                        offset += 4;
                    }
                },
                4 => { // FHSS
                    if offset + 2 <= radiotap_len {
                        fields.push(RadiotapField::FHSS(buf[offset], buf[offset+1]));
                        offset += 2;
                    }
                },
                5 => { // DBM_ANTSIGNAL
                    if offset < radiotap_len {
                        fields.push(RadiotapField::AntennaSignal(buf[offset] as i8));
                        offset += 1;
                    }
                },
                6 => { // DBM_ANTNOISE
                    if offset < radiotap_len {
                        fields.push(RadiotapField::AntennaNoise(buf[offset] as i8));
                        offset += 1;
                    }
                },
                7 => { // LOCK_QUALITY
                    offset = align_offset(offset);
                    if offset + 2 <= radiotap_len {
                        let quality = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        fields.push(RadiotapField::LockQuality(quality));
                        offset += 2;
                    }
                },
                8 => { // TX_ATTENUATION
                    offset = align_offset(offset);
                    if offset + 2 <= radiotap_len {
                        let atten = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        fields.push(RadiotapField::TxAttenuation(atten));
                        offset += 2;
                    }
                },
                9 => { // DB_TX_ATTENUATION
                    offset = align_offset(offset);
                    if offset + 2 <= radiotap_len {
                        let atten = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        fields.push(RadiotapField::DBTxAttenuation(atten));
                        offset += 2;
                    }
                },
                10 => { // DBM_TX_POWER
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DBmTxPower(buf[offset] as i8));
                        offset += 1;
                    }
                },
                11 => { // ANTENNA
                    if offset < radiotap_len {
                        fields.push(RadiotapField::Antenna(buf[offset]));
                        offset += 1;
                    }
                },
                12 => { // DB_ANTSIGNAL
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DBAntennaSignal(buf[offset]));
                        offset += 1;
                    }
                },
                13 => { // DB_ANTNOISE
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DBAntennaNoise(buf[offset]));
                        offset += 1;
                    }
                },
                14 => { // RX_FLAGS
                    offset = align_offset(offset);
                    if offset + 2 <= radiotap_len {
                        let flags = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        fields.push(RadiotapField::RxFlags(flags));
                        offset += 2;
                    }
                },
                15 => { // TX_FLAGS
                    offset = align_offset(offset);
                    if offset + 2 <= radiotap_len {
                        let flags = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        fields.push(RadiotapField::TxFlags(flags));
                        offset += 2;
                    }
                },
                16 => { // RTS_RETRIES
                    if offset < radiotap_len {
                        fields.push(RadiotapField::RtsRetries(buf[offset]));
                        offset += 1;
                    }
                },
                17 => { // DATA_RETRIES
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DataRetries(buf[offset]));
                        offset += 1;
                    }
                },
                18 => { // XCHANNEL
                    offset = align_offset(offset);
                    if offset + 8 <= radiotap_len {
                        let flags = u32::from_le_bytes([
                            buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]
                        ]);
                        let freq = u16::from_le_bytes([buf[offset+4], buf[offset+5]]);
                        let channel = buf[offset+6];
                        let max_power = buf[offset+7];
                        fields.push(RadiotapField::XChannel(flags, freq, channel));
                        offset += 8;
                    }
                },
                19 => { // MCS
                    if offset + 3 <= radiotap_len {
                        let known = buf[offset];
                        let flags = buf[offset+1];
                        let mcs = buf[offset+2];
                        fields.push(RadiotapField::MCS(known, flags, mcs));
                        offset += 3;
                    }
                },
                20 => { // AMPDU_STATUS
                    offset = align_offset(offset);
                    if offset + 8 <= radiotap_len {
                        let reference = u32::from_le_bytes([
                            buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]
                        ]);
                        let flags = u16::from_le_bytes([buf[offset+4], buf[offset+5]]);
                        let delimiter_crc = buf[offset+6];
                        let reserved = buf[offset+7];
                        fields.push(RadiotapField::AMPDUStatus(reference, flags, delimiter_crc, reserved));
                        offset += 8;
                    }
                },
                21 => { // VHT
                    if offset + 12 <= radiotap_len {
                        let known = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        let flags = buf[offset+2];
                        let bandwidth = buf[offset+3];
                        let mcs_nss = Vec::from(&buf[offset+4..offset+8]);
                        let coding = buf[offset+8];
                        let group_id = buf[offset+9];
                        let partial_aid = u16::from_le_bytes([buf[offset+10], buf[offset+11]]);
                        fields.push(RadiotapField::VHT(known, flags, bandwidth, mcs_nss));
                        offset += 12;
                    }
                },
                22..=26 => { // HE fields
                    // Skip complex HE fields for now, they have variable size
                    // and depend on the specific 802.11ax implementation
                    offset = align_offset(offset);
                    if offset + 4 <= radiotap_len {
                        let data1 = u16::from_le_bytes([buf[offset], buf[offset+1]]);
                        let data2 = u16::from_le_bytes([buf[offset+2], buf[offset+3]]);
                        fields.push(RadiotapField::HEData1(data1, data2));
                        offset += 4;
                    }
                    // Skip the rest of the HE data for simplicity
                },
                29 => { // RADIOTAP_NAMESPACE
                    fields.push(RadiotapField::RadiotapNamespace());
                    // No length defined, must be followed by another namespace
                },
                30 => { // VENDOR_NAMESPACE
                    offset = align_offset(offset);
                    if offset + 6 <= radiotap_len {
                        let oui_len = u16::from_le_bytes([buf[offset+4], buf[offset+5]]) as usize;
                        if offset + 6 + oui_len <= radiotap_len {
                            let data = Vec::from(&buf[offset..offset+6+oui_len]);
                            fields.push(RadiotapField::VendorNamespace(data));
                            offset += 6 + oui_len;
                        }
                    }
                },
                _ => {
                    // Unknown field, store the bit position
                    fields.push(RadiotapField::Unknown(global_bit as u32, Vec::new()));
                }
            }
        }
    }
    
    Some((fields, radiotap_len - ci))
}

// IEEE 802.11 FCS (Frame Check Sequence)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11FCS {
    pub fcs: Value<u32>,
}

// Decode a complete 802.11 frame from a raw buffer (possibly with radiotap header and FCS)
pub fn decode_802_11_frame(buf: &[u8], has_fcs: bool) -> Option<(LayerStack, usize)> {
    let mut offset = 0;
    let mut stack = LayerStack { layers: Vec::new(), filled: true };
    
    // First, check if we have a radiotap header
    if buf.len() >= 4 && buf[0] == 0x00 && buf[1] == 0x00 { // Radiotap magic
        let radiotap = Radiotap::default();
        if let Some((radiotap_decoded, radiotap_offset)) = radiotap.decode_with_decoder::<BinaryBigEndian>(&buf) {
            stack.layers.extend(radiotap_decoded.layers);
            offset += radiotap_offset;
        } else {
            return None;
        }
    }
    
    // Calculate the length to the end of the frame, taking into account FCS if present
    let data_end = if has_fcs { buf.len() - 4 } else { buf.len() };
    
    // Next, decode the 802.11 header and appropriate frame type
    if let Some((dot11_decoded, dot11_offset)) = decode_dot11_management_frame(&buf[offset..data_end]) {
        stack.layers.extend(dot11_decoded.layers);
        offset += dot11_offset;
    } else {
        return None;
    }
    
    // If we have an FCS, decode it
    if has_fcs && buf.len() >= 4 {
        let fcs_start = buf.len() - 4;
        let fcs_value = u32::from_le_bytes([
            buf[fcs_start], buf[fcs_start+1], buf[fcs_start+2], buf[fcs_start+3]
        ]);
        
        let mut fcs = Dot11FCS::default();
        fcs = fcs.fcs(fcs_value);
        stack.layers.push(Box::new(fcs));
    }
    
    Some((stack, buf.len()))
}

// Calculate the FCS for an 802.11 frame
pub fn calculate_fcs(frame: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFF;
    for &byte in frame {
        crc = (crc >> 8) ^ FCS_TABLE[((crc & 0xFF) ^ byte as u32) as usize];
    }
    !crc
}

// FCS lookup table for CRC-32 calculation
static FCS_TABLE: [u32; 256] = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
];

// Control frame subtypes
pub mod control_frame_subtypes {
    pub const CTS: u8 = 12;
    pub const ACK: u8 = 13;
    pub const RTS: u8 = 11;
    pub const BLOCK_ACK_REQ: u8 = 8;
    pub const BLOCK_ACK: u8 = 9;
    pub const PS_POLL: u8 = 10;
    pub const CF_END: u8 = 14;
    pub const CF_END_ACK: u8 = 15;
}

// Data frame subtypes
pub mod data_frame_subtypes {
    pub const DATA: u8 = 0;
    pub const DATA_CF_ACK: u8 = 1;
    pub const DATA_CF_POLL: u8 = 2;
    pub const DATA_CF_ACK_POLL: u8 = 3;
    pub const NULL: u8 = 4;
    pub const CF_ACK: u8 = 5;
    pub const CF_POLL: u8 = 6;
    pub const CF_ACK_POLL: u8 = 7;
    pub const QOS_DATA: u8 = 8;
    pub const QOS_DATA_CF_ACK: u8 = 9;
    pub const QOS_DATA_CF_POLL: u8 = 10;
    pub const QOS_DATA_CF_ACK_POLL: u8 = 11;
    pub const QOS_NULL: u8 = 12;
    pub const QOS_CF_POLL: u8 = 14;
    pub const QOS_CF_ACK_POLL: u8 = 15;
}

// IEEE 802.11 Control Frame Implementations
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11RTS {
    // RTS has no additional fields beyond the Dot11 header
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11CTS {
    // CTS has no additional fields beyond the Dot11 header
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11ACK {
    // ACK has no additional fields beyond the Dot11 header
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11BlockAckReq {
    pub bar_control: Value<u16>,
    pub sequence_control: Value<u16>,
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11BlockAck {
    pub ba_control: Value<u16>,
    pub sequence_control: Value<u16>,
    pub bitmap: Vec<u8>,
}

// IEEE 802.11 Data Frame Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Data {
    pub addr4: Option<Value<MacAddr>>, // Only present if ToDS and FromDS are both set
    #[nproto(encode = encode_qos_control, decode = decode_qos_control)]
    pub qos_control: Option<Value<u16>>, // Only present in QoS data frames
    #[nproto(encode = encode_ht_control, decode = decode_ht_control)]
    pub ht_control: Option<Value<u32>>, // Only present if Order bit is set
    pub payload: Vec<u8>, // Data payload
}

fn encode_qos_control<E: Encoder>(
    my_layer: &Dot11Data,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(qos_control) = &my_layer.qos_control {
        qos_control.value().encode::<E>()
    } else {
        vec![]
    }
}

fn decode_qos_control<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11Data,
) -> Option<(Option<Value<u16>>, usize)> {
    // This should be used conditionally based on frame subtype
    // The caller should determine if QoS field is present
    if ci + 2 <= buf.len() {
        let buf = &buf[ci..];
        if let Some((qos, size)) = u16::decode::<D>(buf) {
            return Some((Some(Value::Set(qos)), size));
        }
    }
    Some((None, 0))
}

fn encode_ht_control<E: Encoder>(
    my_layer: &Dot11Data,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    if let Some(ht_control) = &my_layer.ht_control {
        ht_control.value().encode::<E>()
    } else {
        vec![]
    }
}

fn decode_ht_control<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11Data,
) -> Option<(Option<Value<u32>>, usize)> {
    // This should be used conditionally based on Order bit
    // The caller should determine if HT Control field is present
    if ci + 4 <= buf.len() {
        let buf = &buf[ci..];
        if let Some((ht, size)) = u32::decode::<D>(buf) {
            return Some((Some(Value::Set(ht)), size));
        }
    }
    Some((None, 0))
}

// Create a decoder for all 802.11 frame types
pub fn decode_dot11_frame(buf: &[u8]) -> Option<(LayerStack, usize)> {
    // First decode the Dot11 header to get the frame control field
    let dot11 = Dot11::default();
    if let Some((mut dot11_decoded, mut offset)) = dot11.decode_with_decoder::<BinaryBigEndian>(buf) {
        if let Some(dot11_layer) = dot11_decoded.layers.first() {
            if let Some(dot11) = dot11_layer.downcast_ref::<Dot11>() {
                let fc = dot11.frame_control.value();
                
                match fc.frame_type {
                    // Management frames
                    frame_types::MANAGEMENT => {
                        match fc.frame_subtype {
                            frame_types::BEACON => {
                                let beacon = Dot11Beacon::default();
                                if let Some((beacon_decoded, beacon_offset)) = beacon.decode_with_decoder::<BinaryBigEndian>(&buf[offset..]) {
                                    dot11_decoded.layers.extend(beacon_decoded.layers);
                                    offset += beacon_offset;
                                }
                            },
                            frame_types::PROBE_REQ => {
                                let probe_req = Dot11ProbeReq::default();
                                if let Some((probe_req_decoded, probe_req_offset)) = probe_req.decode_with_decoder::<BinaryBigEndian>(&buf[offset..]) {
                                    dot11_decoded.layers.extend(probe_req_decoded.layers);
                                    offset += probe_req_offset;
                                }
                            },
                            frame_types::PROBE_RESP => {
                                let probe_resp = Dot11ProbeResp::default();
                                if let Some((probe_resp_decoded, probe_resp_offset)) = probe_resp.decode_with_decoder::<BinaryBigEndian>(&buf[offset..]) {
                                    dot11_decoded.layers.extend(probe_resp_decoded.layers);
                                    offset += probe_resp_offset;
                                }
                            },
                            frame_types::ASSOC_REQ => {
                                let assoc_req = Dot11AssocReq::default();
                                if let Some((assoc_req_decoded, assoc_req_offset)) = assoc_req.decode_with_decoder::<BinaryBigEndian>(&buf[offset..]) {
                                    dot11_decoded.layers.extend(assoc_req_decoded.layers);
                                    offset += assoc_req_offset;
                                }
                            },
                            frame_types::ASSOC

// Helper functions for creating common management frames

// Create a beacon frame
pub fn create_beacon(
    src_mac: MacAddr,
    bssid: MacAddr,
    ssid: &str,
    channel: u8,
    capabilities: CapabilitiesInfo,
    beacon_interval: u16,
) -> LayerStack {
    // Create the Dot11 header
    let mut dot11 = Dot11::default();
    let fc = FrameControl::new(0, frame_types::MANAGEMENT, frame_types::BEACON, false, false, false, false, false, false, false, false);
    dot11 = dot11.frame_control(fc);
    dot11 = dot11.addr1(MacAddr::new(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)); // Broadcast
    dot11 = dot11.addr2(src_mac.clone());
    dot11 = dot11.addr3(bssid.clone());
    dot11 = dot11.seq_control(0); // Sequence number and fragment number

    // Create the beacon frame
    let mut beacon = Dot11Beacon::default();
    beacon = beacon.timestamp(0); // Will be filled by the hardware
    beacon = beacon.beacon_interval(beacon_interval);
    beacon = beacon.capabilities(capabilities);

    // Add elements
    let mut elements = Vec::new();
    
    // SSID
    elements.push(ParsedElement::SSID(ssid.to_string()));
    
    // Supported rates
    elements.push(ParsedElement::SupportedRates(vec![0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]));
    
    // DS Parameter (channel)
    elements.push(ParsedElement::DSParameter(channel));
    
    beacon = beacon.set_elements(elements);

    // Build the layerstack
    dot11.to_stack() / beacon
}

// Create a probe response frame
pub fn create_probe_response(
    dst_mac: MacAddr,
    src_mac: MacAddr,
    bssid: MacAddr,
    ssid: &str,
    channel: u8,
    capabilities: CapabilitiesInfo,
    beacon_interval: u16,
) -> LayerStack {
    // Create the Dot11 header
    let mut dot11 = Dot11::default();
    let fc = FrameControl::new(0, frame_types::MANAGEMENT, frame_types::PROBE_RESP, false, false, false, false, false, false, false, false);
    dot11 = dot11.frame_control(fc);
    dot11 = dot11.addr1(dst_mac);
    dot11 = dot11.addr2(src_mac.clone());
    dot11 = dot11.addr3(bssid.clone());
    dot11 = dot11.seq_control(0); // Sequence number and fragment number

    // Create the probe response frame
    let mut probe_resp = Dot11ProbeResp::default();
    probe_resp = probe_resp.timestamp(0); // Will be filled by the hardware
    probe_resp = probe_resp.beacon_interval(beacon_interval);
    probe_resp = probe_resp.capabilities(capabilities);

    // Add elements
    let mut elements = Vec::new();
    
    // SSID
    elements.push(ParsedElement::SSID(ssid.to_string()));
    
    // Supported rates
    elements.push(ParsedElement::SupportedRates(vec![0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C]));
    
    // DS Parameter (channel)
    elements.push(ParsedElement::DSParameter(channel));
    
    probe_resp = probe_resp.set_elements(elements);

    // Build the layerstack
    dot11.to_stack() / probe_resp
}

// Helper functions for parsing and working with elements

// Extract the SSID from a beacon or probe response
pub fn get_ssid(elements: &[ParsedElement]) -> Option<String> {
    for element in elements {
        if let ParsedElement::SSID(ssid) = element {
            return Some(ssid.clone());
        }
    }
    None
}

// Extract the channel from a beacon or probe response
pub fn get_channel(elements: &[ParsedElement]) -> Option<u8> {
    for element in elements {
        if let ParsedElement::DSParameter(channel) = element {
            return Some(*channel);
        }
    }
    None
}

// Extract the supported rates from a beacon or probe response
pub fn get_supported_rates(elements: &[ParsedElement]) -> Vec<u8> {
    let mut rates = Vec::new();
    
    for element in elements {
        if let ParsedElement::SupportedRates(r) = element {
            rates.extend_from_slice(r);
        } else if let ParsedElement::ExtendedRates(r) = element {
            rates.extend_from_slice(r);
        }
    }
    
    rates
}

// Check if a network is using encryption
pub fn is_encrypted(capabilities: &CapabilitiesInfo, elements: &[ParsedElement]) -> bool {
    // Check the privacy bit in the capabilities
    if capabilities.privacy {
        return true;
    }
    
    // Check for RSN element
    for element in elements {
        if let ParsedElement::RSN(_) = element {
            return true;
        }
    }
    
    // Check for WPA in vendor specific elements
    for element in elements {
        if let ParsedElement::VendorSpecific(vendor) = element {
            // WPA OUI is 00:50:F2
            if vendor.oui == [0x00, 0x50, 0xF2] && vendor.vendor_type == 0x01 {
                return true;
            }
        }
    }
    
    false
}

// Extract the security type (Open, WEP, WPA, WPA2, WPA3) from a beacon or probe response
pub fn get_security_type(capabilities: &CapabilitiesInfo, elements: &[ParsedElement]) -> &'static str {
    if !capabilities.privacy {
        // No encryption
        return "Open";
    }
    
    let mut has_rsn = false;
    let mut has_wpa = false;
    let mut has_wpa3 = false;
    
    for element in elements {
        match element {
            ParsedElement::RSN(rsn) => {
                has_rsn = true;
                
                // Check for WPA3 (SAE authentication)
                for akm in &rsn.akm_suites {
                    // IEEE 802.11 OUI is 00:0F:AC
                    if akm.oui == [0x00, 0x0F, 0xAC] {
                        // SAE is suite type 8
                        if akm.suite_type == 8 {
                            has_wpa3 = true;
                            break;
                        }
                    }
                }
            },
            ParsedElement::VendorSpecific(vendor) => {
                // WPA OUI is 00:50:F2
                if vendor.oui == [0x00, 0x50, 0xF2] && vendor.vendor_type == 0x01 {
                    has_wpa = true;
                }
            },
            _ => {}
        }
    }
    
    if has_wpa3 {
        "WPA3"
    } else if has_rsn {
        "WPA2"
    } else if has_wpa {
        "WPA"
    } else {
        "WEP"
    }
}
>,
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
