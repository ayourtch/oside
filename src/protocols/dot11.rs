/*
Warning: This protocol is a work in progress. The results may vary.
*/

use crate::encdec::binary_little_endian::BinaryLittleEndian;

// Scan a PCAP file for 802.11 beacon frames and return a list of networks
pub fn scan_pcap_for_networks(pcap_data: &[u8]) -> Vec<NetworkInfo> {
    use std::collections::HashMap;

    let mut networks: HashMap<String, NetworkInfo> = HashMap::new();
    let mut current_pos = 0;

    // PCAP global header is at least 24 bytes
    if pcap_data.len() < 24 {
        return Vec::new();
    }

    // Verify PCAP magic number
    let magic = u32::from_le_bytes([pcap_data[0], pcap_data[1], pcap_data[2], pcap_data[3]]);
    let is_little_endian = magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1;

    if !is_little_endian {
        return Vec::new(); // Not a valid PCAP file
    }

    // Skip global header
    current_pos += 24;

    // Process each packet
    while current_pos + 16 <= pcap_data.len() {
        // Read packet header
        let ts_sec = u32::from_le_bytes([
            pcap_data[current_pos],
            pcap_data[current_pos + 1],
            pcap_data[current_pos + 2],
            pcap_data[current_pos + 3],
        ]);

        let incl_len = u32::from_le_bytes([
            pcap_data[current_pos + 8],
            pcap_data[current_pos + 9],
            pcap_data[current_pos + 10],
            pcap_data[current_pos + 11],
        ]) as usize;

        // Move to packet data
        current_pos += 16;

        if current_pos + incl_len > pcap_data.len() {
            break;
        }

        // Get packet data
        let packet_data = &pcap_data[current_pos..current_pos + incl_len];

        // Try to decode as 802.11 frame
        if let Some((stack, _)) = decode_802_11_frame(packet_data) {
            // Look for beacon frames
            if let Some(beacon) = stack.get_layer(Dot11Beacon::default()) {
                if let Some(dot11) = stack.get_layer(Dot11::default()) {
                    // Extract BSSID (MAC address)
                    let bssid = dot11.addr3.as_ref().unwrap().value();

                    // Extract SSID
                    if let Some(ssid) = get_ssid(&beacon.elements) {
                        // Skip hidden SSIDs (empty or all zeros)
                        if ssid.is_empty() || ssid.bytes().all(|b| b == 0) {
                            current_pos += incl_len;
                            continue;
                        }

                        // Get channel
                        let channel = get_channel(&beacon.elements).unwrap_or(0);

                        // Get security type
                        let security =
                            get_security_type(&beacon.capabilities.value(), &beacon.elements);

                        // Get supported rates
                        let rates = get_supported_rates(&beacon.elements);
                        let max_rate = rates.iter().map(|&r| r & 0x7F).max().unwrap_or(0);

                        // Create or update network info
                        let network_key = format!("{} - {}", ssid, bssid);

                        if let Some(network) = networks.get_mut(&network_key) {
                            // Update the last seen timestamp
                            if ts_sec > network.last_seen {
                                network.last_seen = ts_sec;
                            }

                            // Update signal strength and count if we have radiotap header
                            if let Some(radiotap) = stack.get_layer(Radiotap::default()) {
                                for field in &radiotap.fields {
                                    if let RadiotapField::AntennaSignal(signal) = field {
                                        // Sum up signal strengths for averaging later
                                        network.signal_sum += *signal as i32;
                                        network.signal_count += 1;
                                    }
                                }
                            }
                        } else {
                            // Create a new network entry
                            let mut signal = 0;
                            let mut signal_count = 0;

                            // Get signal strength if we have radiotap header
                            if let Some(radiotap) = stack.get_layer(Radiotap::default()) {
                                for field in &radiotap.fields {
                                    if let RadiotapField::AntennaSignal(s) = field {
                                        signal = *s as i32;
                                        signal_count = 1;
                                        break;
                                    }
                                }
                            }

                            networks.insert(
                                network_key,
                                NetworkInfo {
                                    ssid: ssid.clone(),
                                    bssid: bssid.clone(),
                                    channel,
                                    security: security.to_string(),
                                    max_rate,
                                    first_seen: ts_sec,
                                    last_seen: ts_sec,
                                    signal_sum: signal,
                                    signal_strength: 0, // FIXME AYXX
                                    signal_count,
                                    is_privacy_enabled: beacon.capabilities.value().privacy,
                                },
                            );
                        }
                    }
                }
            }
        }

        // Move to next packet
        current_pos += incl_len;
    }

    // Convert HashMap to Vec and calculate average signal strength
    networks
        .into_values()
        .map(|mut network| {
            if network.signal_count > 0 {
                network.signal_strength = network.signal_sum / network.signal_count;
            }
            network
        })
        .collect()
}

// Network information structure for scan results
#[derive(Clone, Debug)]
pub struct NetworkInfo {
    pub ssid: String,
    pub bssid: MacAddr,
    pub channel: u8,
    pub security: String,
    pub max_rate: u8,
    pub first_seen: u32,
    pub last_seen: u32,
    pub signal_strength: i32, // Average signal strength in dBm
    pub signal_sum: i32,      // Internal use for calculating average
    pub signal_count: i32,    // Internal use for calculating average
    pub is_privacy_enabled: bool,
}

// Utility function to create a beacon frame with common elements
pub fn create_beacon_with_elements(
    src_mac: MacAddr,
    bssid: MacAddr,
    ssid: &str,
    channel: u8,
    supported_rates: Vec<u8>,
    interval: u16,
    capabilities: CapabilitiesInfo,
    additional_elements: Vec<ParsedElement>,
) -> LayerStack {
    // Create the Dot11 header
    let mut dot11 = Dot11::default();
    let fc = FrameControl::new(
        0,
        frame_types::MANAGEMENT,
        frame_types::BEACON,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    );
    dot11 = dot11.frame_control(fc);
    dot11 = dot11.addr1(MacAddr::new(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)); // Broadcast
    dot11 = dot11.addr2(Value::Set(src_mac.clone()));
    dot11 = dot11.addr3(Value::Set(bssid.clone()));
    dot11 = dot11.seq_control(Value::Set(0)); // Will be filled by hardware or driver

    // Create the beacon frame
    let mut beacon = Dot11Beacon::default();
    beacon = beacon.timestamp(0); // Will be filled by hardware or driver
    beacon = beacon.beacon_interval(interval);
    beacon = beacon.capabilities(capabilities);

    // Basic elements
    let mut elements = Vec::new();

    // Add SSID
    elements.push(ParsedElement::SSID(ssid.to_string()));

    // Add supported rates (up to 8 rates)
    let supported_rates_len = std::cmp::min(8, supported_rates.len());
    elements.push(ParsedElement::SupportedRates(
        supported_rates[0..supported_rates_len].to_vec(),
    ));

    // Add DS Parameter (channel)
    elements.push(ParsedElement::DSParameter(channel));

    // Add extended rates if we have more than 8 rates
    if supported_rates.len() > 8 {
        elements.push(ParsedElement::ExtendedRates(supported_rates[8..].to_vec()));
    }

    // Add additional elements
    elements.extend(additional_elements);

    beacon = beacon.set_elements(elements);

    // Build the layerstack
    dot11.to_stack() / beacon
}

// Create a WPA2-PSK network beacon
pub fn create_wpa2_beacon(
    src_mac: MacAddr,
    bssid: MacAddr,
    ssid: &str,
    channel: u8,
    interval: u16,
) -> LayerStack {
    // Create capabilities with Privacy bit set
    let mut capabilities = CapabilitiesInfo::default();
    capabilities.ess = true;
    capabilities.privacy = true;

    // Create RSN element for WPA2
    let group_cipher = CipherSuite {
        oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
        suite_type: 4,           // CCMP (AES)
    };

    let pairwise_cipher = CipherSuite {
        oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
        suite_type: 4,           // CCMP (AES)
    };

    let akm_suite = AKMSuite {
        oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
        suite_type: 2,           // PSK
    };

    let rsn = RSNElement {
        version: 1,
        group_cipher_suite: group_cipher,
        pairwise_cipher_suites: vec![pairwise_cipher],
        akm_suites: vec![akm_suite],
        rsn_capabilities: 0, // No special capabilities
        pmkid_count: None,
        pmkid_list: Vec::new(),
        group_management_cipher_suite: None,
    };

    // Standard rates for 802.11g
    let rates = vec![
        0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
    ];

    // Create beacon with RSN element
    create_beacon_with_elements(
        src_mac,
        bssid,
        ssid,
        channel,
        rates,
        interval,
        capabilities,
        vec![ParsedElement::RSN(rsn)],
    )
}

// Helper function to decode a packet and print detailed information
pub fn print_packet_details(packet_data: &[u8]) -> String {
    let mut output = String::new();

    if let Some((stack, _)) = decode_802_11_frame(packet_data) {
        // Print Radiotap header if present
        if let Some(radiotap) = stack.get_layer(Radiotap::default()) {
            output.push_str("Radiotap Header:\n");
            output.push_str(&format!("  Version: {}\n", radiotap.version.value()));
            output.push_str(&format!("  Length: {} bytes\n", radiotap.length.value()));
            for fff in &radiotap.present_flags {
                output.push_str(&format!("  Present flags: 0x{:08x}\n", fff));
            }

            for field in &radiotap.fields {
                match field {
                    RadiotapField::TSFT(tsft) => {
                        output.push_str(&format!("  TSFT: {} μs\n", tsft));
                    }
                    RadiotapField::Flags(flags) => {
                        output.push_str(&format!("  Flags: 0x{:02x}\n", flags));
                        if (flags & 0x01) != 0 {
                            output.push_str("    - CFP\n");
                        }
                        if (flags & 0x02) != 0 {
                            output.push_str("    - Preamble: Short\n");
                        }
                        if (flags & 0x04) != 0 {
                            output.push_str("    - WEP Encrypted\n");
                        }
                        if (flags & 0x08) != 0 {
                            output.push_str("    - Fragmented\n");
                        }
                        if (flags & 0x10) != 0 {
                            output.push_str("    - FCS included\n");
                        }
                    }
                    RadiotapField::Rate(rate) => {
                        output.push_str(&format!("  Rate: {}.{} Mbps\n", rate / 2, (rate % 2) * 5));
                    }
                    RadiotapField::Channel(freq, flags) => {
                        output.push_str(&format!("  Channel:\n"));
                        output.push_str(&format!("    Frequency: {} MHz\n", freq));
                        output.push_str(&format!("    Flags: 0x{:04x}\n", flags));
                        if (flags & 0x0001) != 0 {
                            output.push_str("      - Turbo\n");
                        }
                        if (flags & 0x0002) != 0 {
                            output.push_str("      - CCK\n");
                        }
                        if (flags & 0x0004) != 0 {
                            output.push_str("      - OFDM\n");
                        }
                        if (flags & 0x0008) != 0 {
                            output.push_str("      - 2 GHz\n");
                        }
                        if (flags & 0x0010) != 0 {
                            output.push_str("      - 5 GHz\n");
                        }
                    }
                    RadiotapField::AntennaSignal(signal) => {
                        output.push_str(&format!("  Antenna Signal: {} dBm\n", signal));
                    }
                    RadiotapField::AntennaNoise(noise) => {
                        output.push_str(&format!("  Antenna Noise: {} dBm\n", noise));
                    }
                    RadiotapField::Antenna(antenna) => {
                        output.push_str(&format!("  Antenna: {}\n", antenna));
                    }
                    _ => {}
                }
            }
        }

        // Print 802.11 header
        if let Some(dot11) = stack.get_layer(Dot11::default()) {
            let fc = dot11.frame_control.value();
            output.push_str("\n802.11 Header:\n");
            output.push_str(&format!("  Frame Control: 0x{:04x}\n", fc.to_raw()));
            output.push_str(&format!("    Protocol Version: {}\n", fc.protocol_version));

            output.push_str(&format!(
                "    Type: {}\n",
                match fc.frame_type {
                    frame_types::MANAGEMENT => "Management",
                    frame_types::CONTROL => "Control",
                    frame_types::DATA => "Data",
                    frame_types::EXTENSION => "Extension",
                    _ => "Unknown",
                }
            ));

            output.push_str(&format!("    Subtype: {}\n", fc.frame_subtype));

            output.push_str(&format!("    Flags:"));
            if fc.to_ds {
                output.push_str(" ToDS");
            }
            if fc.from_ds {
                output.push_str(" FromDS");
            }
            if fc.more_fragments {
                output.push_str(" MoreFrag");
            }
            if fc.retry {
                output.push_str(" Retry");
            }
            if fc.power_management {
                output.push_str(" PwrMgmt");
            }
            if fc.more_data {
                output.push_str(" MoreData");
            }
            if fc.protected {
                output.push_str(" Protected");
            }
            if fc.order {
                output.push_str(" Order");
            }
            output.push_str("\n");

            output.push_str(&format!("  Duration: {} μs\n", dot11.duration.value()));
            output.push_str(&format!("  Address 1: {}\n", dot11.addr1.value()));
            output.push_str(&format!("  Address 2: {}\n", dot11.addr2.as_ref().unwrap().value()));
            output.push_str(&format!("  Address 3: {}\n", dot11.addr3.as_ref().unwrap().value()));

            let seq_num = (dot11.seq_control.as_ref().unwrap().value() >> 4) & 0x0FFF;
            let frag_num = dot11.seq_control.as_ref().unwrap().value() & 0x000F;
            output.push_str(&format!(
                "  Sequence: {}, Fragment: {}\n",
                seq_num, frag_num
            ));
        }

        // Print Beacon information
        if let Some(beacon) = stack.get_layer(Dot11Beacon::default()) {
            output.push_str("\nBeacon Frame:\n");
            output.push_str(&format!("  Timestamp: {}\n", beacon.timestamp.value()));
            output.push_str(&format!(
                "  Interval: {} TU ({} ms)\n",
                beacon.beacon_interval.value(),
                beacon.beacon_interval.value() * 1024 / 1000
            ));

            let caps = beacon.capabilities.value();
            output.push_str(&format!("  Capabilities: 0x{:04x}\n", caps.to_raw()));
            output.push_str(&format!(
                "    Infrastructure: {}\n",
                if caps.ess {
                    "ESS"
                } else if caps.ibss {
                    "IBSS"
                } else {
                    "Unknown"
                }
            ));
            output.push_str(&format!(
                "    Privacy: {}\n",
                if caps.privacy { "Enabled" } else { "Disabled" }
            ));
            output.push_str(&format!(
                "    Short Preamble: {}\n",
                if caps.short_preamble { "Yes" } else { "No" }
            ));
            output.push_str(&format!(
                "    Short Slot Time: {}\n",
                if caps.short_slot_time { "Yes" } else { "No" }
            ));

            output.push_str("\n  Information Elements:\n");
            for element in &beacon.elements {
                match element {
                    ParsedElement::SSID(ssid) => {
                        output.push_str(&format!("    SSID: {}\n", ssid));
                    }
                    ParsedElement::SupportedRates(rates) => {
                        output.push_str("    Supported Rates:");
                        for &rate in rates {
                            let basic = (rate & 0x80) != 0;
                            let rate_val = (rate & 0x7F) / 2;
                            let decimal = if (rate & 0x01) != 0 { ".5" } else { "" };
                            if basic {
                                output.push_str(&format!(" *{}{}", rate_val, decimal));
                            } else {
                                output.push_str(&format!(" {}{}", rate_val, decimal));
                            }
                        }
                        output.push_str(" Mbps\n");
                    }
                    ParsedElement::DSParameter(channel) => {
                        output.push_str(&format!("    DS Parameter - Channel: {}\n", channel));
                    }
                    ParsedElement::TIM(tim) => {
                        output.push_str(&format!(
                            "    TIM: DTIM Count: {}, DTIM Period: {}\n",
                            tim.dtim_count, tim.dtim_period
                        ));
                    }
                    ParsedElement::Country(country) => {
                        let country_code = String::from_utf8_lossy(&country.country_code);
                        output.push_str(&format!("    Country: {}\n", country_code));
                        for triplet in &country.triplets {
                            output.push_str(&format!(
                                "      Channels {}-{}, Max TX Power: {} dBm\n",
                                triplet.first_channel,
                                triplet.first_channel + triplet.num_channels - 1,
                                triplet.max_tx_power
                            ));
                        }
                    }
                    ParsedElement::RSN(rsn) => {
                        output.push_str(&format!("    RSN Information:\n"));
                        output.push_str(&format!("      Version: {}\n", rsn.version));

                        // Group Cipher
                        let group_suite_type = match rsn.group_cipher_suite.suite_type {
                            0 => "Use Group Cipher Suite",
                            1 => "WEP-40",
                            2 => "TKIP",
                            4 => "CCMP (AES)",
                            5 => "WEP-104",
                            _ => "Unknown",
                        };
                        output.push_str(&format!("      Group Cipher: {}\n", group_suite_type));

                        // Pairwise Ciphers
                        output.push_str(&format!(
                            "      Pairwise Ciphers ({}):\n",
                            rsn.pairwise_cipher_suites.len()
                        ));
                        for suite in &rsn.pairwise_cipher_suites {
                            let suite_type = match suite.suite_type {
                                0 => "Use Group Cipher Suite",
                                1 => "WEP-40",
                                2 => "TKIP",
                                4 => "CCMP (AES)",
                                5 => "WEP-104",
                                _ => "Unknown",
                            };
                            output.push_str(&format!("        {}\n", suite_type));
                        }

                        // AKM Suites
                        output.push_str(&format!(
                            "      Authentication Key Management ({}):\n",
                            rsn.akm_suites.len()
                        ));
                        for suite in &rsn.akm_suites {
                            let suite_type = match suite.suite_type {
                                1 => "802.1X",
                                2 => "PSK",
                                3 => "FT-802.1X",
                                4 => "FT-PSK",
                                5 => "802.1X-SHA256",
                                6 => "PSK-SHA256",
                                7 => "TDLS",
                                8 => "SAE",
                                9 => "FT-SAE",
                                _ => "Unknown",
                            };
                            output.push_str(&format!("        {}\n", suite_type));
                        }
                    }
                    ParsedElement::VendorSpecific(vendor) => {
                        output.push_str(&format!(
                            "    Vendor Specific: OUI: {:02x}:{:02x}:{:02x}, Type: {}\n",
                            vendor.oui[0], vendor.oui[1], vendor.oui[2], vendor.vendor_type
                        ));

                        // Check if this is a WPA element (OUI: 00:50:F2, Type: 01)
                        if vendor.oui == [0x00, 0x50, 0xF2]
                            && vendor.vendor_type == 1
                            && vendor.data.len() >= 6
                        {
                            output.push_str("      WPA Information:\n");

                            // Skip version (2 bytes)
                            let mut offset = 2;

                            // Group Cipher Suite
                            if offset + 4 <= vendor.data.len() {
                                let group_oui = [
                                    vendor.data[offset],
                                    vendor.data[offset + 1],
                                    vendor.data[offset + 2],
                                ];
                                let group_suite_type = vendor.data[offset + 3];

                                let suite_type_str = match group_suite_type {
                                    1 => "WEP-40",
                                    2 => "TKIP",
                                    4 => "CCMP (AES)",
                                    5 => "WEP-104",
                                    _ => "Unknown",
                                };

                                output.push_str(&format!(
                                    "        Group Cipher: {}\n",
                                    suite_type_str
                                ));
                                offset += 4;

                                // Pairwise Cipher Suite Count
                                if offset + 2 <= vendor.data.len() {
                                    let count = u16::from_le_bytes([
                                        vendor.data[offset],
                                        vendor.data[offset + 1],
                                    ]) as usize;
                                    offset += 2;

                                    output.push_str(&format!(
                                        "        Pairwise Ciphers ({}):\n",
                                        count
                                    ));

                                    // Pairwise Cipher Suites
                                    for i in 0..count {
                                        if offset + 4 <= vendor.data.len() {
                                            let oui = [
                                                vendor.data[offset],
                                                vendor.data[offset + 1],
                                                vendor.data[offset + 2],
                                            ];
                                            let suite_type = vendor.data[offset + 3];

                                            let suite_type_str = match suite_type {
                                                1 => "WEP-40",
                                                2 => "TKIP",
                                                4 => "CCMP (AES)",
                                                5 => "WEP-104",
                                                _ => "Unknown",
                                            };

                                            output.push_str(&format!(
                                                "          {}\n",
                                                suite_type_str
                                            ));
                                            offset += 4;
                                        }
                                    }

                                    // AKM Suite Count
                                    if offset + 2 <= vendor.data.len() {
                                        let count = u16::from_le_bytes([
                                            vendor.data[offset],
                                            vendor.data[offset + 1],
                                        ])
                                            as usize;
                                        offset += 2;

                                        output.push_str(&format!(
                                            "        Authentication Key Management ({}):\n",
                                            count
                                        ));

                                        // AKM Suites
                                        for i in 0..count {
                                            if offset + 4 <= vendor.data.len() {
                                                let oui = [
                                                    vendor.data[offset],
                                                    vendor.data[offset + 1],
                                                    vendor.data[offset + 2],
                                                ];
                                                let suite_type = vendor.data[offset + 3];

                                                let suite_type_str = match suite_type {
                                                    1 => "802.1X",
                                                    2 => "PSK",
                                                    _ => "Unknown",
                                                };

                                                output.push_str(&format!(
                                                    "          {}\n",
                                                    suite_type_str
                                                ));
                                                offset += 4;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Print Probe Request information
        if let Some(probe_req) = stack.get_layer(Dot11ProbeReq::default()) {
            output.push_str("\nProbe Request:\n");

            for element in &probe_req.elements {
                if let ParsedElement::SSID(ssid) = element {
                    output.push_str(&format!("  Requested SSID: {}\n", ssid));
                }
            }
        }

        // Print Probe Response information
        if let Some(probe_resp) = stack.get_layer(Dot11ProbeResp::default()) {
            output.push_str("\nProbe Response:\n");
            output.push_str(&format!("  Timestamp: {}\n", probe_resp.timestamp.value()));
            output.push_str(&format!(
                "  Interval: {} TU ({} ms)\n",
                probe_resp.beacon_interval.value(),
                probe_resp.beacon_interval.value() * 1024 / 1000
            ));

            let caps = probe_resp.capabilities.value();
            output.push_str(&format!("  Capabilities: 0x{:04x}\n", caps.to_raw()));

            output.push_str("\n  Information Elements:\n");
            for element in &probe_resp.elements {
                if let ParsedElement::SSID(ssid) = element {
                    output.push_str(&format!("    SSID: {}\n", ssid));
                }
            }
        }

        // Print Association Request information
        if let Some(assoc_req) = stack.get_layer(Dot11AssocReq::default()) {
            output.push_str("\nAssociation Request:\n");

            let caps = assoc_req.capabilities.value();
            output.push_str(&format!("  Capabilities: 0x{:04x}\n", caps.to_raw()));
            output.push_str(&format!(
                "  Listen Interval: {}\n",
                assoc_req.listen_interval.value()
            ));

            output.push_str("\n  Information Elements:\n");
            for element in &assoc_req.elements {
                if let ParsedElement::SSID(ssid) = element {
                    output.push_str(&format!("    SSID: {}\n", ssid));
                }
            }
        }

        // Print Authentication Frame information
        if let Some(auth) = stack.get_layer(Dot11Auth::default()) {
            output.push_str("\nAuthentication Frame:\n");

            let auth_alg = match auth.auth_algorithm.value() {
                0 => "Open System",
                1 => "Shared Key",
                2 => "Fast BSS Transition",
                3 => "SAE",
                _ => "Unknown",
            };

            output.push_str(&format!(
                "  Authentication Algorithm: {} ({})\n",
                auth.auth_algorithm.value(),
                auth_alg
            ));
            output.push_str(&format!(
                "  Authentication Sequence: {}\n",
                auth.auth_seq.value()
            ));

            let status = match auth.status_code.value() {
                0 => "Success",
                1 => "Failure",
                10 => "Cannot support all requested capabilities",
                11 => "Reassociation denied, could not confirm association exists",
                12 => "Association denied for reason outside standard",
                13 => "Responding station does not support authentication algorithm",
                14 => "Received an authentication frame with unexpected sequence number",
                15 => "Authentication rejected, challenge failure",
                16 => "Authentication rejected, timeout",
                17 => "Association denied, too many stations",
                18 => "Basic rate support denied",
                _ => "Unknown",
            };

            output.push_str(&format!(
                "  Status Code: {} ({})\n",
                auth.status_code.value(),
                status
            ));
        }

        // Print Data Frame information
        /* FIXME AYXX
        if let Some(data) = stack.get_layer(Dot11Data::default()) {
            output.push_str("\nData Frame:\n");

            if let Some(addr4) = &data.addr4 {
                output.push_str(&format!("  Address 4: {}\n", addr4.value()));
            }

            if let Some(qos) = &data.qos_control {
                output.push_str(&format!("  QoS Control: 0x{:04x}\n", qos.value()));

                let tid = qos.value() & 0x000F;
                let eosp = (qos.value() & 0x0010) != 0;
                let ack_policy = (qos.value() >> 5) & 0x0003;

                output.push_str(&format!("    TID: {}\n", tid));
                output.push_str(&format!("    End of Service Period: {}\n", eosp));

                let ack_str = match ack_policy {
                    0 => "Normal ACK",
                    1 => "No ACK",
                    2 => "No explicit ACK",
                    3 => "Block ACK",
                    _ => "Unknown",
                };

                output.push_str(&format!("    ACK Policy: {}\n", ack_str));
            }

            if let Some(ht) = &data.ht_control {
                output.push_str(&format!("  HT Control: 0x{:08x}\n", ht.value()));
            }

            output.push_str(&format!("  Data Length: {} bytes\n", data.payload.len()));
        }
        */

        // Print FCS if present
        if let Some(fcs) = stack.get_layer(Dot11FCS::default()) {
            output.push_str(&format!("\nFCS: 0x{:08x}\n", fcs.fcs.value()));
        }
    } else {
        output.push_str("Failed to decode 802.11 frame");
    }

    output
}

// Helper function to create a WPA beacon
pub fn create_wpa_beacon(
    src_mac: MacAddr,
    bssid: MacAddr,
    ssid: &str,
    channel: u8,
    interval: u16,
) -> LayerStack {
    // Create capabilities with Privacy bit set
    let mut capabilities = CapabilitiesInfo::default();
    capabilities.ess = true;
    capabilities.privacy = true;

    // Create WPA Vendor Specific element
    let mut wpa_data = Vec::new();

    // Version
    wpa_data.extend_from_slice(&[0x01, 0x00]); // Version 1

    // Group Cipher Suite
    wpa_data.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // TKIP

    // Pairwise Cipher Suite Count
    wpa_data.extend_from_slice(&[0x01, 0x00]); // 1 suite

    // Pairwise Cipher Suite
    wpa_data.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // TKIP

    // AKM Suite Count
    wpa_data.extend_from_slice(&[0x01, 0x00]); // 1 suite

    // AKM Suite
    wpa_data.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // PSK

    let wpa_element = VendorSpecificElement {
        oui: [0x00, 0x50, 0xF2], // Microsoft OUI
        vendor_type: 1,          // WPA IE
        data: wpa_data,
    };

    // Standard rates for 802.11g
    let rates = vec![
        0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
    ];

    // Create beacon with WPA element
    create_beacon_with_elements(
        src_mac,
        bssid,
        ssid,
        channel,
        rates,
        interval,
        capabilities,
        vec![ParsedElement::VendorSpecific(wpa_element)],
    )
}

// Helper function to create a hidden SSID beacon
pub fn create_hidden_ssid_beacon(
    src_mac: MacAddr,
    bssid: MacAddr,
    channel: u8,
    interval: u16,
    security_type: &str,
) -> LayerStack {
    let mut capabilities = CapabilitiesInfo::default();
    capabilities.ess = true;

    let mut additional_elements = Vec::new();

    if security_type == "WPA" || security_type == "WPA2" || security_type == "WPA3" {
        capabilities.privacy = true;

        if security_type == "WPA" {
            // Add WPA vendor element
            let mut wpa_data = Vec::new();
            wpa_data.extend_from_slice(&[0x01, 0x00]); // Version 1
            wpa_data.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // TKIP
            wpa_data.extend_from_slice(&[0x01, 0x00]); // 1 pairwise suite
            wpa_data.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // TKIP
            wpa_data.extend_from_slice(&[0x01, 0x00]); // 1 AKM suite
            wpa_data.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // PSK

            let wpa_element = VendorSpecificElement {
                oui: [0x00, 0x50, 0xF2], // Microsoft OUI
                vendor_type: 1,          // WPA IE
                data: wpa_data,
            };

            additional_elements.push(ParsedElement::VendorSpecific(wpa_element));
        } else if security_type == "WPA2" || security_type == "WPA3" {
            // Create RSN element
            let mut rsn = RSNElement {
                version: 1,
                group_cipher_suite: CipherSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 4,           // CCMP (AES)
                },
                pairwise_cipher_suites: vec![CipherSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 4,           // CCMP (AES)
                }],
                akm_suites: Vec::new(),
                rsn_capabilities: 0,
                pmkid_count: None,
                pmkid_list: Vec::new(),
                group_management_cipher_suite: None,
            };

            if security_type == "WPA2" {
                rsn.akm_suites.push(AKMSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 2,           // PSK
                });
            } else {
                // WPA3
                rsn.akm_suites.push(AKMSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 8,           // SAE
                });
            }

            additional_elements.push(ParsedElement::RSN(rsn));
        }
    }

    // Standard rates for 802.11g
    let rates = vec![
        0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
    ];

    // Create beacon with empty SSID
    create_beacon_with_elements(
        src_mac,
        bssid,
        "", // Empty SSID for hidden network
        channel,
        rates,
        interval,
        capabilities,
        additional_elements,
    )
}

// Helper function to create a collection of beacon frames from different networks
pub fn create_network_simulation(networks: &[(&str, u8, &str)]) -> Vec<LayerStack> {
    let mut beacons = Vec::new();

    for (i, &(ssid, channel, security_type)) in networks.iter().enumerate() {
        // Create a unique MAC address for each network
        let mac_bytes = [0x12, 0x34, 0x56, 0x78, 0x90, i as u8];
        let mac = MacAddr::from(mac_bytes);

        // Create the appropriate beacon based on security type
        let beacon = match security_type {
            "Open" => {
                let mut capabilities = CapabilitiesInfo::default();
                capabilities.ess = true;

                // Standard rates for 802.11g
                let rates = vec![
                    0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
                ];

                create_beacon_with_elements(
                    mac.clone(),
                    mac.clone(),
                    ssid,
                    channel,
                    rates,
                    100, // 100 TU = ~102.4ms
                    capabilities,
                    Vec::new(),
                )
            }
            "WEP" => {
                let mut capabilities = CapabilitiesInfo::default();
                capabilities.ess = true;
                capabilities.privacy = true;

                // Standard rates for 802.11g
                let rates = vec![
                    0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
                ];

                create_beacon_with_elements(
                    mac.clone(),
                    mac.clone(),
                    ssid,
                    channel,
                    rates,
                    100, // 100 TU = ~102.4ms
                    capabilities,
                    Vec::new(),
                )
            }
            "WPA" => {
                create_wpa_beacon(
                    mac.clone(),
                    mac.clone(),
                    ssid,
                    channel,
                    100, // 100 TU = ~102.4ms
                )
            }
            "WPA2" => {
                create_wpa2_beacon(
                    mac.clone(),
                    mac.clone(),
                    ssid,
                    channel,
                    100, // 100 TU = ~102.4ms
                )
            }
            "WPA3" => {
                // Create capabilities with Privacy bit set
                let mut capabilities = CapabilitiesInfo::default();
                capabilities.ess = true;
                capabilities.privacy = true;

                // Create RSN element for WPA3
                let group_cipher = CipherSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 4,           // CCMP (AES)
                };

                let pairwise_cipher = CipherSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 4,           // CCMP (AES)
                };

                let akm_suite = AKMSuite {
                    oui: [0x00, 0x0F, 0xAC], // IEEE 802.11 OUI
                    suite_type: 8,           // SAE (WPA3)
                };

                let rsn = RSNElement {
                    version: 1,
                    group_cipher_suite: group_cipher,
                    pairwise_cipher_suites: vec![pairwise_cipher],
                    akm_suites: vec![akm_suite],
                    rsn_capabilities: 0, // No special capabilities
                    pmkid_count: None,
                    pmkid_list: Vec::new(),
                    group_management_cipher_suite: None,
                };

                // Standard rates for 802.11g
                let rates = vec![
                    0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
                ];

                create_beacon_with_elements(
                    mac.clone(),
                    mac.clone(),
                    ssid,
                    channel,
                    rates,
                    100, // 100 TU = ~102.4ms
                    capabilities,
                    vec![ParsedElement::RSN(rsn)],
                )
            }
            "Hidden" => {
                create_hidden_ssid_beacon(
                    mac.clone(),
                    mac.clone(),
                    channel,
                    100, // 100 TU = ~102.4ms
                    "WPA2",
                )
            }
            _ => {
                // Default to Open
                let mut capabilities = CapabilitiesInfo::default();
                capabilities.ess = true;

                // Standard rates for 802.11g
                let rates = vec![
                    0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6C,
                ];

                create_beacon_with_elements(
                    mac.clone(),
                    mac.clone(),
                    ssid,
                    channel,
                    rates,
                    100, // 100 TU = ~102.4ms
                    capabilities,
                    Vec::new(),
                )
            }
        };

        beacons.push(beacon);
    }

    beacons
}

// Convert WlanType (frequency band) to string representation
pub fn wlan_type_to_string(channel: u8) -> &'static str {
    if channel <= 14 {
        "802.11b/g/n (2.4 GHz)"
    } else if channel >= 36 {
        "802.11a/n/ac/ax (5 GHz)"
    } else {
        "Unknown"
    }
}

// Convert channel number to frequency in MHz
pub fn channel_to_frequency(channel: u8) -> u16 {
    if channel <= 14 {
        // 2.4 GHz band
        if channel == 14 {
            2484 // Special case for channel 14
        } else {
            2407 + channel as u16 * 5
        }
    } else if channel >= 36 && channel <= 165 {
        // 5 GHz band
        5000 + channel as u16 * 5
    } else {
        0 // Invalid channel
    }
}

// Convert frequency in MHz to channel number
pub fn frequency_to_channel(frequency: u16) -> u8 {
    if frequency >= 2412 && frequency <= 2472 {
        // 2.4 GHz band, channels 1-13
        ((frequency - 2407) / 5) as u8
    } else if frequency == 2484 {
        // Channel 14
        14
    } else if frequency >= 5180 && frequency <= 5825 {
        // 5 GHz band
        ((frequency - 5000) / 5) as u8
    } else {
        0 // Unknown frequency
    }
}
use crate::typ::string::FixedSizeString;
use crate::*;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
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
    FHParameterSet = 2,
    DSParameter = 3,
    CFParameter = 4,
    TIM = 5,
    IBSS = 6,
    Country = 7,
    HoppingParameterSet = 8,
    HoppingPatternTable = 9,
    Request = 10,
    QBSSLoad = 11,
    EBSSSwitchAnnouncement = 12,
    Challenge = 16,
    PowerConstraint = 32,
    PowerCapability = 33,
    TPCRequest = 34,
    TPCReport = 35,
    SupportedChannels = 36,
    ChannelSwitchAnnouncement = 37,
    MeasurementRequest = 38,
    MeasurementReport = 39,
    Quiet = 40,
    IBSSDFS = 41,
    ERP = 42,
    TSDelay = 43,
    TCLASProcessing = 44,
    HTCapabilities = 45,
    QOSCapability = 46,
    RSN = 48,
    ExtendedRates = 50,
    APChannelReport = 51,
    NeighborReport = 52,
    RCPI = 53,
    MobilityDomain = 54,
    FastBSS = 55,
    Timeout = 56,
    RICData = 57,
    DSERegisteredLocation = 58,
    SupportedOperatingClasses = 59,
    ExtendedChannelSwitchAnnouncement = 60,
    HTOperation = 61,
    SecondaryChannelOffset = 62,
    BSSAverageAccessDelay = 63,
    AntennaInfo = 64,
    RSNI = 65,
    MeasurementPilotTransmission = 66,
    BSSSelectorList = 67,
    BSSSelectorCompatibility = 68,
    OverlapBSSScanParameters = 69,
    RMEnabledCapabilities = 70,
    ManagementMIC = 71,
    EventRequest = 72,
    EventReport = 73,
    DiagnosticRequest = 74,
    DiagnosticReport = 75,
    LocationParameters = 76,
    NonTransmittedBSSID = 77,
    SSIDList = 84,
    EmergencyAlertIdentifier = 91,
    MeshID = 113,
    MeshConfiguration = 114,
    MeshAwakeWindows = 115,
    BeaconTiming = 116,
    MCCAOP = 117,
    MeshChannelSwitchParameters = 118,
    QMFPolicy = 119,
    QMFElementID = 120,
    TSPEC = 121,
    TSClass = 122,
    SCSchedule = 123,
    ChannelUsage = 124,
    TimeAdvertisement = 125,
    ExtendedCapabilities = 127,
    FMSDescriptor = 131,
    QoSTrafficCapability = 139,
    BSSTWTimingSet = 145,
    ChannelSwitchTimingInformation = 156,
    PTIControl = 157,
    TPCReport2 = 158, // Additional TPCReport
    InterworkingElement = 170,
    AdvertisementProtocol = 171,
    ExpediteFrameworkAccess = 172,
    RoamingConsortium = 173,
    EmergencyAlertIdentifier2 = 174, // Additional EmergencyAlertIdentifier
    MeshChannelSwitchParameters2 = 176, // Additional MeshChannelSwitchParameters
    QMF = 177,
    QMFPolicy2 = 178,       // Additional QMFPolicy
    TCLASProcessing2 = 179, // Additional TCLASProcessing
    MCCAOPAdvertisementOverview = 180,
    MPDULengthThreshold = 184,
    VHTCapabilities = 191,
    VHTOperation = 192,
    ExtendedBSS = 193,
    WideBandwidthChannelSwitch = 194,
    VHTTransmitPowerEnvelope = 195,
    ChannelSwitchWrapper = 196,
    AID = 197,
    QuietChannel = 198,
    VHTOperatingModeNotification = 199,
    UPSIMControl = 200,
    ReducedNeighborReport = 201,
    TVHTOperation = 202,
    DeviceLocation = 204,
    WhiteSpaceMap = 205,
    FineTiming = 206,
    S1G = 207,
    SubchannelSelective = 220,
    VendorSpecific = 221,
    AuthenticationControl = 252,
    ExtendedElementID = 255, // Special value for extended element IDs
}

// IEEE 802.11 Extended Element IDs (256-511)
#[derive(FromRepr, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExtendedElementID {
    HECapabilities = 0, // Actual ID is 256, but we store the extension part only
    HEOperation = 1,    // Actual ID is 257
    MUEDCAParameter = 2,
    SpatialReuse = 3,
    HETransmissionDeclaration = 4,
    BSSTarWakeTime = 5,
    BSSTWTOperation = 6,
    S1GRelay = 7,
    S1GCapabilities = 8,
    S1GOperation = 9,
    HECapabilitiesElement = 10,
    MultiBSS = 11,
    SPSMP = 12,
    MultiBSSID = 13,
    TransmitPowerEnvelope = 14,
    BSSColorChange = 15,
    NonInheritedBSSMembershipSelectors = 16,
    WEPSM = 17,
    OperatingMode = 18,
    FDFrame = 19,
    MultiLink = 20,
    EHTOperation = 22,
    EHTCapabilities = 23,
    TIDToLinkMapping = 24,
    EMLCapabilities = 25,
    MediumSync = 26,
    EMLSR = 27,
    TWTSETUP = 28,
    DSE = 29,
    ESL = 30,
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
    HTCapabilities(HTCapabilitiesElement),
    HTOperation(HTOperationElement),
    VHTCapabilities(VHTCapabilitiesElement),
    VHTOperation(VHTOperationElement),
    HECapabilities(HECapabilitiesElement),
    HEOperation(HEOperationElement),
    ChannelSwitch(ChannelSwitchElement),
    ExtendedChannelSwitch(ExtendedChannelSwitchElement),
    Quiet(QuietElement),
    SupportedOperatingClasses(SupportedOperatingClassesElement),
    TransmitPowerEnvelope(TransmitPowerEnvelopeElement),
    WideBandwidthChannelSwitch(WideBandwidthChannelSwitchElement),
    VHTTransmitPowerEnvelope(VHTTransmitPowerEnvelopeElement),
    ReducedNeighborReport(ReducedNeighborReportElement),
    EHTCapabilities(EHTCapabilitiesElement),
    EHTOperation(EHTOperationElement),
    MultiLink(MultiLinkElement),
    PowerConstraint(u8),
    TPCReport(TPCReportElement),
    MobilityDomain(MobilityDomainElement),
    QBSSLoad(QBSSLoadElement),
    RMEnabledCapabilities(RMEnabledCapabilitiesElement),
    DMGCapabilities(DMGCapabilitiesElement),
    FineTiming(FineTimingElement),
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

// Add these structure definitions

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HTCapabilitiesElement {
    pub ht_capabilities_info: u16,
    pub ampdu_parameters: u8,
    pub supported_mcs_set: [u8; 16],
    pub ht_extended_capabilities: u16,
    pub tx_beam_forming_capabilities: u32,
    pub asel_capabilities: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VHTCapabilitiesElement {
    pub vht_capabilities_info: u32,
    pub supported_vht_mcs_and_nss_set: u64,
}

// HT Operation element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HTOperationElement {
    pub primary_channel: u8,
    pub ht_operation_info: [u8; 5],
    pub basic_mcs_set: [u8; 16],
}

// VHT Operation element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VHTOperationElement {
    pub channel_width: u8,
    pub channel_center_frequency_segment0: u8,
    pub channel_center_frequency_segment1: u8,
    pub basic_vht_mcs_and_nss_set: u16,
}

// HE Capabilities element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HECapabilitiesElement {
    pub he_mac_capabilities: [u8; 6],
    pub he_phy_capabilities: [u8; 11],
    pub supported_he_mcs_and_nss_set: [u8; 4],
    pub ppet: Vec<u8>, // Variable length
}

// HE Operation element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HEOperationElement {
    pub he_operation_parameters: [u8; 3],
    pub bss_color_info: u8,
    pub basic_he_mcs_and_nss_set: u16,
    pub vht_operation_info: Option<Vec<u8>>,     // Optional
    pub co_hosted_bss: Option<Vec<u8>>,          // Optional
    pub he_6ghz_operation_info: Option<Vec<u8>>, // Optional
}

// Channel Switch Announcement element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSwitchElement {
    pub switch_mode: u8,
    pub new_channel_number: u8,
    pub channel_switch_count: u8,
}

// Extended Channel Switch Announcement element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedChannelSwitchElement {
    pub switch_mode: u8,
    pub new_operating_class: u8,
    pub new_channel_number: u8,
    pub channel_switch_count: u8,
}

// Quiet element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuietElement {
    pub quiet_count: u8,
    pub quiet_period: u8,
    pub quiet_duration: u16,
    pub quiet_offset: u16,
}

// Extended Capabilities element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedCapabilitiesElement {
    pub capabilities: Vec<u8>, // Variable length
}

// Supported Operating Classes element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportedOperatingClassesElement {
    pub current_operating_class: u8,
    pub operating_classes: Vec<u8>,
}

// Transmit Power Envelope element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransmitPowerEnvelopeElement {
    pub power_info: u8,
    pub power_constraints: Vec<u8>, // Variable length
}

// Wide Bandwidth Channel Switch element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WideBandwidthChannelSwitchElement {
    pub new_channel_width: u8,
    pub new_channel_center_frequency_segment0: u8,
    pub new_channel_center_frequency_segment1: u8,
}

// VHT Transmit Power Envelope element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VHTTransmitPowerEnvelopeElement {
    pub transmit_power_info: u8,
    pub max_transmit_power: Vec<u8>, // Variable length
}

// Reduced Neighbor Report element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReducedNeighborReportElement {
    pub neighbor_ap_info: Vec<NeighborAPInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborAPInfo {
    pub tbtt_information_header: u16,
    pub neighbor_operating_class: u8,
    pub neighbor_channel_number: u8,
    pub tbtt: Vec<TBTTInfo>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TBTTInfo {
    pub tbtt_offset: Option<u8>,
    pub bssid: Option<MacAddr>,
    pub short_ssid: Option<u32>,
    pub bss_parameters: Option<u8>,
    pub psd_20mhz: Option<i8>,
    pub mld_parameters: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborTBTTInfoPresent {
    pub tbtt_offset: bool,
    pub bssid: bool,
    pub short_ssid: bool,
    pub bss_parameters: bool,
    pub psd_20mhz: bool,
    pub mld_parameters: bool,
}

// Parsing function for Reduced Neighbor Report element
pub fn parse_reduced_neighbor_report(data: &[u8]) -> Option<ReducedNeighborReportElement> {
    if data.is_empty() {
        return None;
    }

    let mut offset = 0;
    let mut neighbor_ap_info = Vec::new();

    while offset < data.len() {
        // Need at least TBTT Information Header, Operating Class and Channel Number
        if offset + 4 > data.len() {
            break;
        }

        let tbtt_info_header = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let operating_class = data[offset];
        offset += 1;

        let channel_number = data[offset];
        offset += 1;

        // Determine which fields are present based on the TBTT Information Length field
        let tbtt_info_length = (tbtt_info_header >> 8) as usize;
        let tbtt_info_count = ((tbtt_info_header >> 4) & 0x0f) as usize + 1;

        // Calculate expected field length
        let expected_length = tbtt_info_length * tbtt_info_count;
        if offset + expected_length > data.len() {
            break;
        }

        // Create a structure to track which fields are present
        let mut info_present = NeighborTBTTInfoPresent::default();
        let mut field_length = 0;

        // TBTT Information Field Present field
        if tbtt_info_length > 0 {
            info_present.tbtt_offset = true;
            field_length += 1;
        }
        if tbtt_info_length > 1 {
            info_present.bssid = true;
            field_length += 6;
        }
        if tbtt_info_length > 7 {
            info_present.short_ssid = true;
            field_length += 4;
        }
        if tbtt_info_length > 11 {
            info_present.bss_parameters = true;
            field_length += 1;
        }
        if tbtt_info_length > 12 {
            info_present.psd_20mhz = true;
            field_length += 1;
        }
        if tbtt_info_length > 13 {
            info_present.mld_parameters = true;
            // MLD Parameters is variable, we'll read the rest
        }

        let mut ap_info = NeighborAPInfo {
            tbtt_information_header: tbtt_info_header,
            neighbor_operating_class: operating_class,
            neighbor_channel_number: channel_number,
            tbtt: vec![],
        };

        for tbtt_i in 0..tbtt_info_count {
            let mut tbtt = TBTTInfo {
                tbtt_offset: None,
                bssid: None,
                short_ssid: None,
                bss_parameters: None,
                psd_20mhz: None,
                mld_parameters: None,
            };
            // Parse each present field
            if info_present.tbtt_offset && offset < data.len() {
                tbtt.tbtt_offset = Some(data[offset]);
                offset += 1;
            }

            if info_present.bssid && offset + 6 <= data.len() {
                let mut bssid_bytes = [0u8; 6];
                bssid_bytes.copy_from_slice(&data[offset..offset + 6]);
                tbtt.bssid = Some(MacAddr::from(bssid_bytes));
                offset += 6;
            }

            if info_present.short_ssid && offset + 4 <= data.len() {
                let short_ssid = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                tbtt.short_ssid = Some(short_ssid);
                offset += 4;
            }

            if info_present.bss_parameters && offset < data.len() {
                tbtt.bss_parameters = Some(data[offset]);
                offset += 1;
            }

            if info_present.psd_20mhz && offset < data.len() {
                tbtt.psd_20mhz = Some(data[offset] as i8);
                offset += 1;
            }

            if info_present.mld_parameters {
                // Calculate MLD Parameters length from remaining TBTT Information Length
                let used_length = if info_present.tbtt_offset { 1 } else { 0 }
                    + if info_present.bssid { 6 } else { 0 }
                    + if info_present.short_ssid { 4 } else { 0 }
                    + if info_present.bss_parameters { 1 } else { 0 }
                    + if info_present.psd_20mhz { 1 } else { 0 };

                let mld_length = tbtt_info_length.saturating_sub(used_length);

                if mld_length > 0 && offset + mld_length <= data.len() {
                    tbtt.mld_parameters = Some(data[offset..offset + mld_length].to_vec());
                    offset += mld_length;
                }
            }
            ap_info.tbtt.push(tbtt);
        }

        neighbor_ap_info.push(ap_info);
    }

    Some(ReducedNeighborReportElement { neighbor_ap_info })
}

// Function to encode Reduced Neighbor Report element
pub fn encode_reduced_neighbor_report(rnr: &ReducedNeighborReportElement) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    for ap_info in &rnr.neighbor_ap_info {
        // Add TBTT Information Header, Operating Class, and Channel Number
        result.push((ap_info.tbtt_information_header & 0xff) as u8);
        result.push((ap_info.tbtt_information_header >> 8) as u8);
        result.push(ap_info.neighbor_operating_class);
        result.push(ap_info.neighbor_channel_number);

        for ap_info in &ap_info.tbtt {
            // Add optional fields if present
            if let Some(tbtt_offset) = ap_info.tbtt_offset {
                result.push(tbtt_offset);
            }

            if let Some(bssid) = &ap_info.bssid {
                result.extend_from_slice(&bssid.0.bytes());
            }

            if let Some(short_ssid) = ap_info.short_ssid {
                result.extend_from_slice(&short_ssid.to_le_bytes());
            }

            if let Some(bss_params) = ap_info.bss_parameters {
                result.push(bss_params);
            }

            if let Some(psd) = ap_info.psd_20mhz {
                result.push(psd as u8);
            }

            if let Some(mld_params) = &ap_info.mld_parameters {
                result.extend_from_slice(mld_params);
            }
        }
    }

    result
}

// EHT Capabilities element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EHTCapabilitiesElement {
    pub eht_mac_capabilities: [u8; 2],
    pub eht_phy_capabilities: [u8; 9],
    pub supported_eht_mcs_and_nss_set: Vec<u8>, // Variable length
    pub ppet: Vec<u8>,                          // Variable length
}

// EHT Operation element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EHTOperationElement {
    pub parameters: u8,
    pub disabled_subchannel_bitmap: Option<Vec<u8>>, // Optional
    pub operating_channel_width: Option<Vec<u8>>,    // Optional
}

// Multi-Link element
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiLinkElement {
    pub control: u16,
    pub common_info: Vec<u8>,       // Variable length
    pub link_info: Option<Vec<u8>>, // Optional
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TPCReportElement {
    pub tx_power: u8,
    pub link_margin: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobilityDomainElement {
    pub mdid: u16,
    pub flags: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QBSSLoadElement {
    pub station_count: u16,
    pub channel_utilization: u8,
    pub available_admission_capacity: u16,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RMEnabledCapabilitiesElement {
    pub rm_capabilities: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DMGCapabilitiesElement {
    pub dmg_capabilities: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FineTimingElement {
    pub timing_capabilities: Vec<u8>,
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
    pub addr2: Option<Value<MacAddr>>, // Source
    pub addr3: Option<Value<MacAddr>>, // BSSID
    #[nproto(encode = encode_seq_control, decode = decode_seq_control)]
    pub seq_control: Option<Value<u16>>,
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
    let (raw_value, delta) = u16::decode::<BinaryLittleEndian>(buf)?;
    let fc = FrameControl::from_raw(raw_value);
    Some((fc, delta))
}

fn encode_seq_control<E: Encoder>(
    my_layer: &Dot11,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.seq_control.as_ref().unwrap().value().encode::<BinaryLittleEndian>()
}

fn decode_seq_control<D: Decoder>(buf: &[u8], ci: usize, me: &mut Dot11) -> Option<(Option<Value<u16>>, usize)> {
    let buf = &buf[ci..];
    Option::<Value<u16>>::decode::<BinaryLittleEndian>(buf)
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
    #[nproto(encode = encode_probe_resp_capabilities, decode = decode_probe_resp_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    #[nproto(decode = decode_probe_resp_elements, encode = encode_probe_resp_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Association Request Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11AssocReq {
    #[nproto(encode = encode_assoc_req_capabilities, decode = decode_assoc_req_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    pub listen_interval: Value<u16>,
    #[nproto(decode = decode_assoc_req_elements, encode = encode_assoc_req_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Association Response Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11AssocResp {
    #[nproto(encode = encode_assoc_resp_capabilities, decode = decode_assoc_resp_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    pub status_code: Value<u16>,
    pub association_id: Value<u16>,
    #[nproto(decode = decode_assoc_resp_elements, encode = encode_assoc_resp_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Reassociation Request Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11ReassocReq {
    #[nproto(encode = encode_reassoc_req_capabilities, decode = decode_reassoc_req_capabilities)]
    pub capabilities: Value<CapabilitiesInfo>,
    pub listen_interval: Value<u16>,
    pub current_ap: Value<MacAddr>,
    #[nproto(decode = decode_reassoc_req_elements, encode = encode_reassoc_req_elements)]
    pub elements: Vec<ParsedElement>,
}

// IEEE 802.11 Authentication Frame Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Auth {
    pub auth_algorithm: Value<u16>,
    pub auth_seq: Value<u16>,
    pub status_code: Value<u16>,
    #[nproto(decode = decode_auth_elements, encode = encode_auth_elements)]
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
    #[nproto(decode = decode_action_elements, encode = encode_action_elements)]
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
    #[nproto(encode = Skip, decode = Skip)]
    pub has_fcs: bool,
    #[nproto(encode = encode_radiotap_length, decode = decode_radiotap_length)]
    pub length: Value<u16>,
    #[nproto(encode = encode_radiotap_present, decode = decode_radiotap_present)]
    pub present_flags: Vec<u32>,
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
    XChannel(u32, u16, u8),        // flags, freq, channel
    MCS(u8, u8, u8),               // known, flags, mcs
    AMPDUStatus(u32, u16, u8, u8), // reference number, flags, delimiter CRC, reserved
    VHT(u16, u8, u8, Vec<u8>),     // known, flags, bandwidth, mcs_nss, coding
    HEData1(u16, u16),             // data1, data2
    HEData2(u16, u16),             // data3, data4
    HEData3(u16, u16),             // data5, data6
    HEData4(u8, u8, u8, u8),       // data7-data10
    HEData5(u8, u8, u8, u8),       // data11-data14
    HEData6(u8, u8),               // data15-data16
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
    my_layer.length.value().encode::<BinaryLittleEndian>()
}

fn decode_radiotap_length<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Radiotap,
) -> Option<(u16, usize)> {
    let buf = &buf[ci..];
    u16::decode::<BinaryLittleEndian>(buf)
}

fn encode_radiotap_present<E: Encoder>(
    my_layer: &Radiotap,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for v in &my_layer.present_flags {
        out.extend(v.encode::<BinaryLittleEndian>())
    }
    out
}

fn decode_radiotap_present<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Radiotap,
) -> Option<(Vec<u32>, usize)> {
    let buf = &buf[ci..];
    let mut out: Vec<u32> = vec![];
    let mut consumed = 0;
    let mut offs = 0;
    loop {
        let buf = &buf[offs..];
        if let Some((val, nbytes)) = u32::decode::<BinaryLittleEndian>(buf) {
            out.push(val);
            consumed += nbytes;
            if val & radiotap_flags::EXT == 0 {
                //println!("EXT missing");
                break;
            }
            offs += nbytes;
        } else {
            println!("Error while decode radiotap present");
            return None;
        }
    }
    Some((out, consumed))
}

fn decode_radiotap_fields<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Radiotap,
) -> Option<(Vec<RadiotapField>, usize)> {
    let buf = &buf[ci..];
    let radiotap_len = me.length.value() as usize;

    let mut fields = Vec::new();
    let mut present_bitmaps = me.present_flags.clone();

    let mut offset = 0;

    // alignment for certain fields
    let align_offset_8 = |off: usize| -> usize { (off + 7) & !7 };
    let align_offset_4 = |off: usize| -> usize { (off + 3) & !3 };
    let align_offset_2 = |off: usize| -> usize { (off + 1) & !1 };

    // Parse each bitmap
    for (idx, present) in present_bitmaps.iter().enumerate() {
        let base_bit = idx * 32;

        for bit in 0..31 {
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

            match bit {
                0 => {
                    // TSFT
                    offset = align_offset_8(offset);
                    if offset + 8 <= radiotap_len {
                        let tsft = u64::from_le_bytes([
                            buf[offset],
                            buf[offset + 1],
                            buf[offset + 2],
                            buf[offset + 3],
                            buf[offset + 4],
                            buf[offset + 5],
                            buf[offset + 6],
                            buf[offset + 7],
                        ]);
                        fields.push(RadiotapField::TSFT(tsft));
                        offset += 8;
                    }
                }
                1 => {
                    // FLAGS
                    if offset < radiotap_len {
                        fields.push(RadiotapField::Flags(buf[offset]));
                        if buf[offset] & 0x10 != 0 {
                            me.has_fcs = true;
                        }
                        offset += 1;
                    }
                }
                2 => {
                    // RATE
                    if offset < radiotap_len {
                        fields.push(RadiotapField::Rate(buf[offset]));
                        offset += 1;
                    }
                }
                3 => {
                    // CHANNEL = 2 * u16, so alignment is a u16
                    offset = align_offset_2(offset);
                    // println!("aligned offset: {}", &offset);
                    if offset + 4 <= radiotap_len {
                        let freq = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        let flags = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]);
                        fields.push(RadiotapField::Channel(freq, flags));
                        offset += 4;
                    }
                }
                4 => {
                    // FHSS
                    offset = align_offset_2(offset);
                    if offset + 2 <= radiotap_len {
                        fields.push(RadiotapField::FHSS(buf[offset], buf[offset + 1]));
                        offset += 2;
                    }
                }
                5 => {
                    // DBM_ANTSIGNAL
                    if offset < radiotap_len {
                        fields.push(RadiotapField::AntennaSignal(buf[offset] as i8));
                        offset += 1;
                    }
                }
                6 => {
                    // DBM_ANTNOISE
                    if offset < radiotap_len {
                        fields.push(RadiotapField::AntennaNoise(buf[offset] as i8));
                        offset += 1;
                    }
                }
                7 => {
                    // LOCK_QUALITY
                    offset = align_offset_2(offset);
                    if offset + 2 <= radiotap_len {
                        let quality = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        fields.push(RadiotapField::LockQuality(quality));
                        offset += 2;
                    }
                }
                8 => {
                    // TX_ATTENUATION
                    offset = align_offset_2(offset);
                    if offset + 2 <= radiotap_len {
                        let atten = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        fields.push(RadiotapField::TxAttenuation(atten));
                        offset += 2;
                    }
                }
                9 => {
                    // DB_TX_ATTENUATION
                    offset = align_offset_2(offset);
                    if offset + 2 <= radiotap_len {
                        let atten = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        fields.push(RadiotapField::DBTxAttenuation(atten));
                        offset += 2;
                    }
                }
                10 => {
                    // DBM_TX_POWER
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DBmTxPower(buf[offset] as i8));
                        offset += 1;
                    }
                }
                11 => {
                    // ANTENNA
                    if offset < radiotap_len {
                        fields.push(RadiotapField::Antenna(buf[offset]));
                        offset += 1;
                    }
                }
                12 => {
                    // DB_ANTSIGNAL
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DBAntennaSignal(buf[offset]));
                        offset += 1;
                    }
                }
                13 => {
                    // DB_ANTNOISE
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DBAntennaNoise(buf[offset]));
                        offset += 1;
                    }
                }
                14 => {
                    // RX_FLAGS
                    offset = align_offset_2(offset);
                    if offset + 2 <= radiotap_len {
                        let flags = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        fields.push(RadiotapField::RxFlags(flags));
                        offset += 2;
                    }
                }
                15 => {
                    // TX_FLAGS
                    offset = align_offset_2(offset);
                    if offset + 2 <= radiotap_len {
                        let flags = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        fields.push(RadiotapField::TxFlags(flags));
                        offset += 2;
                    }
                }
                16 => {
                    // RTS_RETRIES
                    if offset < radiotap_len {
                        fields.push(RadiotapField::RtsRetries(buf[offset]));
                        offset += 1;
                    }
                }
                17 => {
                    // DATA_RETRIES
                    if offset < radiotap_len {
                        fields.push(RadiotapField::DataRetries(buf[offset]));
                        offset += 1;
                    }
                }
                18 => {
                    // XCHANNEL
                    offset = align_offset_4(offset);
                    if offset + 8 <= radiotap_len {
                        let flags = u32::from_le_bytes([
                            buf[offset],
                            buf[offset + 1],
                            buf[offset + 2],
                            buf[offset + 3],
                        ]);
                        let freq = u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]);
                        let channel = buf[offset + 6];
                        let max_power = buf[offset + 7];
                        fields.push(RadiotapField::XChannel(flags, freq, channel));
                        offset += 8;
                    }
                }
                19 => {
                    // MCS
                    if offset + 3 <= radiotap_len {
                        let known = buf[offset];
                        let flags = buf[offset + 1];
                        let mcs = buf[offset + 2];
                        fields.push(RadiotapField::MCS(known, flags, mcs));
                        offset += 3;
                    }
                }
                20 => {
                    // AMPDU_STATUS - 4 byte alignment
                    offset = align_offset_4(offset);
                    if offset + 8 <= radiotap_len {
                        let reference = u32::from_le_bytes([
                            buf[offset],
                            buf[offset + 1],
                            buf[offset + 2],
                            buf[offset + 3],
                        ]);
                        let flags = u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]);
                        let delimiter_crc = buf[offset + 6];
                        let reserved = buf[offset + 7];
                        fields.push(RadiotapField::AMPDUStatus(
                            reference,
                            flags,
                            delimiter_crc,
                            reserved,
                        ));
                        offset += 8;
                    }
                }
                21 => {
                    // VHT - 2 byte alignment
                    offset = align_offset_2(offset);
                    if offset + 12 <= radiotap_len {
                        let known = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        let flags = buf[offset + 2];
                        let bandwidth = buf[offset + 3];
                        let mcs_nss = Vec::from(&buf[offset + 4..offset + 8]);
                        let coding = buf[offset + 8];
                        let group_id = buf[offset + 9];
                        let partial_aid = u16::from_le_bytes([buf[offset + 10], buf[offset + 11]]);
                        fields.push(RadiotapField::VHT(known, flags, bandwidth, mcs_nss));
                        offset += 12;
                    }
                }
                22..=26 => {
                    // HE fields
                    // Skip complex HE fields for now, they have variable size
                    // and depend on the specific 802.11ax implementation
                    offset = align_offset_4(offset);
                    if offset + 4 <= radiotap_len {
                        let data1 = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                        let data2 = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]);
                        fields.push(RadiotapField::HEData1(data1, data2));
                        offset += 4;
                    }
                    // Skip the rest of the HE data for simplicity
                }
                29 => {
                    // RADIOTAP_NAMESPACE
                    fields.push(RadiotapField::RadiotapNamespace());
                    // No length defined, must be followed by another namespace
                }
                30 => {
                    // VENDOR_NAMESPACE
                    // offset = align_offset(offset);
                    if offset + 6 <= radiotap_len {
                        let oui_len =
                            u16::from_le_bytes([buf[offset + 4], buf[offset + 5]]) as usize;
                        if offset + 6 + oui_len <= radiotap_len {
                            let data = Vec::from(&buf[offset..offset + 6 + oui_len]);
                            fields.push(RadiotapField::VendorNamespace(data));
                            offset += 6 + oui_len;
                        }
                    }
                }
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
pub fn decode_802_11_frame(buf: &[u8]) -> Option<(LayerStack, usize)> {
    let mut offset = 0;
    let mut stack = LayerStack {
        layers: Vec::new(),
        filled: true,
    };
    let mut has_fcs = false;

    // First, check if we have a radiotap header
    if buf.len() >= 4 && buf[0] == 0x00 && buf[1] == 0x00 {
        // Radiotap magic
        let radiotap = Radiotap::default();
        if let Some((radiotap_decoded, radiotap_offset)) = Radiotap::decode::<BinaryBigEndian>(&buf)
        {
            // radiotap.decode_with_decoder::<BinaryBigEndian>(&buf) {
            // println!("RADIOTAP: {:?}", &radiotap_decoded);
            has_fcs = radiotap_decoded.has_fcs;
            stack.layers.push(Box::new(radiotap_decoded));
            offset += radiotap_offset;
        } else {
            println!("No radiotap header");
            return None;
        }
    }

    // Calculate the length to the end of the frame, taking into account FCS if present
    let data_end = if has_fcs { buf.len() - 4 } else { buf.len() };

    // Next, decode the 802.11 header and appropriate frame type
    if let Some((dot11_decoded, dot11_offset)) = decode_dot11_frame(&buf[offset..data_end]) {
        stack.layers.extend(dot11_decoded.layers);
        offset += dot11_offset;
    } else {
        println!("No 802.11 header");
        return None;
    }

    // If we have an FCS, decode it
    if has_fcs && buf.len() >= 4 {
        let fcs_start = buf.len() - 4;
        let fcs_value = u32::from_le_bytes([
            buf[fcs_start],
            buf[fcs_start + 1],
            buf[fcs_start + 2],
            buf[fcs_start + 3],
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
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
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
// #[derive(Default, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11Data {
    pub addr4: Option<Value<MacAddr>>, // Only present if ToDS and FromDS are both set
    #[nproto(encode = encode_qos_control, decode = decode_qos_control)]
    pub qos_control: Option<Value<u16>>, // Only present in QoS data frames
    #[nproto(encode = encode_ht_control, decode = decode_ht_control)]
    pub ht_control: Option<Value<u32>>, // Only present if Order bit is set
    pub payload: Vec<u8>,              // Data payload
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
    if let Some((mut dot11_decoded, mut offset)) = Dot11::decode::<BinaryBigEndian>(buf) {
        let mut dot11_decoded = dot11_decoded.to_stack();
        if let Some(dot11_layer) = dot11_decoded.layers.first() {
            if let Some(dot11) = dot11_layer.downcast_ref::<Dot11>() {
                let fc = dot11.frame_control.value();

                match fc.frame_type {
                    // Management frames
                    frame_types::MANAGEMENT => {
                        match fc.frame_subtype {
                            frame_types::BEACON => {
                                let beacon = Dot11Beacon::default();
                                if let Some((beacon_decoded, beacon_offset)) =
                                    beacon.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(beacon_decoded.layers);
                                    offset += beacon_offset;
                                }
                            }
                            frame_types::PROBE_REQ => {
                                let probe_req = Dot11ProbeReq::default();
                                if let Some((probe_req_decoded, probe_req_offset)) =
                                    probe_req.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(probe_req_decoded.layers);
                                    offset += probe_req_offset;
                                }
                            }
                            frame_types::PROBE_RESP => {
                                let probe_resp = Dot11ProbeResp::default();
                                if let Some((probe_resp_decoded, probe_resp_offset)) =
                                    probe_resp
                                        .decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(probe_resp_decoded.layers);
                                    offset += probe_resp_offset;
                                }
                            }
                            frame_types::ASSOC_REQ => {
                                let assoc_req = Dot11AssocReq::default();
                                if let Some((assoc_req_decoded, assoc_req_offset)) =
                                    assoc_req.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(assoc_req_decoded.layers);
                                    offset += assoc_req_offset;
                                }
                            }
                            frame_types::ASSOC_RESP => {
                                let assoc_resp = Dot11AssocResp::default();
                                if let Some((assoc_resp_decoded, assoc_resp_offset)) =
                                    assoc_resp
                                        .decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(assoc_resp_decoded.layers);
                                    offset += assoc_resp_offset;
                                }
                            }
                            frame_types::REASSOC_REQ => {
                                let reassoc_req = Dot11ReassocReq::default();
                                if let Some((reassoc_req_decoded, reassoc_req_offset)) = reassoc_req
                                    .decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(reassoc_req_decoded.layers);
                                    offset += reassoc_req_offset;
                                }
                            }
                            frame_types::AUTH => {
                                let auth = Dot11Auth::default();
                                if let Some((auth_decoded, auth_offset)) =
                                    auth.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(auth_decoded.layers);
                                    offset += auth_offset;
                                }
                            }
                            frame_types::DEAUTH => {
                                let deauth = Dot11Deauth::default();
                                if let Some((deauth_decoded, deauth_offset)) =
                                    deauth.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(deauth_decoded.layers);
                                    offset += deauth_offset;
                                }
                            }
                            frame_types::ACTION => {
                                let action = Dot11Action::default();
                                if let Some((action_decoded, action_offset)) =
                                    action.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(action_decoded.layers);
                                    offset += action_offset;
                                }
                            }
                            _ => {
                                // Unknown management frame subtype
                                // Just return the Dot11 header
                            }
                        }
                    }

                    // Control frames
                    frame_types::CONTROL => {
                        match fc.frame_subtype {
                            control_frame_subtypes::RTS => {
                                let rts = Dot11RTS::default();
                                if let Some((rts_decoded, rts_offset)) =
                                    rts.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(rts_decoded.layers);
                                    offset += rts_offset;
                                }
                            }
                            control_frame_subtypes::CTS => {
                                let cts = Dot11CTS::default();
                                if let Some((cts_decoded, cts_offset)) =
                                    cts.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(cts_decoded.layers);
                                    offset += cts_offset;
                                }
                            }
                            control_frame_subtypes::ACK => {
                                let ack = Dot11ACK::default();
                                if let Some((ack_decoded, ack_offset)) =
                                    ack.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(ack_decoded.layers);
                                    offset += ack_offset;
                                }
                            }
                            control_frame_subtypes::BLOCK_ACK_REQ => {
                                let bar = Dot11BlockAckReq::default();
                                if let Some((bar_decoded, bar_offset)) =
                                    bar.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(bar_decoded.layers);
                                    offset += bar_offset;
                                }
                            }
                            control_frame_subtypes::BLOCK_ACK => {
                                let ba = Dot11BlockAck::default();
                                if let Some((ba_decoded, ba_offset)) =
                                    ba.decode_with_decoder::<BinaryBigEndian>(&buf[offset..])
                                {
                                    dot11_decoded.layers.extend(ba_decoded.layers);
                                    offset += ba_offset;
                                }
                            }
                            _ => {
                                // Unknown control frame subtype
                                // Just return the Dot11 header
                            }
                        }
                    }

                    // Data frames
                    frame_types::DATA => {
                        // Create a data frame with the appropriate fields based on the frame control
                        let mut data = Dot11Data {
                            addr4: None,
                            qos_control: None,
                            ht_control: None,
                            payload: Vec::new(),
                        };

                        let mut data_offset = 0;

                        // If both ToDS and FromDS are set, there's a 4th address
                        if fc.to_ds && fc.from_ds {
                            if offset + 6 <= buf.len() {
                                let addr4_bytes = &buf[offset..offset + 6];
                                let addr4 = MacAddr::from(addr4_bytes);
                                data.addr4 = Some(Value::Set(addr4));
                                data_offset += 6;
                            }
                        }

                        // QoS Data frames have a QoS control field
                        if fc.frame_subtype >= data_frame_subtypes::QOS_DATA
                            && fc.frame_subtype <= data_frame_subtypes::QOS_CF_ACK_POLL
                        {
                            if offset + data_offset + 2 <= buf.len() {
                                let qos_bytes =
                                    &buf[offset + data_offset..offset + data_offset + 2];
                                let qos = u16::from_le_bytes([qos_bytes[0], qos_bytes[1]]);
                                data.qos_control = Some(Value::Set(qos));
                                data_offset += 2;
                            }
                        }

                        // Frames with Order bit set have an HT Control field
                        if fc.order {
                            if offset + data_offset + 4 <= buf.len() {
                                let ht_bytes = &buf[offset + data_offset..offset + data_offset + 4];
                                let ht = u32::from_le_bytes([
                                    ht_bytes[0],
                                    ht_bytes[1],
                                    ht_bytes[2],
                                    ht_bytes[3],
                                ]);
                                data.ht_control = Some(Value::Set(ht));
                                data_offset += 4;
                            }
                        }

                        // The rest of the frame is payload
                        if offset + data_offset < buf.len() {
                            data.payload = buf[offset + data_offset..].to_vec();
                        }

                        dot11_decoded.layers.push(Box::new(data));
                        offset = buf.len(); // We've consumed the entire buffer
                    }

                    // Extension frames
                    frame_types::EXTENSION => {
                        // These are complex 802.11ax/be frames, not implementing for now
                        // Just return the Dot11 header
                    }

                    4_u8..=u8::MAX => todo!(),
                }
            }
        }

        return Some((dot11_decoded, offset));
    } else {
        println!("Could not decode dot11");
    }

    None
}

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
    let fc = FrameControl::new(
        0,
        frame_types::MANAGEMENT,
        frame_types::BEACON,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    );
    dot11 = dot11.frame_control(fc);
    dot11 = dot11.addr1(MacAddr::new(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)); // Broadcast
    dot11 = dot11.addr2(Value::Set(src_mac.clone()));
    dot11 = dot11.addr3(Value::Set(bssid.clone()));
    dot11 = dot11.seq_control(Value::Set(0)); // Sequence number and fragment number

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
    elements.push(ParsedElement::SupportedRates(vec![
        0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C,
    ]));

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
    let fc = FrameControl::new(
        0,
        frame_types::MANAGEMENT,
        frame_types::PROBE_RESP,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    );
    dot11 = dot11.frame_control(fc);
    dot11 = dot11.addr1(dst_mac);
    dot11 = dot11.addr2(Value::Set(src_mac.clone()));
    dot11 = dot11.addr3(Value::Set(bssid.clone()));
    dot11 = dot11.seq_control(Value::Set(0)); // Sequence number and fragment number

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
    elements.push(ParsedElement::SupportedRates(vec![
        0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C,
    ]));

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
pub fn get_security_type(
    capabilities: &CapabilitiesInfo,
    elements: &[ParsedElement],
) -> &'static str {
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
            }
            ParsedElement::VendorSpecific(vendor) => {
                // WPA OUI is 00:50:F2
                if vendor.oui == [0x00, 0x50, 0xF2] && vendor.vendor_type == 0x01 {
                    has_wpa = true;
                }
            }
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

/*

stray things:

>,
}
*/

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
            0 => {
                // SSID
                let ssid = String::from_utf8_lossy(&element_data).to_string();
                ParsedElement::SSID(ssid)
            }
            1 => {
                // Supported Rates
                ParsedElement::SupportedRates(element_data)
            }
            3 => {
                // DS Parameter Set
                if element_data.len() == 1 {
                    ParsedElement::DSParameter(element_data[0])
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            5 => {
                // TIM
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
            }
            7 => {
                // Country
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
                            num_channels: element_data[i + 1],
                            max_tx_power: element_data[i + 2],
                        });
                        i += 3;
                    }

                    ParsedElement::Country(country)
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            37 => {
                // Channel Switch Announcement
                if element_data.len() >= 3 {
                    ParsedElement::ChannelSwitch(ChannelSwitchElement {
                        switch_mode: element_data[0],
                        new_channel_number: element_data[1],
                        channel_switch_count: element_data[2],
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            40 => {
                // Quiet
                if element_data.len() >= 6 {
                    let quiet_duration = u16::from_le_bytes([element_data[2], element_data[3]]);
                    let quiet_offset = u16::from_le_bytes([element_data[4], element_data[5]]);

                    ParsedElement::Quiet(QuietElement {
                        quiet_count: element_data[0],
                        quiet_period: element_data[1],
                        quiet_duration,
                        quiet_offset,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            45 => {
                // HT Capabilities
                if element_data.len() >= 26 {
                    let ht_capabilities_info =
                        u16::from_le_bytes([element_data[0], element_data[1]]);
                    let ampdu_parameters = element_data[2];
                    let mut supported_mcs_set = [0u8; 16];
                    supported_mcs_set.copy_from_slice(&element_data[3..19]);
                    let ht_extended_capabilities =
                        u16::from_le_bytes([element_data[19], element_data[20]]);
                    let tx_beam_forming_capabilities = u32::from_le_bytes([
                        element_data[21],
                        element_data[22],
                        element_data[23],
                        element_data[24],
                    ]);
                    let asel_capabilities = element_data[25];

                    ParsedElement::HTCapabilities(HTCapabilitiesElement {
                        ht_capabilities_info,
                        ampdu_parameters,
                        supported_mcs_set,
                        ht_extended_capabilities,
                        tx_beam_forming_capabilities,
                        asel_capabilities,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            59 => {
                // Supported Operating Classes
                if element_data.len() >= 1 {
                    ParsedElement::SupportedOperatingClasses(SupportedOperatingClassesElement {
                        current_operating_class: element_data[0],
                        operating_classes: element_data[1..].to_vec(),
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            60 => {
                // Extended Channel Switch Announcement
                if element_data.len() >= 4 {
                    ParsedElement::ExtendedChannelSwitch(ExtendedChannelSwitchElement {
                        switch_mode: element_data[0],
                        new_operating_class: element_data[1],
                        new_channel_number: element_data[2],
                        channel_switch_count: element_data[3],
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            61 => {
                // HT Operation
                if element_data.len() >= 22 {
                    let primary_channel = element_data[0];
                    let mut ht_operation_info = [0u8; 5];
                    ht_operation_info.copy_from_slice(&element_data[1..6]);
                    let mut basic_mcs_set = [0u8; 16];
                    basic_mcs_set.copy_from_slice(&element_data[6..22]);

                    ParsedElement::HTOperation(HTOperationElement {
                        primary_channel,
                        ht_operation_info,
                        basic_mcs_set,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            127 => {
                // Extended Capabilities
                ParsedElement::ExtendedCapabilities(element_data.to_vec())
            }

            191 => {
                // VHT Capabilities
                if element_data.len() >= 12 {
                    let vht_capabilities_info = u32::from_le_bytes([
                        element_data[0],
                        element_data[1],
                        element_data[2],
                        element_data[3],
                    ]);
                    let supported_vht_mcs_and_nss_set = u64::from_le_bytes([
                        element_data[4],
                        element_data[5],
                        element_data[6],
                        element_data[7],
                        element_data[8],
                        element_data[9],
                        element_data[10],
                        element_data[11],
                    ]);

                    ParsedElement::VHTCapabilities(VHTCapabilitiesElement {
                        vht_capabilities_info,
                        supported_vht_mcs_and_nss_set,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            192 => {
                // VHT Operation
                if element_data.len() >= 5 {
                    let basic_vht_mcs_and_nss_set =
                        u16::from_le_bytes([element_data[3], element_data[4]]);

                    ParsedElement::VHTOperation(VHTOperationElement {
                        channel_width: element_data[0],
                        channel_center_frequency_segment0: element_data[1],
                        channel_center_frequency_segment1: element_data[2],
                        basic_vht_mcs_and_nss_set,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            194 => {
                // Wide Bandwidth Channel Switch
                if element_data.len() >= 3 {
                    ParsedElement::WideBandwidthChannelSwitch(WideBandwidthChannelSwitchElement {
                        new_channel_width: element_data[0],
                        new_channel_center_frequency_segment0: element_data[1],
                        new_channel_center_frequency_segment1: element_data[2],
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            195 => {
                // VHT Transmit Power Envelope
                if element_data.len() >= 2 {
                    ParsedElement::VHTTransmitPowerEnvelope(VHTTransmitPowerEnvelopeElement {
                        transmit_power_info: element_data[0],
                        max_transmit_power: element_data[1..].to_vec(),
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            201 => {
                // Reduced Neighbor Report
                if let Some(rnr) = parse_reduced_neighbor_report(&element_data) {
                    ParsedElement::ReducedNeighborReport(rnr)
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            255 => {
                // Extended Element ID
                if element_data.len() >= 1 {
                    let extended_id = element_data[0];
                    let ext_data = element_data[1..].to_vec();

                    match extended_id {
                        0 => {
                            // HE Capabilities
                            if ext_data.len() >= 21 {
                                let mut he_mac_capabilities = [0u8; 6];
                                let mut he_phy_capabilities = [0u8; 11];
                                let mut supported_he_mcs_and_nss_set = [0u8; 4];

                                if ext_data.len() >= 6 {
                                    he_mac_capabilities.copy_from_slice(&ext_data[0..6]);
                                }

                                if ext_data.len() >= 17 {
                                    he_phy_capabilities.copy_from_slice(&ext_data[6..17]);
                                }

                                if ext_data.len() >= 21 {
                                    supported_he_mcs_and_nss_set.copy_from_slice(&ext_data[17..21]);
                                }

                                let ppet = if ext_data.len() > 21 {
                                    ext_data[21..].to_vec()
                                } else {
                                    Vec::new()
                                };

                                ParsedElement::HECapabilities(HECapabilitiesElement {
                                    he_mac_capabilities,
                                    he_phy_capabilities,
                                    supported_he_mcs_and_nss_set,
                                    ppet,
                                })
                            } else {
                                ParsedElement::Unknown(Element::new(element_id, element_data))
                            }
                        }

                        1 => {
                            // HE Operation
                            if ext_data.len() >= 5 {
                                let mut he_operation_parameters = [0u8; 3];
                                he_operation_parameters.copy_from_slice(&ext_data[0..3]);

                                let bss_color_info = ext_data[3];
                                let basic_he_mcs_and_nss_set =
                                    u16::from_le_bytes([ext_data[4], ext_data[5]]);

                                // Optional fields
                                let mut offset = 6;
                                let mut vht_operation_info = None;
                                let mut co_hosted_bss = None;
                                let mut he_6ghz_operation_info = None;

                                // Simplified parsing - actual parsing would check presence bits
                                if offset < ext_data.len() {
                                    // Parse optional fields based on presence bits
                                    // This is a simplified version
                                }

                                ParsedElement::HEOperation(HEOperationElement {
                                    he_operation_parameters,
                                    bss_color_info,
                                    basic_he_mcs_and_nss_set,
                                    vht_operation_info,
                                    co_hosted_bss,
                                    he_6ghz_operation_info,
                                })
                            } else {
                                ParsedElement::Unknown(Element::new(element_id, element_data))
                            }
                        }

                        23 => {
                            // EHT Capabilities
                            if ext_data.len() >= 11 {
                                let mut eht_mac_capabilities = [0u8; 2];
                                eht_mac_capabilities.copy_from_slice(&ext_data[0..2]);

                                let mut eht_phy_capabilities = [0u8; 9];
                                eht_phy_capabilities.copy_from_slice(&ext_data[2..11]);

                                // MCS and NSS are variable length
                                let supported_eht_mcs_and_nss_set = ext_data[11..].to_vec();

                                // PPET is also variable and would follow MCS/NSS
                                // Simplified version assumes it's not present
                                let ppet = Vec::new();

                                ParsedElement::EHTCapabilities(EHTCapabilitiesElement {
                                    eht_mac_capabilities,
                                    eht_phy_capabilities,
                                    supported_eht_mcs_and_nss_set,
                                    ppet,
                                })
                            } else {
                                ParsedElement::Unknown(Element::new(element_id, element_data))
                            }
                        }

                        22 => {
                            // EHT Operation
                            if ext_data.len() >= 1 {
                                let parameters = ext_data[0];

                                // Optional fields based on parameters
                                let disabled_subchannel_bitmap = None;
                                let operating_channel_width = None;

                                ParsedElement::EHTOperation(EHTOperationElement {
                                    parameters,
                                    disabled_subchannel_bitmap,
                                    operating_channel_width,
                                })
                            } else {
                                ParsedElement::Unknown(Element::new(element_id, element_data))
                            }
                        }

                        20 => {
                            // Multi-Link
                            if ext_data.len() >= 2 {
                                let control = u16::from_le_bytes([ext_data[0], ext_data[1]]);

                                // Parse common info length
                                let common_info_length = (control & 0x00FF) as usize;

                                if ext_data.len() >= 2 + common_info_length {
                                    let common_info = ext_data[2..2 + common_info_length].to_vec();

                                    // If there's more data, it's link info
                                    let link_info = if ext_data.len() > 2 + common_info_length {
                                        Some(ext_data[2 + common_info_length..].to_vec())
                                    } else {
                                        None
                                    };

                                    ParsedElement::MultiLink(MultiLinkElement {
                                        control,
                                        common_info,
                                        link_info,
                                    })
                                } else {
                                    ParsedElement::Unknown(Element::new(element_id, element_data))
                                }
                            } else {
                                ParsedElement::Unknown(Element::new(element_id, element_data))
                            }
                        }

                        _ => ParsedElement::Unknown(Element::new(element_id, element_data)),
                    }
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }

            48 => {
                // RSN
                if element_data.len() >= 4 {
                    let mut rsn = RSNElement::default();
                    let mut pos = 0;

                    // Version (2 bytes)
                    if pos + 2 <= element_data.len() {
                        rsn.version =
                            u16::from_le_bytes([element_data[pos], element_data[pos + 1]]);
                        pos += 2;
                    }

                    // Group Cipher Suite (4 bytes)
                    if pos + 4 <= element_data.len() {
                        rsn.group_cipher_suite = CipherSuite {
                            oui: [
                                element_data[pos],
                                element_data[pos + 1],
                                element_data[pos + 2],
                            ],
                            suite_type: element_data[pos + 3],
                        };
                        pos += 4;
                    }

                    // Pairwise Cipher Suite Count (2 bytes)
                    if pos + 2 <= element_data.len() {
                        let count =
                            u16::from_le_bytes([element_data[pos], element_data[pos + 1]]) as usize;
                        pos += 2;

                        // Pairwise Cipher Suites (count * 4 bytes)
                        for _ in 0..count {
                            if pos + 4 <= element_data.len() {
                                rsn.pairwise_cipher_suites.push(CipherSuite {
                                    oui: [
                                        element_data[pos],
                                        element_data[pos + 1],
                                        element_data[pos + 2],
                                    ],
                                    suite_type: element_data[pos + 3],
                                });
                                pos += 4;
                            }
                        }
                    }

                    // AKM Suite Count (2 bytes)
                    if pos + 2 <= element_data.len() {
                        let count =
                            u16::from_le_bytes([element_data[pos], element_data[pos + 1]]) as usize;
                        pos += 2;

                        // AKM Suites (count * 4 bytes)
                        for _ in 0..count {
                            if pos + 4 <= element_data.len() {
                                rsn.akm_suites.push(AKMSuite {
                                    oui: [
                                        element_data[pos],
                                        element_data[pos + 1],
                                        element_data[pos + 2],
                                    ],
                                    suite_type: element_data[pos + 3],
                                });
                                pos += 4;
                            }
                        }
                    }

                    // RSN Capabilities (2 bytes)
                    if pos + 2 <= element_data.len() {
                        rsn.rsn_capabilities =
                            u16::from_le_bytes([element_data[pos], element_data[pos + 1]]);
                        pos += 2;
                    }

                    // Optional PMKID Count (2 bytes)
                    if pos + 2 <= element_data.len() {
                        let pmkid_count =
                            u16::from_le_bytes([element_data[pos], element_data[pos + 1]]);
                        rsn.pmkid_count = Some(pmkid_count);
                        pos += 2;

                        // PMKID List (count * 16 bytes)
                        for _ in 0..pmkid_count {
                            if pos + 16 <= element_data.len() {
                                let mut pmkid = [0u8; 16];
                                pmkid.copy_from_slice(&element_data[pos..pos + 16]);
                                rsn.pmkid_list.push(pmkid);
                                pos += 16;
                            }
                        }
                    }

                    // Optional Group Management Cipher Suite (4 bytes)
                    if pos + 4 <= element_data.len() {
                        rsn.group_management_cipher_suite = Some(CipherSuite {
                            oui: [
                                element_data[pos],
                                element_data[pos + 1],
                                element_data[pos + 2],
                            ],
                            suite_type: element_data[pos + 3],
                        });
                    }

                    ParsedElement::RSN(rsn)
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            50 => {
                // Extended Supported Rates
                ParsedElement::ExtendedRates(element_data)
            }
            127 => {
                // Extended Capabilities
                ParsedElement::ExtendedCapabilities(element_data)
            }
            221 => {
                // Vendor Specific
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
            }
            32 => {
                // Power Constraint
                if element_data.len() == 1 {
                    ParsedElement::PowerConstraint(element_data[0])
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            35 => {
                // TPC Report
                if element_data.len() >= 2 {
                    ParsedElement::TPCReport(TPCReportElement {
                        tx_power: element_data[0],
                        link_margin: element_data[1],
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            54 => {
                // Mobility Domain
                if element_data.len() >= 3 {
                    let mdid = u16::from_le_bytes([element_data[0], element_data[1]]);
                    ParsedElement::MobilityDomain(MobilityDomainElement {
                        mdid,
                        flags: element_data[2],
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            11 => {
                // QBSS Load Element
                if element_data.len() >= 5 {
                    let station_count = u16::from_le_bytes([element_data[0], element_data[1]]);
                    let channel_utilization = element_data[2];
                    let available_admission_capacity =
                        u16::from_le_bytes([element_data[3], element_data[4]]);

                    ParsedElement::QBSSLoad(QBSSLoadElement {
                        station_count,
                        channel_utilization,
                        available_admission_capacity,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            70 => {
                // RMEnabledCapabilities
                if element_data.len() >= 1 {
                    ParsedElement::RMEnabledCapabilities(RMEnabledCapabilitiesElement {
                        rm_capabilities: element_data,
                    })
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
            150 => {
                // DMG Capabilities
                ParsedElement::DMGCapabilities(DMGCapabilitiesElement {
                    dmg_capabilities: element_data.to_vec(),
                })
            }
            149 => {
                // Fine Timing Measurement
                ParsedElement::FineTiming(FineTimingElement {
                    timing_capabilities: element_data.to_vec(),
                })
            }

            255 => {
                // Extended Element ID
                if element_data.len() >= 1 {
                    let extended_id = element_data[0];
                    let ext_data = element_data[1..].to_vec();

                    match extended_id {
                        // For now, just handle as unknown
                        _ => ParsedElement::Unknown(Element::new(element_id, element_data)),
                    }
                } else {
                    ParsedElement::Unknown(Element::new(element_id, element_data))
                }
            }
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
            }
            ParsedElement::SupportedRates(rates) => {
                out.push(1); // Supported Rates ID
                out.push(rates.len() as u8); // Length
                out.extend_from_slice(rates);
            }
            ParsedElement::DSParameter(channel) => {
                out.push(3); // DS Parameter ID
                out.push(1); // Length
                out.push(*channel);
            }
            ParsedElement::TIM(tim) => {
                out.push(5); // TIM ID
                let len = 3 + tim.partial_virtual_bitmap.len();
                out.push(len as u8); // Length
                out.push(tim.dtim_count);
                out.push(tim.dtim_period);
                out.push(tim.bitmap_control);
                out.extend_from_slice(&tim.partial_virtual_bitmap);
            }
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
            }
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
            }
            ParsedElement::ExtendedRates(rates) => {
                out.push(50); // Extended Supported Rates ID
                out.push(rates.len() as u8); // Length
                out.extend_from_slice(rates);
            }
            ParsedElement::ExtendedCapabilities(capabilities) => {
                out.push(127); // Extended Capabilities ID
                out.push(capabilities.len() as u8); // Length
                out.extend_from_slice(capabilities);
            }
            ParsedElement::VendorSpecific(vendor) => {
                out.push(221); // Vendor Specific ID
                let len = 4 + vendor.data.len();
                out.push(len as u8); // Length
                out.extend_from_slice(&vendor.oui);
                out.push(vendor.vendor_type);
                out.extend_from_slice(&vendor.data);
            }
            ParsedElement::Unknown(element) => {
                out.push(element.id);
                out.push(element.data.len() as u8);
                out.extend_from_slice(&element.data);
            }

            ParsedElement::HTCapabilities(ht) => {
                out.push(45); // HT Capabilities ID
                out.push(26); // Length
                out.extend_from_slice(&ht.ht_capabilities_info.to_le_bytes());
                out.push(ht.ampdu_parameters);
                out.extend_from_slice(&ht.supported_mcs_set);
                out.extend_from_slice(&ht.ht_extended_capabilities.to_le_bytes());
                out.extend_from_slice(&ht.tx_beam_forming_capabilities.to_le_bytes());
                out.push(ht.asel_capabilities);
            }

            ParsedElement::HTOperation(ht_op) => {
                out.push(61); // HT Operation ID
                out.push(22); // Length
                out.push(ht_op.primary_channel);
                out.extend_from_slice(&ht_op.ht_operation_info);
                out.extend_from_slice(&ht_op.basic_mcs_set);
            }

            ParsedElement::VHTCapabilities(vht) => {
                out.push(191); // VHT Capabilities ID
                out.push(12); // Length
                out.extend_from_slice(&vht.vht_capabilities_info.to_le_bytes());
                out.extend_from_slice(&vht.supported_vht_mcs_and_nss_set.to_le_bytes());
            }

            ParsedElement::VHTOperation(vht_op) => {
                out.push(192); // VHT Operation ID
                out.push(5); // Length
                out.push(vht_op.channel_width);
                out.push(vht_op.channel_center_frequency_segment0);
                out.push(vht_op.channel_center_frequency_segment1);
                out.extend_from_slice(&vht_op.basic_vht_mcs_and_nss_set.to_le_bytes());
            }

            ParsedElement::ChannelSwitch(cs) => {
                out.push(37); // Channel Switch Announcement ID
                out.push(3); // Length
                out.push(cs.switch_mode);
                out.push(cs.new_channel_number);
                out.push(cs.channel_switch_count);
            }

            ParsedElement::ExtendedChannelSwitch(ecs) => {
                out.push(60); // Extended Channel Switch Announcement ID
                out.push(4); // Length
                out.push(ecs.switch_mode);
                out.push(ecs.new_operating_class);
                out.push(ecs.new_channel_number);
                out.push(ecs.channel_switch_count);
            }

            ParsedElement::Quiet(quiet) => {
                out.push(40); // Quiet ID
                out.push(6); // Length
                out.push(quiet.quiet_count);
                out.push(quiet.quiet_period);
                out.extend_from_slice(&quiet.quiet_duration.to_le_bytes());
                out.extend_from_slice(&quiet.quiet_offset.to_le_bytes());
            }

            ParsedElement::ExtendedCapabilities(ec) => {
                out.push(127); // Extended Capabilities ID
                out.push(ec.len() as u8); // Length
                out.extend_from_slice(&ec);
            }

            ParsedElement::SupportedOperatingClasses(soc) => {
                out.push(59); // Supported Operating Classes ID
                out.push((1 + soc.operating_classes.len()) as u8); // Length
                out.push(soc.current_operating_class);
                out.extend_from_slice(&soc.operating_classes);
            }

            ParsedElement::WideBandwidthChannelSwitch(wbcs) => {
                out.push(194); // Wide Bandwidth Channel Switch ID
                out.push(3); // Length
                out.push(wbcs.new_channel_width);
                out.push(wbcs.new_channel_center_frequency_segment0);
                out.push(wbcs.new_channel_center_frequency_segment1);
            }

            ParsedElement::VHTTransmitPowerEnvelope(tpe) => {
                out.push(195); // VHT Transmit Power Envelope ID
                out.push((1 + tpe.max_transmit_power.len()) as u8); // Length
                out.push(tpe.transmit_power_info);
                out.extend_from_slice(&tpe.max_transmit_power);
            }

            ParsedElement::ReducedNeighborReport(rnr) => {
                out.push(201); // Reduced Neighbor Report ID
                let data = encode_reduced_neighbor_report(rnr);
                out.push(data.len() as u8); // Length
                out.extend_from_slice(&data);
            }

            ParsedElement::TransmitPowerEnvelope(tpe) => {
                out.push(195); // Transmit Power Envelope ID
                out.push((1 + tpe.power_constraints.len()) as u8); // Length
                out.push(tpe.power_info);
                out.extend_from_slice(&tpe.power_constraints);
            }

            ParsedElement::HECapabilities(he_caps) => {
                out.push(255); // Extended Element ID

                // Calculate length
                let mut length = 1 + 6 + 11 + 4 + he_caps.ppet.len(); // ext_id + mac + phy + mcs + ppet

                out.push(length as u8); // Length
                out.push(0); // HE Capabilities ext_id

                out.extend_from_slice(&he_caps.he_mac_capabilities);
                out.extend_from_slice(&he_caps.he_phy_capabilities);
                out.extend_from_slice(&he_caps.supported_he_mcs_and_nss_set);
                out.extend_from_slice(&he_caps.ppet);
            }

            ParsedElement::HEOperation(he_op) => {
                out.push(255); // Extended Element ID

                // Calculate base length
                let mut length = 1 + 3 + 1 + 2; // ext_id + params + bss_color + mcs

                // Add lengths of optional fields
                if let Some(vht_op) = &he_op.vht_operation_info {
                    length += vht_op.len();
                }
                if let Some(co_hosted) = &he_op.co_hosted_bss {
                    length += co_hosted.len();
                }
                if let Some(he_6ghz) = &he_op.he_6ghz_operation_info {
                    length += he_6ghz.len();
                }

                out.push(length as u8); // Length
                out.push(1); // HE Operation ext_id

                out.extend_from_slice(&he_op.he_operation_parameters);
                out.push(he_op.bss_color_info);
                out.extend_from_slice(&he_op.basic_he_mcs_and_nss_set.to_le_bytes());

                // Add optional fields
                if let Some(vht_op) = &he_op.vht_operation_info {
                    out.extend_from_slice(vht_op);
                }
                if let Some(co_hosted) = &he_op.co_hosted_bss {
                    out.extend_from_slice(co_hosted);
                }
                if let Some(he_6ghz) = &he_op.he_6ghz_operation_info {
                    out.extend_from_slice(he_6ghz);
                }
            }

            ParsedElement::EHTCapabilities(eht_caps) => {
                out.push(255); // Extended Element ID

                // Calculate length
                let mut length =
                    1 + 2 + 9 + eht_caps.supported_eht_mcs_and_nss_set.len() + eht_caps.ppet.len();

                out.push(length as u8); // Length
                out.push(23); // EHT Capabilities ext_id

                out.extend_from_slice(&eht_caps.eht_mac_capabilities);
                out.extend_from_slice(&eht_caps.eht_phy_capabilities);
                out.extend_from_slice(&eht_caps.supported_eht_mcs_and_nss_set);
                out.extend_from_slice(&eht_caps.ppet);
            }

            ParsedElement::EHTOperation(eht_op) => {
                out.push(255); // Extended Element ID

                // Calculate base length
                let mut length = 1 + 1; // ext_id + params

                // Add lengths of optional fields
                if let Some(disabled) = &eht_op.disabled_subchannel_bitmap {
                    length += disabled.len();
                }
                if let Some(width) = &eht_op.operating_channel_width {
                    length += width.len();
                }

                out.push(length as u8); // Length
                out.push(22); // EHT Operation ext_id

                out.push(eht_op.parameters);

                // Add optional fields
                if let Some(disabled) = &eht_op.disabled_subchannel_bitmap {
                    out.extend_from_slice(disabled);
                }
                if let Some(width) = &eht_op.operating_channel_width {
                    out.extend_from_slice(width);
                }
            }

            ParsedElement::MultiLink(ml) => {
                out.push(255); // Extended Element ID

                // Calculate length
                let mut length = 1 + 2 + ml.common_info.len(); // ext_id + control + common_info
                if let Some(link_info) = &ml.link_info {
                    length += link_info.len();
                }

                out.push(length as u8); // Length
                out.push(20); // Multi-Link ext_id

                out.extend_from_slice(&ml.control.to_le_bytes());
                out.extend_from_slice(&ml.common_info);

                if let Some(link_info) = &ml.link_info {
                    out.extend_from_slice(link_info);
                }
            }

            ParsedElement::PowerConstraint(constraint) => {
                out.push(32); // Power Constraint ID
                out.push(1); // Length
                out.push(*constraint);
            }
            ParsedElement::TPCReport(tpc) => {
                out.push(35); // TPC Report ID
                out.push(2); // Length
                out.push(tpc.tx_power);
                out.push(tpc.link_margin);
            }
            ParsedElement::MobilityDomain(md) => {
                out.push(54); // Mobility Domain ID
                out.push(3); // Length
                out.extend_from_slice(&md.mdid.to_le_bytes());
                out.push(md.flags);
            }
            ParsedElement::QBSSLoad(qbss) => {
                out.push(11); // QBSS Load ID
                out.push(5); // Length
                out.extend_from_slice(&qbss.station_count.to_le_bytes());
                out.push(qbss.channel_utilization);
                out.extend_from_slice(&qbss.available_admission_capacity.to_le_bytes());
            }
            ParsedElement::RMEnabledCapabilities(rmcs) => {
                out.push(70); // RM Enabled Capabilities ID

                // Calculate length
                let mut length = 1; // Resource descriptor count
                length += rmcs.rm_capabilities.len();

                out.push(length as u8); // Length
                out.extend_from_slice(&rmcs.rm_capabilities);
            }
            ParsedElement::DMGCapabilities(dmg) => {
                out.push(150); // DMG Capabilities ID
                out.push(dmg.dmg_capabilities.len() as u8); // Length
                out.extend_from_slice(&dmg.dmg_capabilities);
            }
            ParsedElement::FineTiming(ftm) => {
                out.push(149); // Fine Timing Measurement ID
                out.push(ftm.timing_capabilities.len() as u8); // Length
                out.extend_from_slice(&ftm.timing_capabilities);
            }

            // Keep this final case for unknown elements
            ParsedElement::Unknown(element) => {
                out.push(element.id);
                out.push(element.data.len() as u8);
                out.extend_from_slice(&element.data);
            }
        }
    }

    out
}

// IEEE 802.11 Probe Request Implementation
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encode_suppress)]
pub struct Dot11ProbeReq {
    #[nproto(decode = decode_probe_req_elements, encode = encode_probe_req_elements)]
    pub elements: Vec<ParsedElement>,
}

use crate::*;
use rand::distributions::{Distribution, Standard};
use std::str::FromStr;

// Implementation of Distribution for FrameControl
impl Distribution<FrameControl> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> FrameControl {
        FrameControl {
            protocol_version: rng.gen(),
            frame_type: rng.gen_range(0..4),
            frame_subtype: rng.gen_range(0..16),
            to_ds: rng.gen(),
            from_ds: rng.gen(),
            more_fragments: rng.gen(),
            retry: rng.gen(),
            power_management: rng.gen(),
            more_data: rng.gen(),
            protected: rng.gen(),
            order: rng.gen(),
        }
    }
}

// Implementation of FromStr for FrameControl
impl FromStr for FrameControl {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse from a string like "type=0,subtype=8,tods=0,fromds=0"
        let mut frame_control = FrameControl::default();
        let parts: Vec<&str> = s.split(',').collect();

        for part in parts {
            let kv: Vec<&str> = part.split('=').map(|s| s.trim()).collect();
            if kv.len() != 2 {
                return Err(ValueParseError::Error);
            }

            match kv[0] {
                "protocol" | "protocol_version" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.protocol_version = val;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "type" | "frame_type" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.frame_type = val;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "subtype" | "frame_subtype" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.frame_subtype = val;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "tods" | "to_ds" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.to_ds = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "fromds" | "from_ds" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.from_ds = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "more_fragments" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.more_fragments = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "retry" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.retry = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "power_management" | "power_mgmt" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.power_management = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "more_data" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.more_data = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "protected" | "wep" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.protected = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "order" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        frame_control.order = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                _ => return Err(ValueParseError::Error),
            }
        }

        Ok(frame_control)
    }
}

// Implementation of Distribution for CapabilitiesInfo
impl Distribution<CapabilitiesInfo> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> CapabilitiesInfo {
        CapabilitiesInfo {
            ess: rng.gen(),
            ibss: rng.gen(),
            cf_pollable: rng.gen(),
            cf_poll_request: rng.gen(),
            privacy: rng.gen(),
            short_preamble: rng.gen(),
            pbcc: rng.gen(),
            channel_agility: rng.gen(),
            spectrum_management: rng.gen(),
            qos: rng.gen(),
            short_slot_time: rng.gen(),
            apsd: rng.gen(),
            radio_measurement: rng.gen(),
            dsss_ofdm: rng.gen(),
            delayed_block_ack: rng.gen(),
            immediate_block_ack: rng.gen(),
        }
    }
}

// Implementation of FromStr for CapabilitiesInfo
impl FromStr for CapabilitiesInfo {
    type Err = ValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse from a string like "ess=1,ibss=0,privacy=1"
        let mut caps = CapabilitiesInfo::default();
        let parts: Vec<&str> = s.split(',').collect();

        for part in parts {
            let kv: Vec<&str> = part.split('=').map(|s| s.trim()).collect();
            if kv.len() != 2 {
                return Err(ValueParseError::Error);
            }

            match kv[0] {
                "ess" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.ess = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "ibss" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.ibss = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "cf_pollable" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.cf_pollable = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "cf_poll_request" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.cf_poll_request = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "privacy" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.privacy = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "short_preamble" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.short_preamble = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "pbcc" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.pbcc = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "channel_agility" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.channel_agility = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "spectrum_management" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.spectrum_management = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "qos" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.qos = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "short_slot_time" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.short_slot_time = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "apsd" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.apsd = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "radio_measurement" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.radio_measurement = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "dsss_ofdm" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.dsss_ofdm = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "delayed_block_ack" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.delayed_block_ack = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                "immediate_block_ack" => {
                    if let Ok(val) = kv[1].parse::<u8>() {
                        caps.immediate_block_ack = val != 0;
                    } else {
                        return Err(ValueParseError::Error);
                    }
                }
                _ => return Err(ValueParseError::Error),
            }
        }

        Ok(caps)
    }
}

// Implementation of Encode for RadiotapField
impl Encode for RadiotapField {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            RadiotapField::TSFT(value) => value.encode::<E>(),
            RadiotapField::Flags(flags) => flags.encode::<E>(),
            RadiotapField::Rate(rate) => rate.encode::<E>(),
            RadiotapField::Channel(freq, flags) => {
                let mut result = freq.encode::<E>();
                result.extend_from_slice(&flags.encode::<E>());
                result
            }
            RadiotapField::FHSS(hop_set, hop_pattern) => {
                let mut result = hop_set.encode::<E>();
                result.extend_from_slice(&hop_pattern.encode::<E>());
                result
            }
            RadiotapField::AntennaSignal(signal) => (*signal as u8).encode::<E>(),
            RadiotapField::AntennaNoise(noise) => (*noise as u8).encode::<E>(),
            RadiotapField::LockQuality(quality) => quality.encode::<E>(),
            RadiotapField::TxAttenuation(atten) => atten.encode::<E>(),
            RadiotapField::DBTxAttenuation(atten) => atten.encode::<E>(),
            RadiotapField::DBmTxPower(power) => (*power as u8).encode::<E>(),
            RadiotapField::Antenna(antenna) => antenna.encode::<E>(),
            RadiotapField::DBAntennaSignal(signal) => signal.encode::<E>(),
            RadiotapField::DBAntennaNoise(noise) => noise.encode::<E>(),
            RadiotapField::RxFlags(flags) => flags.encode::<E>(),
            RadiotapField::TxFlags(flags) => flags.encode::<E>(),
            RadiotapField::RtsRetries(retries) => retries.encode::<E>(),
            RadiotapField::DataRetries(retries) => retries.encode::<E>(),
            RadiotapField::XChannel(flags, freq, channel) => {
                let mut result = flags.encode::<E>();
                result.extend_from_slice(&freq.encode::<E>());
                result.push(*channel);
                result
            }
            RadiotapField::MCS(known, flags, mcs) => {
                let mut result = known.encode::<E>();
                result.push(*flags);
                result.push(*mcs);
                result
            }
            RadiotapField::AMPDUStatus(ref_num, flags, crc, reserved) => {
                let mut result = ref_num.encode::<E>();
                result.extend_from_slice(&flags.encode::<E>());
                result.push(*crc);
                result.push(*reserved);
                result
            }
            RadiotapField::VHT(known, flags, bandwidth, mcs_nss) => {
                let mut result = known.encode::<E>();
                result.push(*flags);
                result.push(*bandwidth);
                result.extend_from_slice(mcs_nss);
                result
            }
            RadiotapField::HEData1(data1, data2) => {
                let mut result = data1.encode::<E>();
                result.extend_from_slice(&data2.encode::<E>());
                result
            }
            RadiotapField::HEData2(data3, data4) => {
                let mut result = data3.encode::<E>();
                result.extend_from_slice(&data4.encode::<E>());
                result
            }
            RadiotapField::HEData3(data5, data6) => {
                let mut result = data5.encode::<E>();
                result.extend_from_slice(&data6.encode::<E>());
                result
            }
            RadiotapField::HEData4(data7, data8, data9, data10) => {
                let mut result = vec![*data7, *data8, *data9, *data10];
                result
            }
            RadiotapField::HEData5(data11, data12, data13, data14) => {
                let mut result = vec![*data11, *data12, *data13, *data14];
                result
            }
            RadiotapField::HEData6(data15, data16) => {
                let mut result = vec![*data15, *data16];
                result
            }
            RadiotapField::RadiotapNamespace() => Vec::new(),
            RadiotapField::VendorNamespace(data) => data.clone(),
            RadiotapField::ExtendedBitmap(bitmap) => bitmap.encode::<E>(),
            RadiotapField::Unknown(bit, data) => {
                let mut result = bit.encode::<E>();
                result.extend_from_slice(data);
                result
            }
        }
    }
}

// Marker implementation for AutoEncodeAsSequence for Vec<RadiotapField>
impl AutoEncodeAsSequence for Vec<RadiotapField> {}

// Fix for the frame type-specific decode capabilities
// Each frame type needs its own decode_capabilities and decode_elements functions
// Rather than using the ones from Dot11Beacon

// Function for Dot11ProbeReq elements
pub fn decode_probe_req_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11ProbeReq,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

pub fn encode_probe_req_elements<E: Encoder>(
    my_layer: &Dot11ProbeReq,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

// Function for Dot11ProbeResp capabilities
pub fn decode_probe_resp_capabilities<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11ProbeResp,
) -> Option<(CapabilitiesInfo, usize)> {
    let buf = &buf[ci..];
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let caps = CapabilitiesInfo::from_raw(raw_value);
    Some((caps, delta))
}

// Function for Dot11ProbeResp elements
pub fn decode_probe_resp_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11ProbeResp,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

// Function for Dot11AssocReq capabilities
pub fn decode_assoc_req_capabilities<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11AssocReq,
) -> Option<(CapabilitiesInfo, usize)> {
    let buf = &buf[ci..];
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let caps = CapabilitiesInfo::from_raw(raw_value);
    Some((caps, delta))
}

// Function for Dot11AssocReq elements
pub fn decode_assoc_req_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11AssocReq,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

// Function for Dot11AssocResp capabilities
pub fn decode_assoc_resp_capabilities<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11AssocResp,
) -> Option<(CapabilitiesInfo, usize)> {
    let buf = &buf[ci..];
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let caps = CapabilitiesInfo::from_raw(raw_value);
    Some((caps, delta))
}

// Function for Dot11AssocResp elements
pub fn decode_assoc_resp_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11AssocResp,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

// Function for Dot11ReassocReq capabilities
pub fn decode_reassoc_req_capabilities<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11ReassocReq,
) -> Option<(CapabilitiesInfo, usize)> {
    let buf = &buf[ci..];
    let (raw_value, delta) = u16::decode::<D>(buf)?;
    let caps = CapabilitiesInfo::from_raw(raw_value);
    Some((caps, delta))
}

// Function for Dot11ReassocReq elements
pub fn decode_reassoc_req_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11ReassocReq,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

// Function for Dot11Auth elements
pub fn decode_auth_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11Auth,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

// Function for Dot11Action elements
pub fn decode_action_elements<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut Dot11Action,
) -> Option<(Vec<ParsedElement>, usize)> {
    decode_elements::<D>(buf, ci, &mut Dot11Beacon::default())
}

// Similarly for encode functions
pub fn encode_probe_resp_capabilities<E: Encoder>(
    my_layer: &Dot11ProbeResp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.capabilities.value().to_raw().encode::<E>()
}

pub fn encode_probe_resp_elements<E: Encoder>(
    my_layer: &Dot11ProbeResp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

pub fn encode_assoc_req_capabilities<E: Encoder>(
    my_layer: &Dot11AssocReq,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.capabilities.value().to_raw().encode::<E>()
}

pub fn encode_assoc_req_elements<E: Encoder>(
    my_layer: &Dot11AssocReq,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

pub fn encode_assoc_resp_capabilities<E: Encoder>(
    my_layer: &Dot11AssocResp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.capabilities.value().to_raw().encode::<E>()
}

pub fn encode_assoc_resp_elements<E: Encoder>(
    my_layer: &Dot11AssocResp,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

pub fn encode_reassoc_req_capabilities<E: Encoder>(
    my_layer: &Dot11ReassocReq,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    my_layer.capabilities.value().to_raw().encode::<E>()
}

pub fn encode_reassoc_req_elements<E: Encoder>(
    my_layer: &Dot11ReassocReq,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

pub fn encode_auth_elements<E: Encoder>(
    my_layer: &Dot11Auth,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

pub fn encode_action_elements<E: Encoder>(
    my_layer: &Dot11Action,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    encode_elements::<E>(&Dot11Beacon::default(), stack, my_index, encoded_layers)
}

// Fix for Dot11Data class to handle Option types correctly
// Implementation of From for Option<Value<MacAddr>>
impl From<Option<Value<MacAddr>>> for Value<MacAddr> {
    fn from(opt: Option<Value<MacAddr>>) -> Self {
        match opt {
            Some(val) => val,
            None => Value::Auto,
        }
    }
}

// Implementation of From for Option<Value<u16>>
impl From<Option<Value<u16>>> for Value<u16> {
    fn from(opt: Option<Value<u16>>) -> Self {
        match opt {
            Some(val) => val,
            None => Value::Auto,
        }
    }
}

// Implementation of From for Option<Value<u32>>
impl From<Option<Value<u32>>> for Value<u32> {
    fn from(opt: Option<Value<u32>>) -> Self {
        match opt {
            Some(val) => val,
            None => Value::Auto,
        }
    }
}

// For Value<T> where T might be Value<U>, implement Distribution
impl<T: Clone + std::default::Default> Distribution<Value<T>> for Standard
where
    Standard: Distribution<T>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Value<T> {
        match rng.gen_range(0..4) {
            0 => Value::Auto,
            1 => Value::Random,
            //        2 => Value::Func(|| Standard.sample(rng)),
            _ => Value::Set(Standard.sample(rng)),
        }
    }
}

// Helper function for optional fields in Dot11Data
fn decode_option_value<D: Decoder, T: Decode>(
    buf: &[u8],
    ci: usize,
) -> Option<(Option<Value<T>>, usize)> {
    if ci + 2 <= buf.len() {
        let (val, size) = T::decode::<D>(&buf[ci..])?;
        Some((Some(Value::Set(val)), size))
    } else {
        Some((None, 0))
    }
}

// Fix for the Value::decode issue in Dot11Data
// We need to implement a decode function for Value<T> where T: Decode

impl<T: Decode + Clone + std::default::Default> Decode for Value<T>
where
    Standard: Distribution<T>,
{
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((val, size)) = T::decode::<D>(buf) {
            Some((Value::Set(val), size))
        } else {
            None
        }
    }
}

// Additionally, we need to implement Decode for Option<Value<T>>
impl<T: Decode + Clone + std::default::Default> Decode for Option<Value<T>>
where
    Standard: Distribution<T>,
{
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if buf.is_empty() {
            return Some((None, 0));
        }

        if let Some((val, size)) = Value::<T>::decode::<D>(buf) {
            Some((Some(val), size))
        } else {
            Some((None, 0))
        }
    }
}
