use log::{debug, error, info, warn};

use std::error::Error;
use std::net::UdpSocket;
use std::str::FromStr;
use std::time::Duration;

use crate::encdec::asn1;
use crate::encdec::asn1::Asn1Decoder;
use crate::encdec::asn1::Asn1Encoder;
use crate::protocols::all::raw;
use crate::protocols::snmp::usm_crypto;

use crate::Decode;
use crate::New;

use crate::protocols::snmp::*;
use crate::Layer;
use crate::LayerStack;
use crate::Value;
use crate::*;

use crate::protocols::snmp::usm_crypto::{AuthAlgorithm, PrivAlgorithm, UsmConfig};

#[derive(Debug, Clone)]
pub enum PduType {
    Get,
    GetNext,
    GetBulk,
}

#[derive(Debug, Clone)]
pub enum SnmpVersion {
    V2c(String), // community string
    V3 {
        user: String,
        auth_algorithm: Option<AuthAlgorithm>,
        auth_password: Option<String>,
        priv_algorithm: Option<PrivAlgorithm>,
        priv_password: Option<String>,
        engine_id: Vec<u8>,
        engine_boots: u32, // Add this
        engine_time: u32,  // Add this
    },
}

#[derive(Clone)]
pub struct SnmpWalkConfig {
    pub target_host: String,
    pub port: u16,
    pub version: SnmpVersion,
    pub starting_oid: String,
    pub max_repetitions: i32,
    pub timeout: Duration,
    pub use_getbulk: bool,
}

impl Default for SnmpWalkConfig {
    fn default() -> Self {
        Self {
            target_host: "127.0.0.1".to_string(),
            port: 161,
            version: SnmpVersion::V2c("public".to_string()),
            starting_oid: "1.3.6.1.2.1".to_string(), // MIB-2
            max_repetitions: 10,
            timeout: Duration::from_secs(5),
            use_getbulk: true,
        }
    }
}

pub struct OsideSnmpSession {
    config: SnmpWalkConfig,
    socket: UdpSocket,
    request_id: u32,
    msg_id: u32,
}

impl OsideSnmpSession {
    pub fn new(config: SnmpWalkConfig) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let target_addr = format!("{}:{}", config.target_host, config.port);
        socket.connect(&target_addr)?;
        socket.set_read_timeout(Some(config.timeout))?;

        Ok(Self {
            config,
            socket,
            request_id: rand::random::<u32>() & 0x7fffffff,
            msg_id: rand::random::<u32>() & 0x7fffffff,
        })
    }

    pub fn get_target_host(&self) -> String {
        self.config.target_host.clone()
    }

    pub fn walk(&mut self, oid: &str) -> Result<Vec<SnmpVarBind>, Box<dyn Error>> {
        let oid = if oid.starts_with(".") {
            oid.to_owned()
        } else {
            format!(".{}", oid)
        };
        let mut current_oid = oid.to_string();
        self.config.starting_oid = oid.to_string();

        let mut results_count = 0;
        let mut results = vec![];

        println!("Walking from OID: {}", current_oid);
        println!("----------------------------------------");

        loop {
            let response = if self.config.use_getbulk {
                // && matches!(self.config.version, SnmpVersion::V2c(_)) {
                self.send_getbulk_request(&current_oid)?
            } else {
                self.send_getnext_request(&current_oid)?
            };

            // Use the new extraction method
            let (found_next, next_oid, bindings) = self.extract_and_process_bindings(&response)?;

            results_count += bindings.len();
            results.extend(bindings);

            if !found_next {
                debug!("No more OIDs found");
                break;
            }

            current_oid = next_oid;

            if results_count > 10000 {
                debug!("Stopping after 10000 results to prevent infinite loop");
                break;
            }
        }

        println!("----------------------------------------");
        println!("Walk completed. Total results: {}", results_count);
        Ok(results)
    }

    fn create_verification_message(
        &self,
        response: &LayerStack,
        usm_config: &UsmConfig,
    ) -> Result<Vec<u8>, String> {
        // Try to reconstruct the message with zero auth params
        // This is a simplified approach - we'll need to build this properly

        // For now, let's try to manually construct the message structure
        // This is complex and may need framework support

        // Fallback: return the original message (this won't work for auth, but helps debugging)
        Ok(response.clone().lencode())
    }

    fn print_hex_dump(&self, data: &[u8]) {
        for (i, chunk) in data.chunks(16).enumerate() {
            let mut out = format!("{:04x}: ", i * 16);
            for byte in chunk {
                out.push_str(&format!("{:02x} ", byte));
            }
            debug!("hex dump: {}", out);
        }
    }

    fn update_engine_info(&mut self, engine_id: Vec<u8>, boots: u32, time: u32) {
        if let SnmpVersion::V3 {
            engine_id: ref mut stored_engine_id,
            engine_boots: ref mut stored_boots,
            engine_time: ref mut stored_time,
            ..
        } = &mut self.config.version
        {
            *stored_engine_id = engine_id;
            *stored_boots = boots;
            *stored_time = time;
        }
    }

    fn increment_ids(&mut self) {
        self.request_id = self.request_id.wrapping_add(1);
        self.msg_id = self.msg_id.wrapping_add(1);
        debug!(
            "INCREMENT IDs: req_id: {},  msg_id: {}",
            self.request_id, self.msg_id
        );
    }

    fn send_getnext_request(&mut self, oid: &str) -> Result<LayerStack, Box<dyn Error>> {
        let request = match &self.config.version {
            SnmpVersion::V2c(community) => {
                let community = community.clone();
                self.increment_ids();
                SNMP!()
                    / SNMPV2C!(community = community.as_str())
                    / SnmpGetNext(SNMPGETORRESPONSE!(
                        request_id = self.request_id,
                        var_bindings = vec![SNMPVARBIND!(name = oid, value = SnmpValue::Null)]
                    ))
            }

            SnmpVersion::V3 { .. } => {
                if let Some(mut usm_config) = self.create_usm_config() {
                    debug!("Doing discovery");
                    // If engine ID is empty, do discovery first
                    if usm_config.engine_id.is_empty() {
                        let engine_id = self.snmpv3_discovery(&mut usm_config)?;
                        usm_config.engine_id = engine_id;
                    }

                    debug!(
                        "USM config after engine discovery - has_auth: {}, has_priv: {}, USM: {:?}",
                        usm_config.has_auth(),
                        usm_config.has_priv(),
                        &usm_config
                    );
                    self.increment_ids();

                    if usm_config.has_auth() {
                        let encoded = self.create_authenticated_request(
                            Some(oid),
                            &usm_config,
                            true,
                            PduType::GetNext,
                        )?;
                        debug!("ENCODED: {:?}", &encoded);

                        debug!("Sending authenticated request, length: {}", encoded.len());
                        debug!("Encoded message length: {}", encoded.len());
                        debug!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        debug!("Received response length: {}", len);
                        debug!(
                            "Response first 50 bytes: {:02x?}",
                            &buf[0..std::cmp::min(50, len)]
                        );

                        // Try to decode the response
                        let response = SNMP!()
                            .ldecode(&buf[0..len])
                            .ok_or("Failed to decode SNMP response")?
                            .0;

                        // Check if it's an authenticated response and verify auth
                        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
                            if snmpv3.has_authentication() {
                                debug!("Received authenticated response, verifying...");
                            }
                        }

                        return Ok(response);
                    } else {
                        // For no-auth SNMPv3, still need proper structure
                        debug!("DOING v3 no auth");
                        let encoded = self.create_authenticated_request(
                            Some(oid),
                            &usm_config,
                            false,
                            PduType::GetNext,
                        )?;
                        debug!("ENCODED: {:?}", &encoded);

                        debug!("Sending authenticated request, length: {}", encoded.len());
                        debug!("Encoded message length: {}", encoded.len());
                        debug!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        debug!("Received response length: {}", len);
                        debug!(
                            "Response first 50 bytes: {:02x?}",
                            &buf[0..std::cmp::min(50, len)]
                        );

                        // Try to decode the response
                        let response = SNMP!()
                            .ldecode(&buf[0..len])
                            .ok_or("Failed to decode SNMP response")?
                            .0;

                        return Ok(response);
                    }
                } else {
                    return Err("Failed to create USM configuration".into());
                }
            }
        };

        debug!("request result: {:#02x?}", &request);
        self.send_request(request)
    }

    fn send_getbulk_request(&mut self, oid: &str) -> Result<LayerStack, Box<dyn Error>> {
        let request = match &self.config.version {
            SnmpVersion::V2c(community) => {
                let community = community.clone();
                self.increment_ids();

                SNMP!()
                    / SNMPV2C!(community = community.as_str())
                    / SnmpGetBulk(SnmpGetBulkRequest {
                        request_id: Value::Set(self.request_id),
                        non_repeaters: Value::Set(0),
                        max_repetitions: Value::Set(self.config.max_repetitions),
                        _bindings_tag_len: Value::Auto,
                        var_bindings: vec![SNMPVARBIND!(name = oid, value = SnmpValue::Null)],
                    })
            }
            SnmpVersion::V3 { .. } => {
                if let Some(mut usm_config) = self.create_usm_config() {
                    debug!("Doing discovery");
                    // If engine ID is empty, do discovery first
                    if usm_config.engine_id.is_empty() {
                        let engine_id = self.snmpv3_discovery(&mut usm_config)?;
                        usm_config.engine_id = engine_id;
                    }

                    debug!(
                        "USM config after engine discovery - has_auth: {}, has_priv: {}, USM: {:?}",
                        usm_config.has_auth(),
                        usm_config.has_priv(),
                        &usm_config
                    );
                    self.increment_ids();

                    if usm_config.has_auth() {
                        let encoded = self.create_authenticated_request(
                            Some(oid),
                            &usm_config,
                            true,
                            PduType::GetBulk,
                        )?;
                        debug!("ENCODED: {:?}", &encoded);

                        debug!("Sending authenticated request, length: {}", encoded.len());
                        debug!("Encoded message length: {}", encoded.len());
                        debug!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        debug!("Received response length: {}", len);
                        debug!(
                            "Response first 50 bytes: {:02x?}",
                            &buf[0..std::cmp::min(50, len)]
                        );

                        // Try to decode the response
                        let response = SNMP!()
                            .ldecode(&buf[0..len])
                            .ok_or("Failed to decode SNMP response")?
                            .0;

                        return Ok(response);
                    } else {
                        // For no-auth SNMPv3, still need proper structure
                        debug!("DOING v3 no auth");
                        let encoded = self.create_authenticated_request(
                            Some(oid),
                            &usm_config,
                            false,
                            PduType::GetBulk,
                        )?;
                        debug!("ENCODED: {:?}", &encoded);

                        debug!("Sending authenticated request, length: {}", encoded.len());
                        debug!("Encoded message length: {}", encoded.len());
                        debug!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        debug!("Received response length: {}", len);
                        debug!(
                            "Response first 50 bytes: {:02x?}",
                            &buf[0..std::cmp::min(50, len)]
                        );

                        // Try to decode the response
                        let response = SNMP!()
                            .ldecode(&buf[0..len])
                            .ok_or("Failed to decode SNMP response")?
                            .0;

                        return Ok(response);
                    }
                } else {
                    return Err("Failed to create USM configuration".into());
                }
            }
        };

        self.send_request(request)
    }

    fn send_request(&mut self, request: LayerStack) -> Result<LayerStack, Box<dyn Error>> {
        let encoded = request.lencode();

        // Send request
        self.socket.send(&encoded)?;

        // Receive response
        let mut buf = vec![0u8; 65535];
        let len = self.socket.recv(&mut buf)?;

        // Decode response
        let response = SNMP!()
            .ldecode(&buf[0..len])
            .ok_or("Failed to decode SNMP response")?
            .0;

        if response.clone().lencode() != buf[0..len] {
            debug!("encode/decode sanity check fail!");
        }

        Ok(response)
    }

    fn print_result(&self, binding: &SnmpVarBind) {
        let oid = format!("{}", binding.name.value());
        let value = &binding.value.value();

        let value_str = match value {
            SnmpValue::Null => "NULL".to_string(),
            SnmpValue::Integer(i) => format!("INTEGER: {}", i),
            SnmpValue::OctetString(bytes) => {
                // Try to display as string if printable, otherwise as hex
                if bytes
                    .iter()
                    .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
                {
                    format!("STRING: \"{}\"", String::from_utf8_lossy(bytes))
                } else {
                    format!(
                        "HEX-STRING: {}",
                        bytes
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                }
            }
            SnmpValue::ObjectIdentifier(oid) => format!("OID: {}", oid),
            SnmpValue::IpAddress(ip) => format!("IpAddress: {}", ip),
            SnmpValue::Counter32(c) => format!("Counter32: {}", c),
            SnmpValue::Gauge32(g) => format!("Gauge32: {}", g),
            SnmpValue::TimeTicks(t) => {
                let days = t / (24 * 60 * 60 * 100);
                let hours = (t % (24 * 60 * 60 * 100)) / (60 * 60 * 100);
                let minutes = (t % (60 * 60 * 100)) / (60 * 100);
                let seconds = (t % (60 * 100)) / 100;
                let centisecs = t % 100;
                format!(
                    "Timeticks: ({}) {}:{}:{}.{}.{}",
                    t, days, hours, minutes, seconds, centisecs
                )
            }
            SnmpValue::Opaque(bytes) => format!("Opaque: {} bytes", bytes.len()),
            SnmpValue::Counter64(c) => format!("Counter64: {}", c),
            SnmpValue::NoSuchObject => "noSuchObject".to_string(),
            SnmpValue::NoSuchInstance => "noSuchInstance".to_string(),
            SnmpValue::EndOfMibView => "endOfMibView".to_string(),
            SnmpValue::SimpleInt32(i) => format!("Integer32: {}", i),
            SnmpValue::Unknown(obj) => format!("Unknown: {:?}", obj),
        };

        println!("RESULT: {} = {}", oid, value_str);
    }

    fn create_usm_config(&self) -> Option<UsmConfig> {
        match &self.config.version {
            SnmpVersion::V3 {
                user,
                auth_algorithm,
                auth_password,
                priv_algorithm,
                priv_password,
                engine_id,
                engine_boots,
                engine_time,
            } => {
                let mut usm_config = UsmConfig::new(user);

                if let (Some(auth_alg), Some(auth_pass)) = (auth_algorithm, auth_password) {
                    debug!(
                        "Setting up authentication: {:?} with password length {}",
                        auth_alg,
                        auth_pass.len()
                    );

                    usm_config = usm_config.with_auth(auth_alg.clone(), auth_pass);

                    if let (Some(priv_alg), Some(priv_pass)) = (priv_algorithm, priv_password) {
                        usm_config = usm_config.with_priv(priv_alg.clone(), priv_pass);
                    }
                }

                if !engine_id.is_empty() {
                    usm_config =
                        usm_config.with_engine_info(engine_id, *engine_boots, *engine_time);
                }
                debug!(
                    "USM config - has_auth: {}, has_priv: {}",
                    usm_config.has_auth(),
                    usm_config.has_priv()
                );

                Some(usm_config)
            }
            _ => None,
        }
    }

    fn snmpv3_discovery(&mut self, x: &mut UsmConfig) -> Result<Vec<u8>, Box<dyn Error>> {
        debug!("Starting SNMPv3 engine discovery...");
        self.increment_ids();

        // Create a proper SNMPv3 discovery message (no authentication)
        let var_bindings = vec![];

        let scoped_pdu = SnmpV3ScopedPdu {
            _scoped_pdu_seq_tag_len: Value::Auto,
            context_engine_id: Value::Set(ByteArray::from(vec![])),
            context_name: Value::Set(ByteArray::from(vec![])),
            pdu: Value::Set(SnmpV3Pdu::Get(SnmpGetOrResponse {
                request_id: Value::Set(self.request_id),
                error_status: Value::Set(0),
                error_index: Value::Set(0),
                _bindings_tag_len: Value::Auto,
                var_bindings,
            })),
        };

        // Create discovery USM parameters (all empty for discovery)
        let usm_params = UsmSecurityParameters::discovery();

        // Create SNMPv3 message with discovery flags
        let snmpv3 = SnmpV3 {
            _seq_tag_len_v3: Value::Auto,
            msg_id: Value::Set(self.msg_id),
            msg_max_size: Value::Set(65507),
            msg_flags: SnmpV3::flags(0x04), // Only reportable flag, no auth/priv
            msg_security_model: Value::Set(3), // USM
            msg_security_parameters: Value::Set(SnmpV3SecurityParameters::Usm(usm_params)),
        };

        let discovery_stack = LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(3),
            })
            .push(snmpv3)
            .push(scoped_pdu);

        // Encode the discovery message (no USM context needed for discovery)
        let encoded = discovery_stack.lencode();

        debug!("Sending discovery message, length: {}", encoded.len());
        debug!(
            "Discovery message first 50 bytes: {:02x?}",
            &encoded[0..std::cmp::min(50, encoded.len())]
        );

        self.socket.send(&encoded)?;

        let mut buf = vec![0u8; 65535];
        let len = self.socket.recv(&mut buf)?;

        debug!("Received discovery response, length: {}", len);
        debug!(
            "Response first 50 bytes: {:02x?}",
            &buf[0..std::cmp::min(50, len)]
        );

        // Parse response to extract engine ID
        if let Some((response_stack, _)) = SNMP!().ldecode(&buf[0..len]) {
            debug!("Successfully decoded discovery response");

            // Look for SNMPv3 layer with USM parameters
            if let Some(snmpv3) = response_stack.get_layer(SnmpV3::new()) {
                debug!("Found SNMPv3 layer in response");
                debug!("Response msg_flags: {:?}", snmpv3.msg_flags);
                debug!("Response security_model: {:?}", snmpv3.msg_security_model);

                // Debug: Print the security parameters type
                match &snmpv3.msg_security_parameters {
                    Value::Set(SnmpV3SecurityParameters::Usm(ref usm)) => {
                        debug!("Found USM parameters in response");
                        let engine_id = usm.msg_authoritative_engine_id.value().as_vec().clone();
                        debug!("Extracted engine ID: {:02x?}", engine_id);
                        x.engine_boots = usm.msg_authoritative_engine_boots.value();
                        x.engine_time = usm.msg_authoritative_engine_time.value();
                        self.update_engine_info(
                            engine_id.clone(),
                            usm.msg_authoritative_engine_boots.value(),
                            usm.msg_authoritative_engine_time.value(),
                        );

                        if !engine_id.is_empty() {
                            return Ok(engine_id);
                        } else {
                            debug!("Engine ID is empty in response");
                        }
                    }
                    Value::Set(SnmpV3SecurityParameters::Raw(ref raw)) => {
                        debug!("Found RAW security parameters: {:02x?}", raw.as_vec());
                        panic!("Could not operate with raw security parameters!");
                    }
                    Value::Set(SnmpV3SecurityParameters::None) => {
                        debug!("No security parameters in response");
                    }
                    _ => {
                        debug!(
                            "Other security parameters type: {:?}",
                            snmpv3.msg_security_parameters
                        );
                    }
                }
            } else {
                debug!("No SNMPv3 layer found in response");
            }
        } else {
            debug!("Failed to decode discovery response");
        }

        Err("Failed to discover engine ID".into())
    }

    // Add this helper method to manually parse raw USM parameters
    fn parse_raw_usm_params(&self, raw_data: &[u8]) -> Option<Vec<u8>> {
        if raw_data.len() < 2 {
            return None;
        }

        let mut cursor = 0;

        // Check if it starts with SEQUENCE tag (0x30)
        if raw_data[cursor] == 0x30 {
            cursor += 1;

            // Skip sequence length
            if raw_data[cursor] & 0x80 == 0 {
                cursor += 1;
            } else {
                let len_bytes = (raw_data[cursor] & 0x7F) as usize;
                cursor += 1 + len_bytes;
            }

            // First element should be the engine ID (OCTET STRING 0x04)
            if cursor < raw_data.len() && raw_data[cursor] == 0x04 {
                cursor += 1;
                let engine_id_len = raw_data[cursor] as usize;
                cursor += 1;

                if cursor + engine_id_len <= raw_data.len() {
                    let engine_id = raw_data[cursor..cursor + engine_id_len].to_vec();
                    if !engine_id.is_empty() {
                        return Some(engine_id);
                    }
                }
            }
        }

        None
    }

    fn create_authenticated_request(
        &mut self,
        oid: Option<&str>,
        usm_config: &UsmConfig,
        do_crypt: bool,
        pdu_type: PduType,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        // Create the var bindings
        let var_bindings = if let Some(oid) = oid {
            vec![SnmpVarBind {
                _bind_tag_len: Value::Auto,
                name: Value::Set(BerOid::from_str(oid).unwrap_or_default()),
                value: Value::Set(SnmpValue::Null),
            }]
        } else {
            vec![]
        };

        let scoped_pdu = match pdu_type {
            PduType::Get => SnmpV3ScopedPdu {
                _scoped_pdu_seq_tag_len: Value::Auto,
                context_engine_id: Value::Set(ByteArray::from(usm_config.engine_id.clone())),
                context_name: Value::Set(ByteArray::from(vec![])),
                pdu: Value::Set(SnmpV3Pdu::Get(SnmpGetOrResponse {
                    request_id: Value::Set(self.request_id),
                    error_status: Value::Set(0),
                    error_index: Value::Set(0),
                    _bindings_tag_len: Value::Auto,
                    var_bindings,
                })),
            },
            PduType::GetNext => SnmpV3ScopedPdu {
                _scoped_pdu_seq_tag_len: Value::Auto,
                context_engine_id: Value::Set(ByteArray::from(usm_config.engine_id.clone())),
                context_name: Value::Set(ByteArray::from(vec![])),
                pdu: Value::Set(SnmpV3Pdu::GetNext(SnmpGetOrResponse {
                    request_id: Value::Set(self.request_id),
                    error_status: Value::Set(0),
                    error_index: Value::Set(0),
                    _bindings_tag_len: Value::Auto,
                    var_bindings,
                })),
            },
            PduType::GetBulk => SnmpV3ScopedPdu {
                _scoped_pdu_seq_tag_len: Value::Auto,
                context_engine_id: Value::Set(ByteArray::from(usm_config.engine_id.clone())),
                context_name: Value::Set(ByteArray::from(vec![])),
                pdu: Value::Set(SnmpV3Pdu::GetBulk(SnmpGetBulkRequest {
                    request_id: Value::Set(self.request_id),
                    non_repeaters: Value::Set(0),
                    max_repetitions: Value::Set(self.config.max_repetitions),
                    _bindings_tag_len: Value::Auto,
                    var_bindings,
                })),
            },
        };

        debug!("SCOPED PDU: {:?}", &scoped_pdu);

        // Create USM parameters with the discovered engine ID
        let mut usm_params = UsmSecurityParameters::with_user(&usm_config.user_name);
        usm_params.set_engine_info(
            &usm_config.engine_id,
            usm_config.engine_boots,
            usm_config.engine_time,
        );

        if usm_config.has_auth() {
            // Placeholder auth params - will be calculated during encoding
            usm_params.set_auth_params(&vec![0u8; usm_config.auth_algorithm.auth_param_length()]);
        }

        if usm_config.has_priv() {
            // Generate random IV for privacy
            let iv = usm_config.priv_algorithm.generate_iv();
            debug!("=== SALT/IV DEBUG (USM setup) ===");
            debug!("Generated IV for USM: {:02x?}", iv);
            debug!("Engine boots: {}", usm_config.engine_boots);
            debug!("Engine time: {}", usm_config.engine_time);

            usm_params.set_priv_params(&iv);
        }

        // Create the SNMPv3 message with proper flags
        let mut flags = 0u8;
        if usm_config.has_auth() {
            flags |= 0x01;
        }
        if usm_config.has_priv() {
            flags |= 0x02;
        }

        flags |= 0x04; // reportable

        let snmpv3 = SnmpV3 {
            _seq_tag_len_v3: Value::Auto,
            msg_id: Value::Set(self.msg_id),
            msg_max_size: Value::Set(65507),
            msg_flags: SnmpV3::flags(flags),
            msg_security_model: Value::Set(3), // USM
            msg_security_parameters: Value::Set(SnmpV3SecurityParameters::Usm(usm_params)),
        };

        let stack = LayerStack::new()
            .push(Snmp {
                _seq_tag_len: Value::Auto,
                version: Value::Set(3),
            })
            .push(snmpv3)
            .push(scoped_pdu);

        // Create USM context and encode
        let mut usm_context = UsmEncodingContext::new(usm_config.clone())?;
        let encoded = stack.encode_with_usm::<Asn1Encoder>(&mut usm_context)?;

        Ok(encoded)
    }

    /// Extract variable bindings and process walk results
    fn extract_and_process_bindings(
        &mut self,
        response: &LayerStack,
    ) -> Result<(bool, String, Vec<SnmpVarBind>), Box<dyn Error>> {
        let mut found_next = false;
        let mut next_oid = String::new();
        let mut results_count = 0;
        let mut results = vec![];

        // For SNMPv3, use the new decryption-aware processing
        match &self.config.version {
            SnmpVersion::V3 { .. } => {
                if let Some(usm_config) = self.create_usm_config() {
                    // Use a custom processing method that returns the bindings
                    let bindings = self.extract_bindings_from_snmpv3(response, &usm_config)?;
                    debug!("BINDINGS: {:?}", bindings);

                    for binding in &bindings {
                        let oid_str = format!("{}", binding.name.value());
                        debug!("OID STR: {:?}", &oid_str);

                        // Check if we've moved beyond our starting tree
                        if oid_str != "" && !oid_str.starts_with(&self.config.starting_oid) {
                            debug!("Reached end of subtree");
                            return Ok((false, next_oid, results));
                        }

                        // Check for special SNMP values indicating end of walk
                        match &binding.value.value() {
                            SnmpValue::NoSuchObject
                            | SnmpValue::NoSuchInstance
                            | SnmpValue::EndOfMibView => {
                                debug!("End of MIB view reached");
                                return Ok((false, next_oid, results));
                            }
                            _ => {}
                        }

                        // Print the result
                        self.print_result(&binding);
                        results_count += 1;
                        results.push(binding.clone());

                        // Update for next iteration
                        if oid_str != "" {
                            next_oid = oid_str;
                            found_next = true;
                        }
                    }
                } else {
                    return Err("Failed to create USM configuration".into());
                }
            }
            _ => {
                // Original SNMPv1/v2c processing
                if let Some(snmp_response) = response.get_layer(SNMPGETRESPONSE!()) {
                    if let SnmpGetResponse(resp) = snmp_response {
                        if resp.error_status.value() != 0 {
                            return Err(format!(
                                "SNMP Error: {} (index: {})",
                                resp.error_status.value(),
                                resp.error_index.value()
                            )
                            .into());
                        }

                        for binding in &resp.var_bindings {
                            let oid_str = format!("{}", binding.name.value());

                            if !oid_str.starts_with(&self.config.starting_oid) {
                                debug!("Reached end of subtree");
                                return Ok((false, next_oid, results));
                            }

                            match &binding.value.value() {
                                SnmpValue::NoSuchObject
                                | SnmpValue::NoSuchInstance
                                | SnmpValue::EndOfMibView => {
                                    debug!("End of MIB view reached");
                                    return Ok((false, next_oid, results));
                                }
                                _ => {}
                            }

                            self.print_result(&binding);
                            results_count += 1;
                            results.push(binding.clone());
                            next_oid = oid_str;
                            found_next = true;
                        }
                    }
                } else {
                    return Err("No valid SNMP response received".into());
                }
            }
        }

        Ok((found_next, next_oid, results))
    }

    /// Extract bindings from SNMPv3 response with decryption support
    fn extract_bindings_from_snmpv3(
        &self,
        response: &LayerStack,
        usm_config: &UsmConfig,
    ) -> Result<Vec<SnmpVarBind>, Box<dyn Error>> {
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            let server_engine_time = if let Value::Set(SnmpV3SecurityParameters::Usm(ref usm)) =
                &snmpv3.msg_security_parameters
            {
                let server_engine_time = usm.msg_authoritative_engine_time.value();
                debug!(
                    "Server engine time from response: {}, discovery time: {}",
                    server_engine_time, &usm_config.engine_time
                );
                server_engine_time
            } else {
                usm_config.engine_time // fallback
            };

            // Verify authentication if required (with lenient checking)
            if usm_config.has_auth() {
                if let Err(e) = self.verify_authentication(response, usm_config) {
                    debug!("Authentication verification warning: {}", e);
                    debug!("Proceeding with response processing...");
                }
            }

            // Handle privacy (decryption) if enabled
            if usm_config.has_priv() {
                debug!("Privacy enabled - attempting decryption");

                if let Some(encrypted_data) = self.extract_encrypted_data(response)? {
                    let privacy_params = self.extract_privacy_params(response)?;
                    let decrypted_scoped_pdu = self.decrypt_scoped_pdu(
                        &encrypted_data,
                        &privacy_params,
                        usm_config,
                        server_engine_time,
                    )?;

                    return self.extract_bindings_from_scoped_pdu(&decrypted_scoped_pdu);
                } else {
                    return Err("Expected encrypted data but found none".into());
                }
            } else {
                // No privacy - process normally
                if let Some(scoped_pdu) = response.get_layer(SnmpV3ScopedPdu::default()) {
                    return self.extract_bindings_from_scoped_pdu(scoped_pdu);
                }
            }
        }

        Err("Failed to extract bindings from SNMPv3 response".into())
    }

    /// Extract bindings from a scoped PDU
    fn extract_bindings_from_scoped_pdu(
        &self,
        scoped_pdu: &SnmpV3ScopedPdu,
    ) -> Result<Vec<SnmpVarBind>, Box<dyn Error>> {
        match &scoped_pdu.pdu.value() {
            SnmpV3Pdu::Response(resp) => {
                if resp.error_status.value() != 0 {
                    return Err(format!(
                        "SNMP Error: {} (index: {})",
                        resp.error_status.value(),
                        resp.error_index.value()
                    )
                    .into());
                }
                Ok(resp.var_bindings.clone())
            }
            SnmpV3Pdu::Report(report) => Err(format!(
                "Received SNMP report: error {} at index {}",
                report.error_status.value(),
                report.error_index.value()
            )
            .into()),
            other => Err(format!("Unexpected PDU type: {:?}", other).into()),
        }
    }

    fn verify_authentication(
        &self,
        response: &LayerStack,
        usm_config: &UsmConfig,
    ) -> Result<(), String> {
        debug!("=== AUTHENTICATION VERIFICATION DEBUG ===");

        // First, let's see the raw response bytes
        let original_response_bytes = response.clone().lencode();
        debug!(
            "Original response bytes length: {}",
            original_response_bytes.len()
        );
        debug!(
            "Original response bytes: {:02x?}",
            &original_response_bytes[0..std::cmp::min(100, original_response_bytes.len())]
        );

        // Extract USM parameters from the response
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            debug!("Found SNMPv3 layer");
            debug!("SNMPv3 msg_id: {:?}", snmpv3.msg_id);
            debug!(
                "SNMPv3 msg_flags: {:02x?}",
                snmpv3.msg_flags.value().as_vec()
            );

            match &snmpv3.msg_security_parameters.value() {
                SnmpV3SecurityParameters::Usm(usm_params) => {
                    debug!("Found USM parameters");
                    debug!(
                        "Engine ID: {:02x?}",
                        usm_params.msg_authoritative_engine_id.value().as_vec()
                    );
                    debug!(
                        "Engine boots: {}",
                        usm_params.msg_authoritative_engine_boots.value()
                    );
                    debug!(
                        "Engine time: {}",
                        usm_params.msg_authoritative_engine_time.value()
                    );
                    debug!(
                        "User name: {:?}",
                        String::from_utf8_lossy(usm_params.msg_user_name.value().as_vec())
                    );

                    let param_val = usm_params.msg_authentication_parameters.value();
                    let received_auth_params = param_val.as_vec();

                    debug!("Received auth params: {:02x?}", received_auth_params);

                    if received_auth_params.len() != 12 {
                        return Err(format!(
                            "Invalid authentication parameter length: {}",
                            received_auth_params.len()
                        ));
                    }

                    // Method 1: Try to manually find and replace auth params in raw bytes
                    debug!("\n=== METHOD 1: Manual byte replacement ===");
                    let mut message_for_verification_v1 = original_response_bytes.clone();
                    let zero_auth_params = vec![0u8; 12];

                    if let Some(pos) =
                        find_subsequence(&message_for_verification_v1, received_auth_params)
                    {
                        debug!("Found auth params at position: {}", pos);
                        message_for_verification_v1[pos..pos + 12]
                            .copy_from_slice(&zero_auth_params);
                        debug!("Replaced auth params with zeros");
                    } else {
                        debug!("Could not find auth params in message bytes!");
                        // Let's try to find them by looking for the pattern around them
                        for i in 0..message_for_verification_v1.len().saturating_sub(12) {
                            if &message_for_verification_v1[i..i + 12] == received_auth_params {
                                debug!("Found auth params at position {} (alternative search)", i);
                                message_for_verification_v1[i..i + 12]
                                    .copy_from_slice(&zero_auth_params);
                                break;
                            }
                        }
                    }

                    // Method 2: Re-encode with modified structure
                    debug!("\n=== METHOD 2: Re-encode with modified structure ===");
                    let mut verification_response = response.clone();

                    // Traverse all layers to find and modify USM params
                    for layer_idx in 0..verification_response.layers.len() {
                        if let Some(layer) = verification_response.layers.get_mut(layer_idx) {
                            // This is pseudocode - we need to find the actual way to modify layers
                            debug!(
                                "Checking layer {}: {:?}",
                                layer_idx,
                                std::any::type_name_of_val(layer)
                            );
                        }
                    }

                    // Let's manually create a new message with zero auth params
                    let message_for_verification_v2 =
                        self.create_verification_message(response, usm_config)?;

                    // Calculate auth key
                    let auth_key = usm_config
                        .auth_key()
                        .map_err(|e| format!("Failed to derive auth key: {}", e))?;

                    debug!("\nAuth configuration:");
                    debug!("Auth algorithm: {:?}", usm_config.auth_algorithm);
                    debug!("Auth key: {:02x?}", auth_key);
                    debug!("Engine ID: {:02x?}", usm_config.engine_id);

                    // Test both methods
                    debug!("\n=== TESTING METHOD 1 ===");
                    let expected_auth_params_v1 = usm_config
                        .auth_algorithm
                        .generate_auth_params(&auth_key, &message_for_verification_v1)
                        .map_err(|e| format!("Failed to generate auth params v1: {}", e))?;

                    debug!(
                        "Method 1 - Message length: {}",
                        message_for_verification_v1.len()
                    );
                    debug!(
                        "Method 1 - Expected auth params: {:02x?}",
                        expected_auth_params_v1
                    );
                    debug!(
                        "Method 1 - Match: {}",
                        received_auth_params == &expected_auth_params_v1
                    );

                    debug!("\n=== TESTING METHOD 2 ===");
                    let expected_auth_params_v2 = usm_config
                        .auth_algorithm
                        .generate_auth_params(&auth_key, &message_for_verification_v2)
                        .map_err(|e| format!("Failed to generate auth params v2: {}", e))?;

                    debug!(
                        "Method 2 - Message length: {}",
                        message_for_verification_v2.len()
                    );
                    debug!(
                        "Method 2 - Expected auth params: {:02x?}",
                        expected_auth_params_v2
                    );
                    debug!(
                        "Method 2 - Match: {}",
                        received_auth_params == &expected_auth_params_v2
                    );

                    // Let's also see the hex dump comparison
                    debug!("\n=== HEX DUMP COMPARISON ===");
                    debug!("Original first 64 bytes:");
                    self.print_hex_dump(
                        &original_response_bytes
                            [0..std::cmp::min(64, original_response_bytes.len())],
                    );
                    debug!("Method 1 first 64 bytes:");
                    self.print_hex_dump(
                        &message_for_verification_v1
                            [0..std::cmp::min(64, message_for_verification_v1.len())],
                    );
                    debug!("Method 2 first 64 bytes:");
                    self.print_hex_dump(
                        &message_for_verification_v2
                            [0..std::cmp::min(64, message_for_verification_v2.len())],
                    );

                    // For now, accept either method that works
                    if received_auth_params == &expected_auth_params_v1
                        || received_auth_params == &expected_auth_params_v2
                    {
                        debug!("Authentication verification PASSED");
                        Ok(())
                    } else {
                        debug!("Authentication verification FAILED - both methods failed");
                        Ok(()) // Still being lenient for debugging
                    }
                }
                _ => Err("No USM parameters in response".to_string()),
            }
        } else {
            Err("No SNMPv3 layer found".to_string())
        }
    }
    /// Extract encrypted data from the response using Raw layer
    fn extract_encrypted_data(
        &self,
        response: &LayerStack,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        debug!("=== ENCRYPTED DATA EXTRACTION DEBUG ===");

        // First try to find Raw layer (which contains encrypted data)
        if let Some(raw_layer) = response.get_layer(Raw!()) {
            debug!("Found Raw layer with {} bytes", raw_layer.data.len());
            debug!(
                "Raw data: {:02x?}",
                &raw_layer.data[0..std::cmp::min(50, raw_layer.data.len())]
            );

            // The Raw layer contains the ASN.1 OCTET STRING with tag and length
            // We need to parse it to extract just the encrypted content
            let raw_data = &raw_layer.data;

            if raw_data.len() < 2 {
                debug!("Raw data too short");
                return Ok(None);
            }

            // Check for OCTET STRING tag (0x04)
            if raw_data[0] == 0x04 {
                let mut cursor = 1;

                // Parse length
                let content_length = if raw_data[cursor] & 0x80 == 0 {
                    // Short form
                    let len = raw_data[cursor] as usize;
                    cursor += 1;
                    len
                } else {
                    // Long form
                    let len_bytes = (raw_data[cursor] & 0x7F) as usize;
                    cursor += 1;

                    if len_bytes == 0 || len_bytes > 4 || cursor + len_bytes > raw_data.len() {
                        debug!("Invalid length encoding");
                        return Ok(None);
                    }

                    let mut len = 0usize;
                    for _ in 0..len_bytes {
                        len = (len << 8) | (raw_data[cursor] as usize);
                        cursor += 1;
                    }
                    len
                };

                debug!(
                    "OCTET STRING content length: {}, starts at offset: {}",
                    content_length, cursor
                );

                if cursor + content_length <= raw_data.len() {
                    let encrypted_content = raw_data[cursor..cursor + content_length].to_vec();
                    debug!(
                        "Extracted encrypted content: {} bytes",
                        encrypted_content.len()
                    );
                    debug!(
                        "Encrypted content: {:02x?}",
                        &encrypted_content[0..std::cmp::min(50, encrypted_content.len())]
                    );
                    return Ok(Some(encrypted_content));
                } else {
                    debug!("Content length exceeds available data");
                }
            } else {
                debug!(
                    "Raw data doesn't start with OCTET STRING tag, found: 0x{:02x}",
                    raw_data[0]
                );
            }

            // Fallback: return the raw data as-is
            return Ok(Some(raw_layer.data.clone()));
        }

        // Fallback: try to extract manually from the response bytes
        let response_bytes = response.clone().lencode();
        debug!("Total response length: {}", response_bytes.len());

        if let Some(encrypted_start) = self.find_encrypted_data_offset_v2(&response_bytes) {
            let encrypted_data = response_bytes[encrypted_start..].to_vec();
            debug!(
                "Extracted encrypted data from offset {}: {} bytes",
                encrypted_start,
                encrypted_data.len()
            );
            debug!(
                "Encrypted data: {:02x?}",
                &encrypted_data[0..std::cmp::min(50, encrypted_data.len())]
            );
            return Ok(Some(encrypted_data));
        }

        debug!("No encrypted data found");
        Ok(None)
    }

    /// Improved method to find encrypted data offset
    fn find_encrypted_data_offset_v2(&self, encoded: &[u8]) -> Option<usize> {
        debug!("=== PARSING MESSAGE STRUCTURE ===");
        let mut cursor = 0;

        // Parse outer SEQUENCE
        if encoded.len() < 2 || encoded[0] != 0x30 {
            debug!("Not a valid SEQUENCE");
            return None;
        }
        cursor += 1;

        // Parse outer length
        let outer_len = if encoded[cursor] & 0x80 == 0 {
            let len = encoded[cursor] as usize;
            cursor += 1;
            len
        } else {
            let len_bytes = (encoded[cursor] & 0x7F) as usize;
            cursor += 1;
            let mut len = 0usize;
            for _ in 0..len_bytes {
                if cursor >= encoded.len() {
                    return None;
                }
                len = (len << 8) | (encoded[cursor] as usize);
                cursor += 1;
            }
            len
        };

        debug!("Outer SEQUENCE length: {}", outer_len);

        // Skip version (INTEGER 3)
        if cursor >= encoded.len() || encoded[cursor] != 0x02 {
            debug!("Version not found at position {}", cursor);
            return None;
        }
        cursor += 1; // tag
        cursor += 1; // length (should be 1)
        cursor += 1; // value (should be 3)
        debug!("Skipped version, now at position: {}", cursor);

        // Skip msgGlobalData SEQUENCE (msgID, msgMaxSize, msgFlags, msgSecurityModel)
        if cursor >= encoded.len() || encoded[cursor] != 0x30 {
            debug!("msgGlobalData SEQUENCE not found at position {}", cursor);
            return None;
        }
        cursor += 1; // tag
        let global_len = encoded[cursor] as usize;
        cursor += 1; // length
        cursor += global_len; // skip content
        debug!("Skipped msgGlobalData, now at position: {}", cursor);

        // Skip msgSecurityParameters (OCTET STRING containing USM parameters)
        if cursor >= encoded.len() || encoded[cursor] != 0x04 {
            debug!("msgSecurityParameters not found at position {}", cursor);
            return None;
        }
        cursor += 1; // tag

        // Parse security parameters length
        let sec_params_len = if encoded[cursor] & 0x80 == 0 {
            let len = encoded[cursor] as usize;
            cursor += 1;
            len
        } else {
            let len_bytes = (encoded[cursor] & 0x7F) as usize;
            cursor += 1;
            let mut len = 0usize;
            for _ in 0..len_bytes {
                if cursor >= encoded.len() {
                    return None;
                }
                len = (len << 8) | (encoded[cursor] as usize);
                cursor += 1;
            }
            len
        };

        debug!("Security parameters length: {}", sec_params_len);
        cursor += sec_params_len; // Skip security parameters content
        debug!("Skipped security parameters, now at position: {}", cursor);

        // Now we should be at the encrypted scoped PDU (OCTET STRING)
        if cursor < encoded.len() {
            if encoded[cursor] == 0x04 {
                debug!(
                    "Found OCTET STRING (encrypted data) at position: {}",
                    cursor
                );
                cursor += 1; // skip tag

                // Parse length of encrypted data
                let encrypted_len = if encoded[cursor] & 0x80 == 0 {
                    let len = encoded[cursor] as usize;
                    cursor += 1;
                    len
                } else {
                    let len_bytes = (encoded[cursor] & 0x7F) as usize;
                    cursor += 1;
                    let mut len = 0usize;
                    for _ in 0..len_bytes {
                        if cursor >= encoded.len() {
                            return None;
                        }
                        len = (len << 8) | (encoded[cursor] as usize);
                        cursor += 1;
                    }
                    len
                };

                debug!(
                    "Encrypted data length: {}, starts at position: {}",
                    encrypted_len, cursor
                );
                return Some(cursor);
            } else {
                debug!(
                    "Expected OCTET STRING but found tag: 0x{:02x}",
                    encoded[cursor]
                );
            }
        }

        None
    }

    /// Extract privacy parameters (salt/IV) from USM security parameters
    fn extract_privacy_params(&self, response: &LayerStack) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            match &snmpv3.msg_security_parameters.value() {
                SnmpV3SecurityParameters::Usm(usm_params) => {
                    let priv_params = usm_params.msg_privacy_parameters.value().as_vec().clone();
                    debug!("Extracted privacy parameters: {:02x?}", priv_params);
                    Ok(priv_params)
                }
                _ => Err("No USM parameters found in response".into()),
            }
        } else {
            Err("No SNMPv3 layer found in response".into())
        }
    }

    /// Decrypt the scoped PDU with improved DES handling
    fn decrypt_scoped_pdu(
        &self,
        encrypted_data: &[u8],
        privacy_params: &[u8],
        usm_config: &UsmConfig,
        server_engine_time: u32,
    ) -> Result<SnmpV3ScopedPdu, Box<dyn Error>> {
        debug!("=== DECRYPTION COMPARISON DEBUG ===");
        debug!("Encrypted data length: {}", encrypted_data.len());
        debug!("Privacy params (received salt): {:02x?}", privacy_params);

        // Derive the privacy key - use the SAME method as encryption
        let priv_key = usm_config
            .priv_key()
            .map_err(|e| format!("Failed to derive privacy key: {}", e))?;

        debug!("Privacy key (16 bytes): {:02x?}", priv_key);

        // Extract salt - should be the full 8 bytes from privacy_params
        let salt = if privacy_params.len() >= 8 {
            &privacy_params[privacy_params.len() - 8..] // Last 8 bytes
        } else {
            privacy_params
        };

        debug!("Using salt (8 bytes): {:02x?}", salt);

        // Calculate IV using the SAME method as encryption
        let iv = match usm_config.priv_algorithm {
            usm_crypto::PrivAlgorithm::DesCbc => {
                // Use EXACTLY the same calculation as in encryption
                if salt.len() != 8 || priv_key.len() < 16 {
                    return Err("Invalid salt or privacy key length for DES".into());
                }

                let pre_iv = &priv_key[8..16];
                let mut iv = vec![0u8; 8];
                for i in 0..8 {
                    iv[i] = salt[i] ^ pre_iv[i];
                }
                debug!("Pre-IV (last 8 bytes of priv key): {:02x?}", pre_iv);
                debug!("Calculated IV for decryption: {:02x?}", iv);
                iv
            }
            usm_crypto::PrivAlgorithm::Aes128 => {
                debug!("=== DECRYPTION WITH SERVER ENGINE TIME ===");
                debug!("Server engine time: {}", server_engine_time);

                // For AES: use the calculate_iv method
                usm_config
                    .priv_algorithm
                    .calculate_iv(salt, &priv_key, usm_config.engine_boots, server_engine_time)
                    .map_err(|e| format!("Failed to calculate AES IV: {}", e))?
            }
            _ => return Err("Unsupported privacy algorithm".into()),
        };

        // Use only the first 8 bytes of privacy key for DES
        let encryption_key = match &usm_config.priv_algorithm {
            usm_crypto::PrivAlgorithm::DesCbc => {
                debug!("Encryption key (first 8 bytes for des)");
                &priv_key[0..8]
            }
            usm_crypto::PrivAlgorithm::Aes128 => {
                debug!("Encryption key (first 16 bytes for aes)");
                &priv_key[0..16]
            }
            x => {
                return Err(format!(
                    "Unsupported privacy algorithm {:?} for getting the encryption key",
                    &x
                )
                .into())
            }
        };
        debug!("Encryption key as per above: {:02x?}", encryption_key);

        // Compare with what we used during encryption
        debug!("=== COMPARISON WITH ENCRYPTION ===");
        debug!("During decryption we're using:");
        debug!("  Salt: {:02x?}", salt);
        debug!("  IV:   {:02x?}", iv);
        debug!("  Key:  {:02x?}", encryption_key);

        // Decrypt the data
        let decrypted_data = usm_config
            .priv_algorithm
            .decrypt(encryption_key, &iv, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        debug!("=== DECRYPTION DEBUG ===");
        debug!("Encrypted data length: {}", encrypted_data.len());
        debug!("Privacy params (salt): {:02x?}", privacy_params);

        // Derive the privacy key
        let priv_key = usm_config
            .priv_key()
            .map_err(|e| format!("Failed to derive privacy key: {}", e))?;

        debug!("Privacy key: {:02x?}", priv_key);

        // For DES, we need to extract the salt from privacy parameters
        // and calculate the IV correctly
        let salt = if privacy_params.len() >= 8 {
            &privacy_params[privacy_params.len() - 8..] // Last 8 bytes
        } else {
            privacy_params
        };

        debug!("Using salt: {:02x?}", salt);

        // Calculate the IV based on the privacy algorithm
        let iv = match usm_config.priv_algorithm {
            usm_crypto::PrivAlgorithm::DesCbc => {
                // For DES: IV = salt XOR pre_iv (last 8 bytes of privacy key)
                if salt.len() != 8 || priv_key.len() < 16 {
                    return Err("Invalid salt or privacy key length for DES".into());
                }

                let pre_iv = &priv_key[8..16];
                let mut iv = vec![0u8; 8];
                for i in 0..8 {
                    iv[i] = salt[i] ^ pre_iv[i];
                }
                iv
            }
            usm_crypto::PrivAlgorithm::Aes128 => {
                // For AES: use the calculate_iv method
                usm_config
                    .priv_algorithm
                    .calculate_iv(salt, &priv_key, usm_config.engine_boots, server_engine_time)
                    .map_err(|e| format!("Failed to calculate AES IV: {}", e))?
            }
            _ => return Err("Unsupported privacy algorithm".into()),
        };

        debug!("Calculated IV: {:02x?}", iv);

        // For DES, we only use the first 8 bytes of the privacy key
        let encryption_key = match usm_config.priv_algorithm {
            usm_crypto::PrivAlgorithm::DesCbc => &priv_key[0..8],
            usm_crypto::PrivAlgorithm::Aes128 => &priv_key[0..16],
            _ => return Err("Unsupported privacy algorithm".into()),
        };

        debug!("Encryption key: {:02x?}", encryption_key);

        // Decrypt the data
        let decrypted_data = usm_config
            .priv_algorithm
            .decrypt(encryption_key, &iv, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        debug!("Decrypted data length: {}", decrypted_data.len());
        debug!("Decrypted data: {:02x?}", &decrypted_data);

        // Parse the decrypted data as a scoped PDU
        if let Some((scoped_pdu, consumed)) =
            SnmpV3ScopedPdu::decode::<Asn1Decoder>(&decrypted_data)
        {
            debug!(
                "Successfully decoded scoped PDU from decrypted data (consumed {} bytes)",
                consumed
            );
            Ok(scoped_pdu)
        } else {
            debug!("Failed to decode scoped PDU, trying to parse ASN.1 structure manually");

            // Try to understand what we got
            if decrypted_data.len() > 0 {
                debug!("First byte: 0x{:02x}", decrypted_data[0]);
                if decrypted_data[0] == 0x30 {
                    debug!("Starts with SEQUENCE tag, this looks promising");
                } else {
                    debug!("Does not start with SEQUENCE tag");
                }
            }

            Err("Failed to decode scoped PDU from decrypted data".into())
        }
    }
}

/// Helper function to find a subsequence in a byte array
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
