use oside::Decode;
use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use oside::protocols::all::raw;

use oside::encdec::asn1::Asn1Decoder;
use oside::New;
use oside::Raw;
use std::str::FromStr;

use oside::protocols::snmp::*;
use oside::Layer;
use oside::LayerStack;
use oside::Value;
use oside::SNMP;
use oside::SNMPGETBULK;
use oside::SNMPGETNEXT;
use oside::SNMPGETORRESPONSE;
use oside::SNMPGETRESPONSE;
use oside::SNMPV2C;
use oside::SNMPVARBIND;

use oside::protocols::snmp::usm_crypto::{AuthAlgorithm, PrivAlgorithm, UsmConfig};

#[derive(Debug, Clone)]
enum SnmpVersion {
    V2c(String), // community string
    V3 {
        user: String,
        auth_algorithm: Option<AuthAlgorithm>,
        auth_password: Option<String>,
        priv_algorithm: Option<PrivAlgorithm>,
        priv_password: Option<String>,
        engine_id: Vec<u8>,
    },
}

struct SnmpWalkConfig {
    target_host: String,
    port: u16,
    version: SnmpVersion,
    starting_oid: String,
    max_repetitions: i32,
    timeout: Duration,
    use_getbulk: bool,
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

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let config = parse_args(&args)?;
    println!(
        "Starting SNMP walk on {}:{}",
        config.target_host, config.port
    );
    println!("Starting OID: {}", config.starting_oid);

    let mut walker = SnmpWalker::new(config)?;
    walker.walk()?;

    Ok(())
}

fn parse_args(args: &[String]) -> Result<SnmpWalkConfig, Box<dyn Error>> {
    let mut config = SnmpWalkConfig::default();

    if args.len() < 3 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    config.target_host = args[1].clone();
    config.starting_oid = args[2].clone();

    // Parse optional arguments
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-v" | "--version" => {
                if i + 1 >= args.len() {
                    return Err("Version argument requires a value".into());
                }
                let version_arg = args[i + 1].as_str();
                match version_arg {
                    "2c" => {
                        let community = if i + 2 < args.len() && !args[i + 2].starts_with('-') {
                            i += 1;
                            args[i + 1].clone()
                        } else {
                            "public".to_string()
                        };
                        config.version = SnmpVersion::V2c(community);
                    }
                    "3" => {
                        if i + 2 >= args.len() {
                            return Err("SNMPv3 requires username".into());
                        }
                        let user = args[i + 2].clone();
                        i += 1;

                        let mut auth_algorithm = None;
                        let mut auth_password = None;
                        let mut priv_algorithm = None;
                        let mut priv_password = None;

                        // Check for optional auth and priv parameters
                        if i + 2 < args.len() && args[i + 2] == "-a" {
                            if i + 4 >= args.len() {
                                return Err("Auth requires algorithm and password".into());
                            }

                            let auth_alg_str = &args[i + 3];
                            auth_algorithm = Some(match auth_alg_str.to_lowercase().as_str() {
                                "md5" => AuthAlgorithm::HmacMd5,
                                "sha1" | "sha" => AuthAlgorithm::HmacSha1,
                                _ => {
                                    return Err(
                                        "Unsupported auth algorithm. Use 'md5' or 'sha1'".into()
                                    )
                                }
                            });

                            auth_password = Some(args[i + 4].clone());
                            i += 3;

                            if i + 2 < args.len() && args[i + 2] == "-x" {
                                if i + 4 >= args.len() {
                                    return Err("Privacy requires algorithm and password".into());
                                }

                                let priv_alg_str = &args[i + 3];
                                priv_algorithm = Some(match priv_alg_str.to_lowercase().as_str() {
                                    "des" => PrivAlgorithm::DesCbc,
                                    "aes" | "aes128" => PrivAlgorithm::Aes128,
                                    _ => {
                                        return Err(
                                            "Unsupported privacy algorithm. Use 'des' or 'aes'"
                                                .into(),
                                        )
                                    }
                                });

                                priv_password = Some(args[i + 4].clone());
                                i += 3;
                            }
                        }

                        config.version = SnmpVersion::V3 {
                            user,
                            auth_algorithm,
                            auth_password,
                            priv_algorithm,
                            priv_password,
                            engine_id: vec![], // Will be discovered
                        };
                    }
                    _ => return Err("Unsupported SNMP version. Use '2c' or '3'".into()),
                }
                i += 1;
            }
            "-p" | "--port" => {
                if i + 1 >= args.len() {
                    return Err("Port argument requires a value".into());
                }
                config.port = args[i + 1].parse()?;
                i += 1;
            }
            "-m" | "--max-repetitions" => {
                if i + 1 >= args.len() {
                    return Err("Max repetitions argument requires a value".into());
                }
                config.max_repetitions = args[i + 1].parse()?;
                i += 1;
            }
            "--no-bulk" => {
                config.use_getbulk = false;
            }
            "-t" | "--timeout" => {
                if i + 1 >= args.len() {
                    return Err("Timeout argument requires a value".into());
                }
                let seconds: u64 = args[i + 1].parse()?;
                config.timeout = Duration::from_secs(seconds);
                i += 1;
            }
            _ => return Err(format!("Unknown argument: {}", args[i]).into()),
        }
        i += 1;
    }

    Ok(config)
}

fn print_usage(program_name: &str) {
    println!("Usage: {} <host> <starting_oid> [options]", program_name);
    println!();
    println!("Options:");
    println!("  -v, --version <2c|3>       SNMP version (default: 2c)");
    println!("      For v2c: -v 2c [community]  (default community: public)");
    println!(
        "      For v3:  -v 3 <username> [-a <auth_alg> <auth_pass>] [-x <priv_alg> <priv_pass>]"
    );
    println!("               Auth algorithms: md5, sha1");
    println!("               Privacy algorithms: des, aes");
    println!("  -p, --port <port>          Target port (default: 161)");
    println!("  -m, --max-repetitions <n>  Max repetitions for GetBulk (default: 10)");
    println!("  --no-bulk                  Use GetNext instead of GetBulk");
    println!("  -t, --timeout <seconds>    Timeout in seconds (default: 5)");
    println!();
    println!("Examples:");
    println!("  {} 192.168.1.1 1.3.6.1.2.1.1.1.0", program_name);
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1.1.0 -v 2c private",
        program_name
    );
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1.1.0 -v 3 myuser",
        program_name
    );
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1.1.0 -v 3 myuser -a md5 authpass",
        program_name
    );
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1.1.0 -v 3 myuser -a sha1 authpass -x aes privpass",
        program_name
    );
}

struct SnmpWalker {
    config: SnmpWalkConfig,
    socket: UdpSocket,
    request_id: u32,
    msg_id: u32,
}

impl SnmpWalker {
    fn new(config: SnmpWalkConfig) -> Result<Self, Box<dyn Error>> {
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

    fn walk(&mut self) -> Result<(), Box<dyn Error>> {
        let mut current_oid = self.config.starting_oid.clone();
        let mut results_count = 0;

        println!("Walking from OID: {}", current_oid);
        println!("----------------------------------------");

        loop {
            let response =
                if self.config.use_getbulk && matches!(self.config.version, SnmpVersion::V2c(_)) {
                    self.send_getbulk_request(&current_oid)?
                } else {
                    self.send_getnext_request(&current_oid)?
                };

            // Use the new extraction method
            let (found_next, next_oid, batch_count) =
                self.extract_and_process_bindings(&response)?;

            results_count += batch_count;

            if !found_next {
                println!("No more OIDs found");
                break;
            }

            current_oid = next_oid;

            if results_count > 10000 {
                println!("Stopping after 10000 results to prevent infinite loop");
                break;
            }
        }

        println!("----------------------------------------");
        println!("Walk completed. Total results: {}", results_count);
        Ok(())
    }

    fn walk_old(&mut self) -> Result<(), Box<dyn Error>> {
        let mut current_oid = self.config.starting_oid.clone();
        let mut results_count = 0;

        println!("Walking from OID: {}", current_oid);
        println!("----------------------------------------");

        loop {
            let response =
                if self.config.use_getbulk && matches!(self.config.version, SnmpVersion::V2c(_)) {
                    self.send_getbulk_request(&current_oid)?
                } else {
                    self.send_getnext_request(&current_oid)?
                };

            let mut found_next = false;
            let mut next_oid = String::new();

            // For SNMPv3, we need different response processing
            match &self.config.version {
                SnmpVersion::V3 { .. } => {
                    // Try to process as SNMPv3 response
                    if let Err(e) = self.process_snmpv3_response(&response) {
                        println!("SNMPv3 response processing failed: {}", e);
                        break;
                    }

                    // Extract the actual SNMP data
                    if let Some(scoped_pdu) = response.get_layer(SnmpV3ScopedPdu::default()) {
                        if let SnmpV3Pdu::Response(resp) = &scoped_pdu.pdu.value() {
                            if resp.error_status.value() != 0 {
                                println!(
                                    "SNMP Error: {} (index: {})",
                                    resp.error_status.value(),
                                    resp.error_index.value()
                                );
                                break;
                            }

                            for binding in &resp.var_bindings {
                                let oid_str = format!("{:?}", binding.name.value());

                                // Check if we've moved beyond our starting tree
                                if !oid_str.starts_with(&self.config.starting_oid) {
                                    println!("Reached end of subtree");
                                    return Ok(());
                                }

                                // Check for special SNMP values indicating end of walk
                                match &binding.value.value() {
                                    SnmpValue::NoSuchObject
                                    | SnmpValue::NoSuchInstance
                                    | SnmpValue::EndOfMibView => {
                                        println!("End of MIB view reached");
                                        return Ok(());
                                    }
                                    _ => {}
                                }

                                // Print the result
                                self.print_result(&binding);
                                results_count += 1;

                                // Update for next iteration
                                next_oid = oid_str;
                                found_next = true;
                            }
                        }
                    }
                }
                _ => {
                    // Original SNMPv1/v2c processing
                    if let Some(snmp_response) = response.get_layer(SNMPGETRESPONSE!()) {
                        if let SnmpGetResponse(resp) = snmp_response {
                            if resp.error_status.value() != 0 {
                                println!(
                                    "SNMP Error: {} (index: {})",
                                    resp.error_status.value(),
                                    resp.error_index.value()
                                );
                                break;
                            }

                            for binding in &resp.var_bindings {
                                let oid_str = format!("{:?}", binding.name.value());

                                if !oid_str.starts_with(&self.config.starting_oid) {
                                    println!("Reached end of subtree");
                                    return Ok(());
                                }

                                match &binding.value.value() {
                                    SnmpValue::NoSuchObject
                                    | SnmpValue::NoSuchInstance
                                    | SnmpValue::EndOfMibView => {
                                        println!("End of MIB view reached");
                                        return Ok(());
                                    }
                                    _ => {}
                                }

                                self.print_result(&binding);
                                results_count += 1;
                                next_oid = oid_str;
                                found_next = true;
                            }
                        }
                    } else {
                        println!("No valid SNMP response received");
                        break;
                    }
                }
            }

            if !found_next {
                println!("No more OIDs found");
                break;
            }

            current_oid = next_oid;

            if results_count > 10000 {
                println!("Stopping after 10000 results to prevent infinite loop");
                break;
            }
        }

        println!("----------------------------------------");
        println!("Walk completed. Total results: {}", results_count);
        Ok(())
    }

    fn increment_ids(&mut self) {
        self.request_id = self.request_id.wrapping_add(1);
        self.msg_id = self.msg_id.wrapping_add(1);
        println!(
            "INCREMENT IDs: req_id: {},  msg_id: {}",
            self.request_id, self.msg_id
        );
    }

    fn send_getnext_request(&mut self, oid: &str) -> Result<oside::LayerStack, Box<dyn Error>> {
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
                    println!("Doing discovery");
                    // If engine ID is empty, do discovery first
                    if usm_config.engine_id.is_empty() {
                        let engine_id = self.snmpv3_discovery(&mut usm_config)?;
                        usm_config.engine_id = engine_id;
                        // usm_config.engine_boots = 1;
                        // usm_config.engine_time = 0;
                    }

                    println!(
                        "USM config after engine discovery - has_auth: {}, has_priv: {}, USM: {:?}",
                        usm_config.has_auth(),
                        usm_config.has_priv(),
                        &usm_config
                    );
                    self.increment_ids();

                    if usm_config.has_auth() {
                        let encoded =
                            self.create_authenticated_request(Some(oid), &usm_config, true, false)?;
                        println!("ENCODED: {:?}", &encoded);

                        println!("Sending authenticated request, length: {}", encoded.len());
                        println!("Encoded message length: {}", encoded.len());
                        println!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        println!("Received response length: {}", len);
                        println!(
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
                                println!("Received authenticated response, verifying...");

                                // For now, skip auth verification and just process the response
                                // In production, you should verify the auth params here
                            }
                        }

                        return Ok(response);
                    } else {
                        // For no-auth SNMPv3, still need proper structure
                        println!("DOING v3 no auth");
                        let encoded = self.create_authenticated_request(
                            Some(oid),
                            &usm_config,
                            false,
                            false,
                        )?;
                        println!("ENCODED: {:?}", &encoded);

                        println!("Sending authenticated request, length: {}", encoded.len());
                        println!("Encoded message length: {}", encoded.len());
                        println!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        println!("Received response length: {}", len);
                        println!(
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
                                println!("Received authenticated response, verifying...");

                                // For now, skip auth verification and just process the response
                                // In production, you should verify the auth params here
                            }
                        }

                        return Ok(response);
                    }
                } else {
                    return Err("Failed to create USM configuration".into());
                }
            }
        };

        println!("request result: {:#02x?}", &request);
        self.send_request(request)
    }

    fn send_getbulk_request(&mut self, oid: &str) -> Result<oside::LayerStack, Box<dyn Error>> {
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
                    println!("Doing discovery");
                    // If engine ID is empty, do discovery first
                    if usm_config.engine_id.is_empty() {
                        let engine_id = self.snmpv3_discovery(&mut usm_config)?;
                        usm_config.engine_id = engine_id;
                        // usm_config.engine_boots = 1;
                        // usm_config.engine_time = 0;
                    }

                    println!(
                        "USM config after engine discovery - has_auth: {}, has_priv: {}, USM: {:?}",
                        usm_config.has_auth(),
                        usm_config.has_priv(),
                        &usm_config
                    );
                    self.increment_ids();

                    if usm_config.has_auth() {
                        let encoded =
                            self.create_authenticated_request(Some(oid), &usm_config, true, true)?;
                        println!("ENCODED: {:?}", &encoded);

                        println!("Sending authenticated request, length: {}", encoded.len());
                        println!("Encoded message length: {}", encoded.len());
                        println!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        println!("Received response length: {}", len);
                        println!(
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
                                println!("Received authenticated response, verifying...");

                                // For now, skip auth verification and just process the response
                                // In production, you should verify the auth params here
                            }
                        }

                        return Ok(response);
                    } else {
                        // For no-auth SNMPv3, still need proper structure
                        println!("DOING v3 no auth");
                        let encoded =
                            self.create_authenticated_request(Some(oid), &usm_config, false, true)?;
                        println!("ENCODED: {:?}", &encoded);

                        println!("Sending authenticated request, length: {}", encoded.len());
                        println!("Encoded message length: {}", encoded.len());
                        println!(
                            "First 50 bytes: {:02x?}",
                            &encoded[0..std::cmp::min(50, encoded.len())]
                        );

                        // Send the encoded message directly
                        self.socket.send(&encoded)?;

                        // Receive and decode response
                        let mut buf = vec![0u8; 65535];
                        let len = self.socket.recv(&mut buf)?;

                        println!("Received response length: {}", len);
                        println!(
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
                                println!("Received authenticated response, verifying...");

                                // For now, skip auth verification and just process the response
                                // In production, you should verify the auth params here
                            }
                        }

                        return Ok(response);
                    }
                } else {
                    return Err("Failed to create USM configuration".into());
                }
            }
        };

        self.send_request(request)
    }

    fn send_request(
        &mut self,
        request: oside::LayerStack,
    ) -> Result<oside::LayerStack, Box<dyn Error>> {
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

        Ok(response)
    }

    fn print_result(&self, binding: &SnmpVarBind) {
        let oid = format!("{:?}", binding.name.value());
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
            SnmpValue::ObjectIdentifier(oid) => format!("OID: {:?}", oid),
            SnmpValue::IpAddress(ip) => format!("IpAddress: {:?}", ip),
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

        println!("{} = {}", oid, value_str);
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
            } => {
                let mut usm_config = UsmConfig::new(user);

                if let (Some(auth_alg), Some(auth_pass)) = (auth_algorithm, auth_password) {
                    println!(
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
                    usm_config = usm_config.with_engine_info(engine_id, 1, 0);
                }
                println!(
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
        println!("Starting SNMPv3 engine discovery...");
        self.increment_ids();

        // Create a proper SNMPv3 discovery message (no authentication)
        let var_bindings = vec![]; /* SnmpVarBind {
                                       _bind_tag_len: Value::Auto,
                                       name: Value::Set(BerOid::from_str("1.3.6.1.6.3.15.1.1.4.0").unwrap_or_default()),
                                       value: Value::Set(SnmpValue::Null),
                                   }]; */

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
            msg_id: Value::Set(self.msg_id), // rand::random::<u32>() & 0x7fffffff),
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

        println!("Sending discovery message, length: {}", encoded.len());
        println!(
            "Discovery message first 50 bytes: {:02x?}",
            &encoded[0..std::cmp::min(50, encoded.len())]
        );

        self.socket.send(&encoded)?;

        let mut buf = vec![0u8; 65535];
        let len = self.socket.recv(&mut buf)?;

        println!("Received discovery response, length: {}", len);
        println!(
            "Response first 50 bytes: {:02x?}",
            &buf[0..std::cmp::min(50, len)]
        );

        // Parse response to extract engine ID
        if let Some((response_stack, _)) = SNMP!().ldecode(&buf[0..len]) {
            println!("Successfully decoded discovery response");

            // Look for SNMPv3 layer with USM parameters
            if let Some(snmpv3) = response_stack.get_layer(SnmpV3::new()) {
                println!("Found SNMPv3 layer in response");
                println!("Response msg_flags: {:?}", snmpv3.msg_flags);
                println!("Response security_model: {:?}", snmpv3.msg_security_model);

                // Debug: Print the security parameters type
                match &snmpv3.msg_security_parameters {
                    Value::Set(SnmpV3SecurityParameters::Usm(ref usm)) => {
                        println!("Found USM parameters in response");
                        let engine_id = usm.msg_authoritative_engine_id.value().to_vec();
                        println!("Extracted engine ID: {:02x?}", engine_id);
                        x.engine_boots = usm.msg_authoritative_engine_boots.value();
                        x.engine_time = usm.msg_authoritative_engine_time.value();

                        if !engine_id.is_empty() {
                            return Ok(engine_id);
                        } else {
                            println!("Engine ID is empty in response");
                        }
                    }
                    Value::Set(SnmpV3SecurityParameters::Raw(ref raw)) => {
                        println!("Found RAW security parameters: {:02x?}", raw.to_vec());
                        // Try to parse the raw security parameters manually
                        if let Some(engine_id) = self.parse_raw_usm_params(&raw.to_vec()) {
                            println!("Extracted engine ID from raw params: {:02x?}", engine_id);
                            return Ok(engine_id);
                        }
                    }
                    Value::Set(SnmpV3SecurityParameters::None) => {
                        println!("No security parameters in response");
                    }
                    _ => {
                        println!(
                            "Other security parameters type: {:?}",
                            snmpv3.msg_security_parameters
                        );
                    }
                }
            } else {
                println!("No SNMPv3 layer found in response");
            }
        } else {
            println!("Failed to decode discovery response");
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

    fn process_snmpv3_response(&self, response: &oside::LayerStack) -> Result<(), Box<dyn Error>> {
        // Get the USM config for this walker
        if let SnmpVersion::V3 { .. } = &self.config.version {
            if let Some(usm_config) = self.create_usm_config() {
                return self.process_snmpv3_response_with_decryption(response, &usm_config);
            }
        }

        // Fallback to original processing
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            println!("Processing SNMPv3 response: {:?}", &response);

            if let Some(scoped_pdu) = response.get_layer(SnmpV3ScopedPdu::default()) {
                return self.process_scoped_pdu_content(scoped_pdu);
            }
        }

        Err("No valid SNMPv3 response structure found".into())
    }

    fn process_snmpv3_response_old(
        &self,
        response: &oside::LayerStack,
    ) -> Result<(), Box<dyn Error>> {
        // Check if we have an SNMPv3 layer
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            println!("Processing SNMPv3 response: {:?}", &response);
            println!("Response flags: {:02x?}", snmpv3.msg_flags.value());
            println!(
                "Response security model: {}",
                snmpv3.msg_security_model.value()
            );

            // Check for USM parameters
            match &snmpv3.msg_security_parameters.value() {
                SnmpV3SecurityParameters::Usm(usm) => {
                    println!("Found USM parameters in response");
                    println!(
                        "Engine ID: {:02x?}",
                        usm.msg_authoritative_engine_id.value()
                    );
                }
                SnmpV3SecurityParameters::Raw(raw) => {
                    println!("Found raw security parameters: {:02x?}", raw);
                }
                _ => {
                    println!("No security parameters found");
                }
            }

            // Check for scoped PDU
            if let Some(scoped_pdu) = response.get_layer(SnmpV3ScopedPdu::default()) {
                println!("Found scoped PDU");
                match &scoped_pdu.pdu.value() {
                    SnmpV3Pdu::Response(resp) => {
                        println!(
                            "Found response PDU with {} bindings",
                            resp.var_bindings.len()
                        );
                        return Ok(());
                    }
                    SnmpV3Pdu::Report(report) => {
                        println!("Received report PDU - this might indicate an error");
                        println!("Error status: {}", report.error_status.value());
                        println!("Error index: {}", report.error_index.value());
                        return Err("Received SNMP report instead of response".into());
                    }
                    other => {
                        println!("Unexpected PDU type: {:?}", other);
                        return Err("Unexpected PDU type in response".into());
                    }
                }
            } else {
                println!("No scoped PDU found in response: {:?}", &response);
            }
        }

        Err("No valid SNMPv3 response structure found".into())
    }

    fn create_authenticated_request(
        &mut self,
        oid: Option<&str>,
        usm_config: &UsmConfig,
        do_crypt: bool,
        use_getbulk: bool,
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

        // Create the scoped PDU - THIS IS THE KEY FIX
        // Make sure context_engine_id matches the authoritative engine ID
        let scoped_pdu = if use_getbulk {
            SnmpV3ScopedPdu {
                _scoped_pdu_seq_tag_len: Value::Auto,
                context_engine_id: Value::Set(ByteArray::from(usm_config.engine_id.clone())), // FIXED: Use discovered engine ID
                context_name: Value::Set(ByteArray::from(vec![])),
                pdu: Value::Set(SnmpV3Pdu::GetBulk(SnmpGetBulkRequest {
                    request_id: Value::Set(self.request_id),
                    non_repeaters: Value::Set(0),
                    max_repetitions: Value::Set(self.config.max_repetitions),
                    _bindings_tag_len: Value::Auto,
                    var_bindings,
                })),
            }
        } else {
            SnmpV3ScopedPdu {
                _scoped_pdu_seq_tag_len: Value::Auto,
                context_engine_id: Value::Set(ByteArray::from(usm_config.engine_id.clone())), // FIXED: Use discovered engine ID
                context_name: Value::Set(ByteArray::from(vec![])),
                pdu: Value::Set(SnmpV3Pdu::Get(SnmpGetOrResponse {
                    // FIXED: Use GetNext instead of Get
                    request_id: Value::Set(self.request_id),
                    error_status: Value::Set(0),
                    error_index: Value::Set(0),
                    _bindings_tag_len: Value::Auto,
                    var_bindings,
                })),
            }
        };
        println!("SCOPED PDU: {:?}", &scoped_pdu);

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
            println!("=== SALT/IV DEBUG (USM setup) ===");
            println!("Generated IV for USM: {:02x?}", iv);
            println!("Engine boots: {}", usm_config.engine_boots);
            println!("Engine time: {}", usm_config.engine_time);

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
            msg_id: Value::Set(self.msg_id), // rand::random::<u32>() & 0x7fffffff),
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
        let encoded =
            stack.encode_with_usm::<oside::encdec::asn1::Asn1Encoder>(&mut usm_context)?;

        Ok(encoded)
    }
    /// Process SNMPv3 response with decryption support
    fn process_snmpv3_response_with_decryption(
        &self,
        response: &oside::LayerStack,
        usm_config: &UsmConfig,
    ) -> Result<(), Box<dyn Error>> {
        // Check if we have an SNMPv3 layer
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            println!("Processing SNMPv3 response with potential decryption");
            println!("Response flags: {:02x?}", snmpv3.msg_flags.value());

            // Verify authentication if required
            if usm_config.has_auth() {
                if let Err(e) = self.verify_authentication(response, usm_config) {
                    println!("Authentication verification failed: {}", e);
                    return Err(format!("Authentication failed: {}", e).into());
                }
                println!("Authentication verified successfully");
            }

            // Handle privacy (decryption) if enabled
            if usm_config.has_priv() {
                println!("Privacy enabled - attempting decryption");

                // Extract encrypted data and privacy parameters
                if let Some(encrypted_data) = self.extract_encrypted_data(response)? {
                    let privacy_params = self.extract_privacy_params(response)?;

                    // Decrypt the scoped PDU
                    let decrypted_scoped_pdu =
                        self.decrypt_scoped_pdu(&encrypted_data, &privacy_params, usm_config)?;

                    // Process the decrypted scoped PDU
                    return self.process_decrypted_scoped_pdu(&decrypted_scoped_pdu);
                } else {
                    return Err("Expected encrypted data but found none".into());
                }
            } else {
                // No privacy - process normally
                if let Some(scoped_pdu) = response.get_layer(SnmpV3ScopedPdu::default()) {
                    return self.process_scoped_pdu_content(scoped_pdu);
                }
            }
        }

        Err("No valid SNMPv3 response structure found".into())
    }

    /// Verify authentication of the response
    fn verify_authentication(
        &self,
        response: &oside::LayerStack,
        usm_config: &UsmConfig,
    ) -> Result<(), String> {
        // Extract USM parameters from the response
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            match &snmpv3.msg_security_parameters.value() {
                SnmpV3SecurityParameters::Usm(usm_params) => {
                    let param_val = usm_params.msg_authentication_parameters.value();
                    let received_auth_params = param_val.as_vec();

                    if received_auth_params.len() != 12 {
                        return Err("Invalid authentication parameter length".to_string());
                    }

                    // Create a copy of the encoded message with zeroed auth params for verification
                    let mut message_for_verification = response.clone().lencode();

                    // Find and zero out the auth params in the message
                    let zero_auth_params = vec![0u8; 12];
                    if let Some(pos) =
                        find_subsequence(&message_for_verification, received_auth_params)
                    {
                        message_for_verification[pos..pos + 12].copy_from_slice(&zero_auth_params);
                    } else {
                        return Err("Could not locate auth params in message".to_string());
                    }

                    // Calculate expected auth params
                    let auth_key = usm_config
                        .auth_key()
                        .map_err(|e| format!("Failed to derive auth key: {}", e))?;

                    let expected_auth_params = usm_config
                        .auth_algorithm
                        .generate_auth_params(&auth_key, &message_for_verification)
                        .map_err(|e| format!("Failed to generate auth params: {}", e))?;

                    // Compare
                    if received_auth_params == &expected_auth_params {
                        Ok(())
                    } else {
                        Err(format!(
                            "Authentication parameter mismatch: received ({:?}) expected ({:?})",
                            received_auth_params, &expected_auth_params
                        ))
                    }
                }
                _ => Err("No USM parameters in response".to_string()),
            }
        } else {
            Err("No SNMPv3 layer found".to_string())
        }
    }

    /// Extract encrypted data from the response
    fn extract_encrypted_data(
        &self,
        response: &oside::LayerStack,
    ) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        // Try to get encrypted scoped PDU
        if let Some(encrypted_pdu) = response.get_layer(EncryptedScopedPdu {
            encrypted_data: Value::Auto,
        }) {
            let data = encrypted_pdu.encrypted_data.value().as_vec().clone();
            println!("Extracted encrypted data: {} bytes", data.len());
            return Ok(Some(data));
        }

        // Fallback: try to extract from raw data after SNMPv3 header
        // This handles cases where the framework doesn't parse it as EncryptedScopedPdu
        let encoded = response.clone().lencode();

        // Parse through the message structure to find the encrypted portion
        // This is a simplified approach - in practice you'd want more robust parsing
        if let Some(raw_pdu) = response.get_layer(Raw!()) {
            println!(
                "Extracted encrypted data ({} bytes) from raw",
                raw_pdu.data.len()
            );
            return Ok(Some(raw_pdu.data.clone()));
        }

        Ok(None)
    }

    /// Find the offset where encrypted data starts in the encoded message
    fn find_encrypted_data_offset(&self, encoded: &[u8]) -> Option<usize> {
        // This is a simplified approach. In a real implementation, you'd parse
        // the ASN.1 structure properly to locate the encrypted scoped PDU

        // Look for the pattern that indicates start of encrypted scoped PDU
        // Usually it's after the USM security parameters
        let mut cursor = 0;

        // Skip outer SEQUENCE
        if encoded.len() < 2 || encoded[0] != 0x30 {
            return None;
        }
        cursor += 1;

        // Skip length
        if encoded[cursor] & 0x80 == 0 {
            cursor += 1;
        } else {
            let len_bytes = (encoded[cursor] & 0x7F) as usize;
            cursor += 1 + len_bytes;
        }

        // Skip version (INTEGER)
        if cursor >= encoded.len() || encoded[cursor] != 0x02 {
            return None;
        }
        cursor += 1;
        cursor += 1; // length
        cursor += 1; // value (version 3)

        // Skip msgID, msgMaxSize, msgFlags, msgSecurityModel
        for _ in 0..4 {
            if cursor >= encoded.len() || encoded[cursor] != 0x02 {
                return None;
            }
            cursor += 1; // tag
            let len = encoded[cursor] as usize;
            cursor += 1 + len;
        }

        // Skip msgSecurityParameters (OCTET STRING)
        if cursor >= encoded.len() || encoded[cursor] != 0x04 {
            return None;
        }
        cursor += 1; // tag

        // Parse length of security parameters
        let sec_params_len = if encoded[cursor] & 0x80 == 0 {
            let len = encoded[cursor] as usize;
            cursor += 1;
            len
        } else {
            let len_bytes = (encoded[cursor] & 0x7F) as usize;
            cursor += 1;
            let mut len = 0usize;
            for _ in 0..len_bytes {
                len = (len << 8) | (encoded[cursor] as usize);
                cursor += 1;
            }
            len
        };

        cursor += sec_params_len; // Skip security parameters

        // Now we should be at the encrypted scoped PDU
        if cursor < encoded.len() {
            Some(cursor)
        } else {
            None
        }
    }

    /// Extract privacy parameters (salt/IV) from USM security parameters
    fn extract_privacy_params(
        &self,
        response: &oside::LayerStack,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            match &snmpv3.msg_security_parameters.value() {
                SnmpV3SecurityParameters::Usm(usm_params) => {
                    let priv_params = usm_params.msg_privacy_parameters.value().as_vec().clone();
                    println!("Extracted privacy parameters: {:02x?}", priv_params);
                    Ok(priv_params)
                }
                _ => Err("No USM parameters found in response".into()),
            }
        } else {
            Err("No SNMPv3 layer found in response".into())
        }
    }

    /// Decrypt the scoped PDU
    fn decrypt_scoped_pdu(
        &self,
        encrypted_data: &[u8],
        privacy_params: &[u8],
        usm_config: &UsmConfig,
    ) -> Result<SnmpV3ScopedPdu, Box<dyn Error>> {
        println!("=== DECRYPTION DEBUG ===");
        println!("Encrypted data length: {}", encrypted_data.len());
        println!("Privacy params (salt): {:02x?}", privacy_params);

        // Derive the privacy key
        let priv_key = usm_config
            .priv_key()
            .map_err(|e| format!("Failed to derive privacy key: {}", e))?;

        println!("Privacy key: {:02x?}", priv_key);

        // Calculate the IV based on the privacy algorithm
        let iv = usm_config
            .priv_algorithm
            .calculate_iv(
                privacy_params,
                &priv_key,
                usm_config.engine_boots,
                usm_config.engine_time,
            )
            .map_err(|e| format!("Failed to calculate IV: {}", e))?;

        println!("Calculated IV: {:02x?}", iv);

        // Decrypt the data
        let decrypted_data = usm_config
            .priv_algorithm
            .decrypt(&priv_key, &iv, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        println!("Decrypted data length: {}", decrypted_data.len());
        println!(
            "Decrypted data first 20 bytes: {:02x?}",
            &decrypted_data[0..std::cmp::min(20, decrypted_data.len())]
        );

        // Parse the decrypted data as a scoped PDU
        if let Some((scoped_pdu, _)) = SnmpV3ScopedPdu::decode::<Asn1Decoder>(&decrypted_data) {
            println!("Successfully decoded scoped PDU from decrypted data");
            Ok(scoped_pdu)
        } else {
            Err("Failed to decode scoped PDU from decrypted data".into())
        }
    }

    /// Process a decrypted scoped PDU
    fn process_decrypted_scoped_pdu(
        &self,
        scoped_pdu: &SnmpV3ScopedPdu,
    ) -> Result<(), Box<dyn Error>> {
        println!("Processing decrypted scoped PDU");
        self.process_scoped_pdu_content(scoped_pdu)
    }

    /// Process the content of a scoped PDU (encrypted or not)
    fn process_scoped_pdu_content(
        &self,
        scoped_pdu: &SnmpV3ScopedPdu,
    ) -> Result<(), Box<dyn Error>> {
        match &scoped_pdu.pdu.value() {
            SnmpV3Pdu::Response(resp) => {
                println!(
                    "Found response PDU with {} bindings",
                    resp.var_bindings.len()
                );

                if resp.error_status.value() != 0 {
                    println!(
                        "SNMP Error: {} (index: {})",
                        resp.error_status.value(),
                        resp.error_index.value()
                    );
                    return Err(format!("SNMP Error: {}", resp.error_status.value()).into());
                }

                // Process the variable bindings
                for binding in &resp.var_bindings {
                    self.print_result(binding);
                }

                Ok(())
            }
            SnmpV3Pdu::Report(report) => {
                println!("Received report PDU - this might indicate an error");
                println!("Error status: {}", report.error_status.value());
                println!("Error index: {}", report.error_index.value());
                Err("Received SNMP report instead of response".into())
            }
            other => {
                println!("Unexpected PDU type in scoped PDU: {:?}", other);
                Err("Unexpected PDU type in response".into())
            }
        }
    }

    /// Extract variable bindings and process walk results
    fn extract_and_process_bindings(
        &mut self,
        response: &oside::LayerStack,
    ) -> Result<(bool, String, usize), Box<dyn Error>> {
        let mut found_next = false;
        let mut next_oid = String::new();
        let mut results_count = 0;

        // For SNMPv3, use the new decryption-aware processing
        match &self.config.version {
            SnmpVersion::V3 { .. } => {
                if let Some(usm_config) = self.create_usm_config() {
                    // Use a custom processing method that returns the bindings
                    let bindings = self.extract_bindings_from_snmpv3(response, &usm_config)?;

                    for binding in &bindings {
                        let oid_str = format!("{:?}", binding.name.value());

                        // Check if we've moved beyond our starting tree
                        if !oid_str.starts_with(&self.config.starting_oid) {
                            println!("Reached end of subtree");
                            return Ok((false, next_oid, results_count));
                        }

                        // Check for special SNMP values indicating end of walk
                        match &binding.value.value() {
                            SnmpValue::NoSuchObject
                            | SnmpValue::NoSuchInstance
                            | SnmpValue::EndOfMibView => {
                                println!("End of MIB view reached");
                                return Ok((false, next_oid, results_count));
                            }
                            _ => {}
                        }

                        // Print the result
                        self.print_result(&binding);
                        results_count += 1;

                        // Update for next iteration
                        next_oid = oid_str;
                        found_next = true;
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
                            let oid_str = format!("{:?}", binding.name.value());

                            if !oid_str.starts_with(&self.config.starting_oid) {
                                println!("Reached end of subtree");
                                return Ok((false, next_oid, results_count));
                            }

                            match &binding.value.value() {
                                SnmpValue::NoSuchObject
                                | SnmpValue::NoSuchInstance
                                | SnmpValue::EndOfMibView => {
                                    println!("End of MIB view reached");
                                    return Ok((false, next_oid, results_count));
                                }
                                _ => {}
                            }

                            self.print_result(&binding);
                            results_count += 1;
                            next_oid = oid_str;
                            found_next = true;
                        }
                    }
                } else {
                    return Err("No valid SNMP response received".into());
                }
            }
        }

        Ok((found_next, next_oid, results_count))
    }

    /// Extract bindings from SNMPv3 response with decryption support
    fn extract_bindings_from_snmpv3(
        &self,
        response: &oside::LayerStack,
        usm_config: &UsmConfig,
    ) -> Result<Vec<SnmpVarBind>, Box<dyn Error>> {
        if let Some(snmpv3) = response.get_layer(SnmpV3::new()) {
            // Verify authentication if required
            if usm_config.has_auth() {
                self.verify_authentication(response, usm_config)?;
            }

            // Handle privacy (decryption) if enabled
            if usm_config.has_priv() {
                if let Some(encrypted_data) = self.extract_encrypted_data(response)? {
                    let privacy_params = self.extract_privacy_params(response)?;
                    let decrypted_scoped_pdu =
                        self.decrypt_scoped_pdu(&encrypted_data, &privacy_params, usm_config)?;

                    return self.extract_bindings_from_scoped_pdu(&decrypted_scoped_pdu);
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
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
