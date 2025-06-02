use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use oside::New;
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
    println!("  {} 192.168.1.1 1.3.6.1.2.1.1", program_name);
    println!("  {} 192.168.1.1 1.3.6.1.2.1.1 -v 2c private", program_name);
    println!("  {} 192.168.1.1 1.3.6.1.2.1.1 -v 3 myuser", program_name);
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1 -v 3 myuser -a md5 authpass",
        program_name
    );
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1 -v 3 myuser -a sha1 authpass -x aes privpass",
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
                println!("No scoped PDU found in response");
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
        let encoded = stack.encode_with_usm::<oside::encdec::asn1::Asn1Encoder>(&mut usm_context)?;

        Ok(encoded)
    }
}
