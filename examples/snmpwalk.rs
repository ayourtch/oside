use std::env;
use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use oside::New;
use std::str::FromStr;

use oside::protocols::snmp::*;
use oside::Layer;
use oside::Value;
use oside::SNMP;
use oside::SNMPGETBULK;
use oside::SNMPGETNEXT;
use oside::SNMPGETORRESPONSE;
use oside::SNMPGETRESPONSE;
use oside::SNMPV2C;
use oside::SNMPVARBIND;

#[derive(Debug, Clone)]
enum SnmpVersion {
    V2c(String), // community string
    V3 {
        user: String,
        auth_key: Option<String>,
        priv_key: Option<String>,
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
    println!("Version: {:?}", config.version);
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

                        let mut auth_key = None;
                        let mut priv_key = None;

                        // Check for optional auth and priv keys
                        if i + 2 < args.len() && args[i + 2] == "-a" {
                            if i + 3 >= args.len() {
                                return Err("Auth key requires a value".into());
                            }
                            auth_key = Some(args[i + 3].clone());
                            i += 2;

                            if i + 2 < args.len() && args[i + 2] == "-x" {
                                if i + 3 >= args.len() {
                                    return Err("Priv key requires a value".into());
                                }
                                priv_key = Some(args[i + 3].clone());
                                i += 2;
                            }
                        }

                        config.version = SnmpVersion::V3 {
                            user,
                            auth_key,
                            priv_key,
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
    println!("      For v3:  -v 3 <username> [-a <auth_key>] [-x <priv_key>]");
    println!("  -p, --port <port>          Target port (default: 161)");
    println!("  -m, --max-repetitions <n>  Max repetitions for GetBulk (default: 10)");
    println!("  --no-bulk                  Use GetNext instead of GetBulk");
    println!("  -t, --timeout <seconds>    Timeout in seconds (default: 5)");
    println!();
    println!("Examples:");
    println!("  {} 192.168.1.1 1.3.6.1.2.1.1", program_name);
    println!("  {} 192.168.1.1 1.3.6.1.2.1.1 -v 2c private", program_name);
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1 -v 3 myuser -a myauthkey",
        program_name
    );
    println!(
        "  {} 192.168.1.1 1.3.6.1.2.1.1 -v 3 myuser -a myauthkey -x myprivkey",
        program_name
    );
}

struct SnmpWalker {
    config: SnmpWalkConfig,
    socket: UdpSocket,
    request_id: u32,
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
            request_id: rand::random(),
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

            // Process response
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
            } else {
                println!("No valid SNMP response received");
                break;
            }

            if !found_next {
                println!("No more OIDs found");
                break;
            }

            current_oid = next_oid;

            // Safety check to prevent infinite loops
            if results_count > 10000 {
                println!("Stopping after 10000 results to prevent infinite loop");
                break;
            }
        }

        println!("----------------------------------------");
        println!("Walk completed. Total results: {}", results_count);
        Ok(())
    }

    fn send_getnext_request(&mut self, oid: &str) -> Result<oside::LayerStack, Box<dyn Error>> {
        self.request_id = self.request_id.wrapping_add(1);

        let request = match &self.config.version {
            SnmpVersion::V2c(community) => {
                SNMP!()
                    / SNMPV2C!(community = community.as_str())
                    / SnmpGetNext(SNMPGETORRESPONSE!(
                        request_id = self.request_id,
                        var_bindings = vec![SNMPVARBIND!(name = oid, value = SnmpValue::Null)]
                    ))
            }
            SnmpVersion::V3 {
                user,
                auth_key,
                priv_key,
            } => {
                // Use the new LayerStack-based SNMPv3 implementation
                if auth_key.is_some() {
                    Snmp::v3_get_auth(
                        user,
                        &[], // Empty engine ID for discovery
                        &vec![oid],
                    )
                } else {
                    Snmp::v3_get(&vec![oid])
                }
            }
        };
        println!("request result: {:#02x?}", &request);

        self.send_request(request)
    }

    fn send_getbulk_request(&mut self, oid: &str) -> Result<oside::LayerStack, Box<dyn Error>> {
        self.request_id = self.request_id.wrapping_add(1);

        let request = match &self.config.version {
            SnmpVersion::V2c(community) => {
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
                // SNMPv3 doesn't typically use GetBulk in the same way
                // Fall back to GetNext
                return self.send_getnext_request(oid);
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
}
