use std::env;
use std::error::Error;
use std::time::Duration;

use oside::protocols::snmp::usm_crypto::{AuthAlgorithm, PrivAlgorithm};

use oside::oside_snmp_session::{OsideSnmpSession, SnmpVersion, SnmpWalkConfig};

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();

    let config = parse_args(&args)?;
    println!(
        "Starting SNMP walk on {}:{}",
        config.target_host, config.port
    );
    println!("Starting OID: {}", config.starting_oid);

    let mut walker = OsideSnmpSession::new(config.clone())?;
    walker.walk(&config.starting_oid)?;

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
                            engine_boots: 1,
                            engine_time: 0,
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
