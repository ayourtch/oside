use oside::*;
use oside::protocols::all::*;
use oside::protocols::wireguard_handshake::{process_handshake_initiation, create_handshake_response};
use oside::protocols::wireguard_transport::TransportKeys;
use std::net::UdpSocket;
use std::error::Error;
use std::env;
use std::fs;
use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};

/// WireGuard server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WgServerConfig {
    /// Server's private key (base64-encoded, as in wg.conf)
    #[serde(default)]
    private_key: Option<String>,

    /// Server's public key (base64-encoded, optional - can be derived from private key)
    #[serde(default)]
    public_key: Option<String>,

    /// Peer configurations
    #[serde(default)]
    peers: Vec<WgPeerConfig>,

    /// Listen address
    #[serde(default = "default_listen_addr")]
    listen_addr: String,

    /// Listen port
    #[serde(default = "default_listen_port")]
    listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WgPeerConfig {
    /// Peer's public key (base64-encoded)
    public_key: String,

    /// Allowed IPs for this peer
    #[serde(default)]
    allowed_ips: Vec<String>,
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_listen_port() -> u16 {
    51820
}

impl Default for WgServerConfig {
    fn default() -> Self {
        WgServerConfig {
            private_key: None,
            public_key: None,
            peers: vec![],
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
        }
    }
}

impl WgServerConfig {
    /// Load configuration from a TOML file
    fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)?;
        let config: WgServerConfig = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Parse a base64-encoded key (WireGuard format) to bytes
    fn parse_key(key_str: &str) -> Result<[u8; 32], Box<dyn Error>> {
        let decoded = general_purpose::STANDARD.decode(key_str)?;
        if decoded.len() != 32 {
            return Err(format!("Key must be 32 bytes, got {}", decoded.len()).into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        Ok(arr)
    }

    /// Get server's public key as bytes (from config or derive from private key)
    fn get_public_key(&self) -> Option<[u8; 32]> {
        if let Some(ref pk) = self.public_key {
            Self::parse_key(pk).ok()
        } else if let Some(ref sk) = self.private_key {
            // Derive public key from private key
            if let Ok(private_bytes) = Self::parse_key(sk) {
                Some(derive_public_key(&private_bytes))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get server's private key as bytes
    fn get_private_key(&self) -> Option<[u8; 32]> {
        if let Some(ref sk) = self.private_key {
            Self::parse_key(sk).ok()
        } else {
            None
        }
    }

    /// Find peer configuration by public key
    fn find_peer(&self, public_key: &[u8; 32]) -> Option<&WgPeerConfig> {
        let pk_b64 = general_purpose::STANDARD.encode(public_key);
        self.peers.iter().find(|p| p.public_key == pk_b64)
    }
}

/// Simple WireGuard server example
/// This demonstrates:
/// 1. Creating WireGuard packet structures
/// 2. Parsing incoming WireGuard messages
/// 3. Responding to handshake attempts with proper MAC1
///
/// Usage: wireguard_server [config.toml]
/// If config file is provided, it will load keys and peer information
/// Otherwise, runs in demo mode with hardcoded values
fn main() -> Result<(), Box<dyn Error>> {
    println!("WireGuard Protocol Implementation Demo");
    println!("=======================================\n");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let config = if args.len() > 1 {
        match WgServerConfig::from_file(&args[1]) {
            Ok(cfg) => {
                println!("Loaded configuration from: {}", args[1]);
                if let Some(ref pk) = cfg.public_key {
                    println!("  Server public key: {}", pk);
                }
                println!("  Configured peers: {}", cfg.peers.len());
                for (i, peer) in cfg.peers.iter().enumerate() {
                    println!("    Peer #{}: {}", i + 1, peer.public_key);
                }
                cfg
            }
            Err(e) => {
                eprintln!("Failed to load config from {}: {}", args[1], e);
                eprintln!("Using default configuration");
                WgServerConfig::default()
            }
        }
    } else {
        println!("No configuration file provided");
        println!("Usage: {} [config.toml]", args[0]);
        println!("\nExample config.toml:");
        println!("---");
        println!("# Server's private key (generate with: wg genkey)");
        println!("private_key = \"YourBase64PrivateKeyHere=\"");
        println!();
        println!("# Server's public key (generate with: wg pubkey < privatekey)");
        println!("public_key = \"YourBase64PublicKeyHere=\"");
        println!();
        println!("[[peers]]");
        println!("public_key = \"PeerBase64PublicKeyHere=\"");
        println!("allowed_ips = [\"10.0.0.2/32\"]");
        println!("---\n");
        WgServerConfig::default()
    };
    println!();

    // Create example WireGuard packets
    demonstrate_packet_construction();

    // Start a simple UDP server
    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    println!("\nStarting WireGuard server on {}...", listen_addr);
    if !config.peers.is_empty() {
        println!("(Server will calculate proper MAC1 values for configured peers)\n");
    } else {
        println!("(Note: No peers configured - MAC1 will be zeros)\n");
    }

    run_server(config)?;

    Ok(())
}

/// Demonstrates creating various WireGuard packet types
fn demonstrate_packet_construction() {
    println!("=== WireGuard Packet Construction Demo ===\n");

    // 1. Handshake Initiation Message
    println!("1. Creating Handshake Initiation message:");
    let wg_msg = WgMessage {
        message_type: Value::Set(1),
        reserved_zero: Value::Set(0),
    };
    let handshake_init = WgHandshakeInit {
        sender_index: Value::Set(12345),
        unencrypted_ephemeral: vec![0x01; 32],  // Example ephemeral key
        encrypted_static: vec![0x02; 48],       // Example encrypted static key
        encrypted_timestamp: vec![0x03; 28],    // Example encrypted timestamp
        mac1: vec![0x04; 16],                   // Example MAC1
        mac2: vec![0x05; 16],                   // Example MAC2
    };

    let init_stack = UDP!(dport = 51820, sport = 54321) / wg_msg.clone() / handshake_init.clone();
    let init_data = init_stack.fill().lencode();
    println!("   Handshake Init size: {} bytes (expected 148 bytes + UDP/IP headers)", init_data.len());
    println!("   First 32 bytes: {:02x?}\n", &init_data[0..32.min(init_data.len())]);

    // 2. Handshake Response Message
    println!("2. Creating Handshake Response message:");
    let wg_msg2 = WgMessage {
        message_type: Value::Set(2),
        reserved_zero: Value::Set(0),
    };
    let handshake_response = WgHandshakeResponse {
        sender_index: Value::Set(67890),
        receiver_index: Value::Set(12345),
        unencrypted_ephemeral: vec![0x06; 32],
        encrypted_nothing: vec![0x07; 16],
        mac1: vec![0x08; 16],
        mac2: vec![0x09; 16],
    };

    let response_stack = UDP!(dport = 54321, sport = 51820) / wg_msg2 / handshake_response;
    let response_data = response_stack.fill().lencode();
    println!("   Handshake Response size: {} bytes (expected 92 bytes + UDP/IP headers)", response_data.len());
    println!("   First 32 bytes: {:02x?}\n", &response_data[0..32.min(response_data.len())]);

    // 3. Cookie Reply Message
    println!("3. Creating Cookie Reply message:");
    let wg_msg3 = WgMessage {
        message_type: Value::Set(3),
        reserved_zero: Value::Set(0),
    };
    let cookie_reply = WgCookieReply {
        receiver_index: Value::Set(12345),
        nonce: vec![0x0a; 24],
        encrypted_cookie: vec![0x0b; 32],
    };

    let cookie_stack = UDP!(dport = 54321, sport = 51820) / wg_msg3 / cookie_reply;
    let cookie_data = cookie_stack.fill().lencode();
    println!("   Cookie Reply size: {} bytes (expected 64 bytes + UDP/IP headers)", cookie_data.len());
    println!("   First 32 bytes: {:02x?}\n", &cookie_data[0..32.min(cookie_data.len())]);

    // 4. Transport Data Message
    println!("4. Creating Transport Data message:");
    let wg_msg4 = WgMessage {
        message_type: Value::Set(4),
        reserved_zero: Value::Set(0),
    };
    let transport_data = WgTransportData {
        receiver_index: Value::Set(12345),
        counter: Value::Set(1),
        encrypted_encapsulated_packet: vec![0x0c; 100],  // Example encrypted payload + auth tag
    };

    let data_stack = UDP!(dport = 54321, sport = 51820) / wg_msg4 / transport_data;
    let data_bytes = data_stack.fill().lencode();
    println!("   Transport Data size: {} bytes (32 bytes overhead + {} bytes payload + UDP/IP headers)",
             data_bytes.len(), 100);
    println!("   First 32 bytes: {:02x?}\n", &data_bytes[0..32.min(data_bytes.len())]);

    // 5. Demonstrate round-trip encoding/decoding
    println!("5. Testing encode/decode round-trip:");
    let original_msg = WgMessage {
        message_type: Value::Set(1),
        reserved_zero: Value::Set(0),
    };
    let original_init = WgHandshakeInit {
        sender_index: Value::Set(99999),
        unencrypted_ephemeral: vec![0xaa; 32],
        encrypted_static: vec![0xbb; 48],
        encrypted_timestamp: vec![0xcc; 28],
        mac1: vec![0xdd; 16],
        mac2: vec![0xee; 16],
    };

    // Encode
    let stack = LayerStack::new() / original_msg.clone() / original_init.clone();
    let encoded = stack.lencode();
    println!("   Encoded: {} bytes", encoded.len());

    // Decode - start with WgMessage which will dispatch to the right type
    if let Some((decoded_stack, consumed)) = WGMESSAGE!().ldecode(&encoded) {
        println!("   Decoded successfully, consumed {} bytes", consumed);
        if let Some(decoded_init) = decoded_stack.get_layer(WGHANDSHAKEINIT!()) {
            println!("   Sender index matches: {}",
                     original_init.sender_index.value() == decoded_init.sender_index.value());
        }
    }
    println!();
}

/// Run a simple UDP server that listens for WireGuard messages
fn run_server(config: WgServerConfig) -> Result<(), Box<dyn Error>> {
    let listen_addr = format!("{}:{}", config.listen_addr, config.listen_port);
    let socket = UdpSocket::bind(&listen_addr)?;
    println!("Server listening on {}", listen_addr);
    println!("Waiting for WireGuard messages...\n");

    let mut buf = vec![0u8; 2048];
    let mut packet_count = 0;

    // Session storage: receiver_index -> (TransportKeys, send_counter)
    let mut sessions: HashMap<u32, (TransportKeys, u64)> = HashMap::new();

    loop {
        // Receive UDP packet
        let (len, src) = socket.recv_from(&mut buf)?;
        packet_count += 1;

        println!("=== Packet #{} from {} ===", packet_count, src);
        println!("Received {} bytes", len);

        // Try to parse as WireGuard message
        if len == 0 {
            println!("Empty packet received\n");
            continue;
        }

        // Use automatic decoding via the registry mechanism
        // Start with WgMessage which will automatically dispatch to the right type
        if let Some((decoded_stack, consumed)) = WGMESSAGE!().ldecode(&buf[0..len]) {
            println!("Successfully decoded WireGuard message (consumed {} bytes)", consumed);

            // Check the message type from WgMessage
            if let Some(wg_msg) = decoded_stack.get_layer(WGMESSAGE!()) {
                println!("Message type: {}", wg_msg.message_type.value());
            }

            // Check which specific message type we got
            if let Some(init) = decoded_stack.get_layer(WGHANDSHAKEINIT!()) {
                println!("Type: Handshake Initiation");
                println!("  Sender Index: {}", init.sender_index.value());
                println!("  Unencrypted Ephemeral (first 16 bytes): {:02x?}",
                         &init.unencrypted_ephemeral[0..16]);
                println!("  Received MAC1: {}", hex::encode(&init.mac1));
                println!("  Received MAC2: {}", hex::encode(&init.mac2));

                // Verify the incoming MAC1 if we have server's public key
                if let Some(server_pubkey) = config.get_public_key() {
                    println!("\n  Verifying incoming MAC1:");
                    println!("    Server public key: {}", config.public_key.as_ref().unwrap());
                    // The MAC1 should be calculated over bytes 0..116 (everything before mac1)
                    let incoming_mac1_offset = 116;
                    let expected_mac1 = calculate_mac1_for_message(&server_pubkey, &buf[..len], incoming_mac1_offset);
                    println!("    Expected MAC1: {}", hex::encode(expected_mac1));
                    println!("    Received MAC1: {}", hex::encode(&init.mac1));
                    if &expected_mac1[..] == &init.mac1[..] {
                        println!("    ✓ MAC1 is VALID");
                    } else {
                        println!("    ✗ MAC1 is INVALID");
                    }
                }

                // Get server keys
                let server_private = match config.get_private_key() {
                    Some(sk) => sk,
                    None => {
                        println!("  ERROR: No server private key configured");
                        continue;
                    }
                };
                let server_public = match config.get_public_key() {
                    Some(pk) => pk,
                    None => {
                        println!("  ERROR: No server public key configured");
                        continue;
                    }
                };

                println!("\n  Processing handshake with Noise protocol...");

                // Process the handshake initiation using the Noise protocol
                let mut hs = match process_handshake_initiation(&init, &server_private, &server_public, None) {
                    Ok(hs) => {
                        println!("  ✓ Handshake initiation processed successfully");
                        println!("    Initiator static key: {}", hex::encode(&hs.initiator_static));
                        println!("    Timestamp: {}", hex::encode(&hs.timestamp));
                        hs
                    }
                    Err(e) => {
                        println!("  ✗ Failed to process handshake initiation: {}", e);
                        continue;
                    }
                };

                // Try to identify the peer by their static public key (which we decrypted)
                let peer_pubkey = if !config.peers.is_empty() {
                    // Check if the decrypted initiator static key matches any configured peer
                    let peer_pk_b64 = general_purpose::STANDARD.encode(&hs.initiator_static);
                    if config.peers.iter().any(|p| p.public_key == peer_pk_b64) {
                        println!("  ✓ Peer recognized: {}", peer_pk_b64);
                        Some(hs.initiator_static)
                    } else {
                        println!("  ⚠ Peer not in configured list: {}", peer_pk_b64);
                        Some(hs.initiator_static)
                    }
                } else {
                    println!("  ⚠ No peers configured, accepting any peer");
                    Some(hs.initiator_static)
                };

                // Create handshake response using the Noise protocol
                let response = match create_handshake_response(&mut hs, &server_private, None) {
                    Ok(resp) => {
                        println!("  ✓ Handshake response created with proper encryption");
                        println!("    Encrypted nothing length: {} bytes", resp.encrypted_nothing.len());

                        // Derive transport keys from the completed handshake
                        let local_index = resp.sender_index.value();
                        let transport_keys = TransportKeys::from_handshake_responder(&hs, local_index);

                        // Store the session with send counter initialized to 0
                        sessions.insert(local_index, (transport_keys, 0));
                        println!("  ✓ Transport keys derived and session stored");
                        println!("    Local index: {}", local_index);
                        println!("    Peer index: {}", hs.sender_index);

                        resp
                    }
                    Err(e) => {
                        println!("  ✗ Failed to create handshake response: {}", e);
                        continue;
                    }
                };

                // Wrap in WireGuard message
                let response_msg = WgMessage {
                    message_type: Value::Set(2),
                    reserved_zero: Value::Set(0),
                };

                let response_stack = LayerStack::new() / response_msg / response;
                let mut response_bytes = response_stack.lencode();

                println!("\n  DEBUG: Response message breakdown:");
                println!("    Total length: {} bytes", response_bytes.len());
                println!("    Bytes 0-3 (header): {:02x?}", &response_bytes[0..4]);
                println!("    Bytes 4-7 (sender_index): {:02x?}", &response_bytes[4..8]);
                println!("    Bytes 8-11 (receiver_index): {:02x?}", &response_bytes[8..12]);
                println!("    Bytes 12-43 (ephemeral, first 32): {:02x?}", &response_bytes[12..44]);
                println!("    Bytes 44-59 (encrypted_nothing): {:02x?}", &response_bytes[44..60]);
                println!("    Bytes 60-75 (mac1): {:02x?}", &response_bytes[60..76]);
                println!("    Bytes 76-91 (mac2): {:02x?}", &response_bytes[76..92]);

                // Calculate MAC1 if we have the peer's public key
                if let Some(pubkey) = peer_pubkey {
                    // MAC1 offset for Handshake Response:
                    // 4 bytes (WgMessage header) + 4 (sender_index) + 4 (receiver_index) + 32 (ephemeral) + 16 (encrypted_nothing)
                    // = 60 bytes
                    let mac1_offset = 60;
                    println!("\n  Calculating MAC1:");
                    println!("    Using bytes 0..{} for MAC calculation", mac1_offset);
                    println!("    Message bytes (hex): {}", hex::encode(&response_bytes[..mac1_offset]));

                    let mac1 = calculate_mac1_for_message(&pubkey, &response_bytes, mac1_offset);
                    response_bytes[mac1_offset..mac1_offset+16].copy_from_slice(&mac1);
                    println!("    Calculated MAC1 (full): {:02x?}", mac1);
                    println!("    Calculated MAC1 (hex): {}", hex::encode(mac1));
                } else {
                    println!("  MAC1: [zeros - no peer public key configured]");
                }

                println!("\n  Final message (first 92 bytes): {}", hex::encode(&response_bytes[..92.min(response_bytes.len())]));

                socket.send_to(&response_bytes, src)?;
                println!("\n  Sent Handshake Response ({} bytes)", response_bytes.len());
            } else if let Some(resp) = decoded_stack.get_layer(WGHANDSHAKERESPONSE!()) {
                println!("Type: Handshake Response");
                println!("  Sender Index: {}", resp.sender_index.value());
                println!("  Receiver Index: {}", resp.receiver_index.value());
            } else if let Some(cookie) = decoded_stack.get_layer(WGCOOKIEREPLY!()) {
                println!("Type: Cookie Reply");
                println!("  Receiver Index: {}", cookie.receiver_index.value());
            } else if let Some(data) = decoded_stack.get_layer(WGTRANSPORTDATA!()) {
                println!("Type: Transport Data");
                let receiver_index = data.receiver_index.value();
                let counter = data.counter.value();
                println!("  Receiver Index: {}", receiver_index);
                println!("  Counter: {}", counter);
                println!("  Encrypted Payload Size: {} bytes", data.encrypted_encapsulated_packet.len());

                // Try to decrypt if we have a session for this receiver_index
                if let Some((transport_keys, send_counter)) = sessions.get_mut(&receiver_index) {
                    match transport_keys.decrypt_transport_data(counter, &data.encrypted_encapsulated_packet) {
                        Ok(plaintext) => {
                            println!("  ✓ Successfully decrypted payload");
                            println!("    Plaintext length: {} bytes", plaintext.len());
                            if plaintext.is_empty() {
                                println!("    (Empty payload - this is a keepalive packet)");

                                // Send a keepalive response
                                println!("\n  Sending keepalive response...");

                                // Encrypt empty payload (keepalive)
                                match transport_keys.encrypt_transport_data(*send_counter, &[]) {
                                    Ok(encrypted) => {
                                        // Create transport data message
                                        let keepalive_msg = WgMessage {
                                            message_type: Value::Set(4),
                                            reserved_zero: Value::Set(0),
                                        };
                                        let keepalive_data = WgTransportData {
                                            receiver_index: Value::Set(transport_keys.peer_index),
                                            counter: Value::Set(*send_counter),
                                            encrypted_encapsulated_packet: encrypted,
                                        };

                                        let keepalive_stack = LayerStack::new() / keepalive_msg / keepalive_data;
                                        let keepalive_bytes = keepalive_stack.lencode();

                                        socket.send_to(&keepalive_bytes, src)?;
                                        println!("    ✓ Sent keepalive response ({} bytes, counter: {})", keepalive_bytes.len(), *send_counter);

                                        // Increment send counter
                                        *send_counter += 1;
                                    }
                                    Err(e) => {
                                        println!("    ✗ Failed to encrypt keepalive: {}", e);
                                    }
                                }
                            } else {
                                println!("    Plaintext (hex): {}", hex::encode(&plaintext));
                                // Try to interpret as IPv4/IPv6 packet
                                if plaintext.len() >= 1 {
                                    let version = (plaintext[0] >> 4) & 0x0F;
                                    match version {
                                        4 => println!("    Looks like IPv4 packet"),
                                        6 => println!("    Looks like IPv6 packet"),
                                        _ => println!("    Unknown protocol"),
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("  ✗ Failed to decrypt payload: {}", e);
                        }
                    }
                } else {
                    println!("  ⚠ No session found for receiver_index {}", receiver_index);
                    println!("    Available sessions: {:?}", sessions.keys().collect::<Vec<_>>());
                }
            } else {
                println!("Unknown WireGuard message type");
                println!("Decoded stack: {:#?}", decoded_stack);
            }
        } else {
            println!("Failed to decode WireGuard message");
            println!("Raw data (first 64 bytes): {:02x?}", &buf[0..64.min(len)]);
        }

        println!();

        // Stop after 10 packets for demo purposes
        if packet_count >= 1000 {
            println!("Demo complete (processed 10 packets)");
            break;
        }
    }

    Ok(())
}
