use oside::*;
use oside::protocols::all::*;
use std::net::UdpSocket;
use std::error::Error;
use std::env;
use base64::{Engine as _, engine::general_purpose};

/// Simple WireGuard server example
/// This demonstrates:
/// 1. Creating WireGuard packet structures
/// 2. Parsing incoming WireGuard messages
/// 3. Responding to handshake attempts with proper MAC1
///
/// Usage: wireguard_server [initiator_public_key_hex]
/// If initiator_public_key is provided, MAC1 will be calculated correctly for responses
fn main() -> Result<(), Box<dyn Error>> {
    println!("WireGuard Protocol Implementation Demo");
    println!("=======================================\n");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let initiator_pubkey = if args.len() > 1 {
        // Try base64 first (WireGuard standard format), then hex
        let key_result = general_purpose::STANDARD.decode(&args[1])
            .or_else(|_| hex::decode(&args[1]));

        match key_result {
            Ok(key) if key.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key);
                println!("Using initiator public key: {}", args[1]);
                Some(arr)
            }
            Ok(key) => {
                eprintln!("Warning: Invalid public key provided (decoded to {} bytes, need 32)", key.len());
                None
            }
            Err(e) => {
                eprintln!("Warning: Failed to decode public key (tried base64 and hex): {}", e);
                None
            }
        }
    } else {
        println!("No initiator public key provided - MAC1 will be zeros");
        println!("Usage: {} <initiator_public_key_base64_or_hex>", args[0]);
        println!("  Example (base64): {} QGJhc2U2NGtleWV4YW1wbGUxMjM0NTY3ODkwMTI=", args[0]);
        println!("  Example (hex):    {} 406261736536346b6579657861...", args[0]);
        None
    };
    println!();

    // Create example WireGuard packets
    demonstrate_packet_construction();

    // Start a simple UDP server on WireGuard's default port
    println!("\nStarting simple WireGuard server on port 51820...");
    if initiator_pubkey.is_some() {
        println!("(Server will calculate proper MAC1 values)\n");
    } else {
        println!("(Note: This is a demonstration server that parses messages but doesn't perform full cryptography)\n");
    }

    run_server(initiator_pubkey)?;

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
fn run_server(initiator_pubkey: Option<[u8; 32]>) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:51820")?;
    println!("Server listening on 0.0.0.0:51820");
    println!("Waiting for WireGuard messages...\n");

    let mut buf = vec![0u8; 2048];
    let mut packet_count = 0;

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

                // Respond with a sample Handshake Response
                let response_msg = WgMessage {
                    message_type: Value::Set(2),
                    reserved_zero: Value::Set(0),
                };
                let response = WgHandshakeResponse {
                    sender_index: Value::Set(88888),  // Our index
                    receiver_index: init.sender_index.clone(),  // Their index
                    unencrypted_ephemeral: vec![0xf0; 32],
                    encrypted_nothing: vec![0xf1; 16],
                    mac1: vec![0; 16],  // Will be calculated
                    mac2: vec![0; 16],  // No cookie, so zeros
                };

                let response_stack = LayerStack::new() / response_msg / response;
                let mut response_bytes = response_stack.lencode();

                // Calculate MAC1 if we have the initiator's public key
                if let Some(pubkey) = initiator_pubkey {
                    // MAC1 offset for Handshake Response:
                    // 4 bytes (WgMessage header) + 4 (sender_index) + 4 (receiver_index) + 32 (ephemeral) + 16 (encrypted_nothing)
                    // = 60 bytes
                    let mac1_offset = 60;
                    let mac1 = calculate_mac1_for_message(&pubkey, &response_bytes, mac1_offset);
                    response_bytes[mac1_offset..mac1_offset+16].copy_from_slice(&mac1);
                    println!("  Calculated MAC1: {:02x?}", &mac1[..8]);
                } else {
                    println!("  MAC1: [zeros - no initiator public key provided]");
                }

                socket.send_to(&response_bytes, src)?;
                println!("  Sent Handshake Response ({} bytes)", response_bytes.len());
            } else if let Some(resp) = decoded_stack.get_layer(WGHANDSHAKERESPONSE!()) {
                println!("Type: Handshake Response");
                println!("  Sender Index: {}", resp.sender_index.value());
                println!("  Receiver Index: {}", resp.receiver_index.value());
            } else if let Some(cookie) = decoded_stack.get_layer(WGCOOKIEREPLY!()) {
                println!("Type: Cookie Reply");
                println!("  Receiver Index: {}", cookie.receiver_index.value());
            } else if let Some(data) = decoded_stack.get_layer(WGTRANSPORTDATA!()) {
                println!("Type: Transport Data");
                println!("  Receiver Index: {}", data.receiver_index.value());
                println!("  Counter: {}", data.counter.value());
                println!("  Encrypted Payload Size: {} bytes", data.encrypted_encapsulated_packet.len());
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
        if packet_count >= 10 {
            println!("Demo complete (processed 10 packets)");
            break;
        }
    }

    Ok(())
}
