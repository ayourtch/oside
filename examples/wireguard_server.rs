use oside::*;
use oside::protocols::all::*;
use std::net::UdpSocket;
use std::error::Error;

/// Simple WireGuard server example
/// This demonstrates:
/// 1. Creating WireGuard packet structures
/// 2. Parsing incoming WireGuard messages
/// 3. Responding to handshake attempts
fn main() -> Result<(), Box<dyn Error>> {
    println!("WireGuard Protocol Implementation Demo");
    println!("=======================================\n");

    // Create example WireGuard packets
    demonstrate_packet_construction();

    // Start a simple UDP server on WireGuard's default port
    println!("\nStarting simple WireGuard server on port 51820...");
    println!("(Note: This is a demonstration server that parses messages but doesn't perform cryptography)\n");

    run_server()?;

    Ok(())
}

/// Demonstrates creating various WireGuard packet types
fn demonstrate_packet_construction() {
    println!("=== WireGuard Packet Construction Demo ===\n");

    // 1. Handshake Initiation Message
    println!("1. Creating Handshake Initiation message:");
    let handshake_init = WgHandshakeInit {
        message_type: Value::Set(1),
        reserved_zero: Value::Set(0),
        sender_index: Value::Set(12345),
        unencrypted_ephemeral: vec![0x01; 32],  // Example ephemeral key
        encrypted_static: vec![0x02; 48],       // Example encrypted static key
        encrypted_timestamp: vec![0x03; 28],    // Example encrypted timestamp
        mac1: vec![0x04; 16],                   // Example MAC1
        mac2: vec![0x05; 16],                   // Example MAC2
    };

    let init_stack = UDP!(dport = 51820, sport = 54321) / handshake_init.clone();
    let init_data = init_stack.fill().lencode();
    println!("   Handshake Init size: {} bytes (expected 148 bytes + UDP/IP headers)", init_data.len());
    println!("   First 32 bytes: {:02x?}\n", &init_data[0..32.min(init_data.len())]);

    // 2. Handshake Response Message
    println!("2. Creating Handshake Response message:");
    let handshake_response = WgHandshakeResponse {
        message_type: Value::Set(2),
        reserved_zero: Value::Set(0),
        sender_index: Value::Set(67890),
        receiver_index: Value::Set(12345),
        unencrypted_ephemeral: vec![0x06; 32],
        encrypted_nothing: vec![0x07; 16],
        mac1: vec![0x08; 16],
        mac2: vec![0x09; 16],
    };

    let response_stack = UDP!(dport = 54321, sport = 51820) / handshake_response;
    let response_data = response_stack.fill().lencode();
    println!("   Handshake Response size: {} bytes (expected 92 bytes + UDP/IP headers)", response_data.len());
    println!("   First 32 bytes: {:02x?}\n", &response_data[0..32.min(response_data.len())]);

    // 3. Cookie Reply Message
    println!("3. Creating Cookie Reply message:");
    let cookie_reply = WgCookieReply {
        message_type: Value::Set(3),
        reserved_zero: Value::Set(0),
        receiver_index: Value::Set(12345),
        nonce: vec![0x0a; 24],
        encrypted_cookie: vec![0x0b; 32],
    };

    let cookie_stack = UDP!(dport = 54321, sport = 51820) / cookie_reply;
    let cookie_data = cookie_stack.fill().lencode();
    println!("   Cookie Reply size: {} bytes (expected 64 bytes + UDP/IP headers)", cookie_data.len());
    println!("   First 32 bytes: {:02x?}\n", &cookie_data[0..32.min(cookie_data.len())]);

    // 4. Transport Data Message
    println!("4. Creating Transport Data message:");
    let transport_data = WgTransportData {
        message_type: Value::Set(4),
        reserved_zero: Value::Set(0),
        receiver_index: Value::Set(12345),
        counter: Value::Set(1),
        encrypted_encapsulated_packet: vec![0x0c; 100],  // Example encrypted payload + auth tag
    };

    let data_stack = UDP!(dport = 54321, sport = 51820) / transport_data;
    let data_bytes = data_stack.fill().lencode();
    println!("   Transport Data size: {} bytes (32 bytes overhead + {} bytes payload + UDP/IP headers)",
             data_bytes.len(), 100);
    println!("   First 32 bytes: {:02x?}\n", &data_bytes[0..32.min(data_bytes.len())]);

    // 5. Demonstrate round-trip encoding/decoding
    println!("5. Testing encode/decode round-trip:");
    let original = WgHandshakeInit {
        message_type: Value::Set(1),
        reserved_zero: Value::Set(0),
        sender_index: Value::Set(99999),
        unencrypted_ephemeral: vec![0xaa; 32],
        encrypted_static: vec![0xbb; 48],
        encrypted_timestamp: vec![0xcc; 28],
        mac1: vec![0xdd; 16],
        mac2: vec![0xee; 16],
    };

    // Encode
    let encoded = original.clone().lencode(&LayerStack::new(), 0, &EncodingVecVec::new());
    println!("   Encoded: {} bytes", encoded.len());

    // Decode
    if let Some((decoded, consumed)) = WgHandshakeInit::decode::<BinaryBigEndian>(&encoded) {
        println!("   Decoded successfully, consumed {} bytes", consumed);
        println!("   Sender index matches: {}",
                 original.sender_index.value() == decoded.sender_index.value());
    }
    println!();
}

/// Run a simple UDP server that listens for WireGuard messages
fn run_server() -> Result<(), Box<dyn Error>> {
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

        // Check message type (first byte)
        let message_type = buf[0];
        println!("Message type: {}", message_type);

        match message_type {
            1 => {
                println!("Type: Handshake Initiation");
                if let Some((init, consumed)) = WgHandshakeInit::decode::<BinaryBigEndian>(&buf[0..len]) {
                    println!("Successfully decoded Handshake Initiation:");
                    println!("  Sender Index: {}", init.sender_index.value());
                    println!("  Reserved Zero: {}", init.reserved_zero.value());
                    println!("  Unencrypted Ephemeral (first 16 bytes): {:02x?}",
                             &init.unencrypted_ephemeral[0..16]);
                    println!("  Consumed {} bytes", consumed);

                    // Respond with a sample Handshake Response
                    let response = WgHandshakeResponse {
                        message_type: Value::Set(2),
                        reserved_zero: Value::Set(0),
                        sender_index: Value::Set(88888),  // Our index
                        receiver_index: init.sender_index.clone(),  // Their index
                        unencrypted_ephemeral: vec![0xf0; 32],
                        encrypted_nothing: vec![0xf1; 16],
                        mac1: vec![0xf2; 16],
                        mac2: vec![0xf3; 16],
                    };

                    let response_bytes = response.lencode(&LayerStack::new(), 0, &EncodingVecVec::new());
                    socket.send_to(&response_bytes, src)?;
                    println!("  Sent Handshake Response ({} bytes)", response_bytes.len());
                } else {
                    println!("Failed to decode Handshake Initiation");
                    println!("Raw data (first 64 bytes): {:02x?}", &buf[0..64.min(len)]);
                }
            }
            2 => {
                println!("Type: Handshake Response");
                if let Some((resp, consumed)) = WgHandshakeResponse::decode::<BinaryBigEndian>(&buf[0..len]) {
                    println!("Successfully decoded Handshake Response:");
                    println!("  Sender Index: {}", resp.sender_index.value());
                    println!("  Receiver Index: {}", resp.receiver_index.value());
                    println!("  Consumed {} bytes", consumed);
                } else {
                    println!("Failed to decode Handshake Response");
                }
            }
            3 => {
                println!("Type: Cookie Reply");
                if let Some((cookie, consumed)) = WgCookieReply::decode::<BinaryBigEndian>(&buf[0..len]) {
                    println!("Successfully decoded Cookie Reply:");
                    println!("  Receiver Index: {}", cookie.receiver_index.value());
                    println!("  Consumed {} bytes", consumed);
                } else {
                    println!("Failed to decode Cookie Reply");
                }
            }
            4 => {
                println!("Type: Transport Data");
                if let Some((data, consumed)) = WgTransportData::decode::<BinaryBigEndian>(&buf[0..len]) {
                    println!("Successfully decoded Transport Data:");
                    println!("  Receiver Index: {}", data.receiver_index.value());
                    println!("  Counter: {}", data.counter.value());
                    println!("  Encrypted Payload Size: {} bytes", data.encrypted_encapsulated_packet.len());
                    println!("  Consumed {} bytes", consumed);
                } else {
                    println!("Failed to decode Transport Data");
                }
            }
            _ => {
                println!("Unknown message type: {}", message_type);
                println!("Raw data (first 64 bytes): {:02x?}", &buf[0..64.min(len)]);
            }
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
