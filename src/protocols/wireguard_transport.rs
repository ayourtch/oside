use crate::protocols::wireguard_crypto::*;
use crate::protocols::wireguard_handshake::HandshakeState;

/// Session keys for encrypting and decrypting transport data
#[derive(Clone, Debug)]
pub struct TransportKeys {
    /// Key for encrypting data we send
    pub sending_key: [u8; 32],
    /// Key for decrypting data we receive
    pub receiving_key: [u8; 32],
    /// Our session index (for packets we send)
    pub local_index: u32,
    /// Peer's session index (for packets we receive)
    pub peer_index: u32,
}

impl TransportKeys {
    /// Derive transport keys from a completed handshake (responder side)
    /// For responder: sending_key = T1, receiving_key = T2
    /// For initiator: sending_key = T2, receiving_key = T1
    pub fn from_handshake_responder(
        hs: &HandshakeState,
        local_index: u32,
    ) -> Self {
        eprintln!("    [DEBUG] Deriving transport keys from chaining_key: {}", hex::encode(&hs.noise.chaining_key));

        // temp1 = HMAC(chaining_key, [empty])
        let temp1 = hmac_blake2s(&hs.noise.chaining_key, &[]);
        eprintln!("    [DEBUG] temp1 = HMAC(ck, []) = {}", hex::encode(&temp1));

        // temp2 = HMAC(temp1, 0x1)
        let temp2 = hmac_blake2s(&temp1, &[0x01]);
        eprintln!("    [DEBUG] temp2 = HMAC(temp1, 0x01) = {}", hex::encode(&temp2));

        // temp3 = HMAC(temp1, temp2 || 0x2)
        let temp3 = {
            let mut data = Vec::new();
            data.extend_from_slice(&temp2);
            data.push(0x02);
            hmac_blake2s(&temp1, &data)
        };
        eprintln!("    [DEBUG] temp3 = HMAC(temp1, temp2 || 0x02) = {}", hex::encode(&temp3));

        // For responder: receive with temp2 (initiator sends with temp2)
        //                send with temp3 (initiator receives with temp3)
        eprintln!("    [DEBUG] Responder: sending_key = temp3, receiving_key = temp2");
        TransportKeys {
            sending_key: temp3,
            receiving_key: temp2,
            local_index,
            peer_index: hs.sender_index,
        }
    }

    /// Decrypt a transport data packet
    /// Returns the decrypted payload (without authentication tag)
    pub fn decrypt_transport_data(
        &self,
        counter: u64,
        encrypted_payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        eprintln!("    [DEBUG] Decrypting with receiving_key: {}", hex::encode(&self.receiving_key));
        eprintln!("    [DEBUG] Counter (nonce): {}", counter);
        eprintln!("    [DEBUG] Encrypted payload: {}", hex::encode(encrypted_payload));
        // WireGuard uses the counter directly as the nonce
        let result = aead_decrypt(&self.receiving_key, counter, encrypted_payload, &[]);
        if let Err(ref e) = result {
            eprintln!("    [DEBUG] Decryption failed: {}", e);
        }
        result
    }

    /// Encrypt data for a transport data packet
    /// Returns the encrypted payload with authentication tag
    pub fn encrypt_transport_data(
        &self,
        counter: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        // WireGuard uses the counter directly as the nonce
        aead_encrypt(&self.sending_key, counter, plaintext, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::wireguard_crypto::*;
    use crate::protocols::wireguard_noise::NoiseState;

    #[test]
    fn test_transport_keys_derivation() {
        // Create a dummy handshake state
        let mut noise = NoiseState::initialize(CONSTRUCTION);
        noise.chaining_key = [0x42u8; 32]; // Test value

        let hs = HandshakeState {
            noise,
            initiator_static: [0u8; 32],
            initiator_ephemeral: [0u8; 32],
            sender_index: 12345,
            timestamp: vec![0u8; 12],
        };

        let keys = TransportKeys::from_handshake_responder(&hs, 67890);

        // Keys should be deterministic
        let keys2 = TransportKeys::from_handshake_responder(&hs, 67890);
        assert_eq!(keys.sending_key, keys2.sending_key);
        assert_eq!(keys.receiving_key, keys2.receiving_key);

        // Sending and receiving keys should be different
        assert_ne!(keys.sending_key, keys.receiving_key);

        // Indices should be set correctly
        assert_eq!(keys.local_index, 67890);
        assert_eq!(keys.peer_index, 12345);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let keys = TransportKeys {
            sending_key: [0x42u8; 32],
            receiving_key: [0x42u8; 32],
            local_index: 1,
            peer_index: 2,
        };

        let plaintext = b"Hello, WireGuard tunnel!";
        let counter = 0;

        let encrypted = keys.encrypt_transport_data(counter, plaintext).unwrap();
        assert_eq!(encrypted.len(), plaintext.len() + 16); // +16 for auth tag

        let decrypted = keys.decrypt_transport_data(counter, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_counter_fails() {
        let keys = TransportKeys {
            sending_key: [0x42u8; 32],
            receiving_key: [0x42u8; 32],
            local_index: 1,
            peer_index: 2,
        };

        let plaintext = b"Hello, WireGuard tunnel!";
        let encrypted = keys.encrypt_transport_data(0, plaintext).unwrap();

        // Trying to decrypt with wrong counter should fail
        let result = keys.decrypt_transport_data(1, &encrypted);
        assert!(result.is_err());
    }
}
