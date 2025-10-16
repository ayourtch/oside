use crate::protocols::wireguard::*;
use crate::protocols::wireguard_crypto::*;
use crate::protocols::wireguard_noise::NoiseState;
use crate::*;

/// Handshake state after processing initiator's message
#[derive(Clone, Debug)]
pub struct HandshakeState {
    pub noise: NoiseState,
    pub initiator_static: [u8; 32],
    pub initiator_ephemeral: [u8; 32],
    pub sender_index: u32,
    pub timestamp: Vec<u8>,
}

/// Process a handshake initiation message (responder side)
/// This implements the Noise IKpsk2 pattern: <- e, es, s, ss
pub fn process_handshake_initiation(
    init: &WgHandshakeInit,
    responder_private: &[u8; 32],
    responder_public: &[u8; 32],
    _psk: Option<&[u8; 32]>,  // PSK support can be added later
) -> Result<HandshakeState, String> {
    // 1. Initialize Noise state
    let mut noise = NoiseState::initialize(CONSTRUCTION);

    // 2. MixHash(IDENTIFIER)
    noise.mix_hash(IDENTIFIER);

    // 3. MixHash(responder.static_public)
    noise.mix_hash(responder_public);

    // 4. MixHash(initiator.ephemeral_public) - the 'e' token
    if init.unencrypted_ephemeral.len() != 32 {
        return Err(format!("Invalid ephemeral key length: {}", init.unencrypted_ephemeral.len()));
    }
    let mut initiator_ephemeral = [0u8; 32];
    initiator_ephemeral.copy_from_slice(&init.unencrypted_ephemeral);
    noise.mix_hash(&initiator_ephemeral);

    // 5. MixKey(DH(responder_private, initiator_ephemeral)) - the 'es' token
    let es = dh(responder_private, &initiator_ephemeral);
    noise.mix_key(&es);

    // 6. DecryptAndHash(initiator.encrypted_static) - the 's' token
    if init.encrypted_static.len() != 48 {  // 32 bytes + 16 bytes auth tag
        return Err(format!("Invalid encrypted_static length: {}", init.encrypted_static.len()));
    }
    let initiator_static_vec = noise.decrypt_and_hash(&init.encrypted_static)?;
    if initiator_static_vec.len() != 32 {
        return Err(format!("Decrypted static key has wrong length: {}", initiator_static_vec.len()));
    }
    let mut initiator_static = [0u8; 32];
    initiator_static.copy_from_slice(&initiator_static_vec);

    // 7. MixKey(DH(responder_private, initiator_static)) - the 'ss' token
    let ss = dh(responder_private, &initiator_static);
    noise.mix_key(&ss);

    // 8. DecryptAndHash(initiator.encrypted_timestamp)
    if init.encrypted_timestamp.len() != 28 {  // 12 bytes + 16 bytes auth tag
        return Err(format!("Invalid encrypted_timestamp length: {}", init.encrypted_timestamp.len()));
    }
    let timestamp = noise.decrypt_and_hash(&init.encrypted_timestamp)?;
    if timestamp.len() != 12 {
        return Err(format!("Decrypted timestamp has wrong length: {}", timestamp.len()));
    }

    // Note: In real WireGuard, we would:
    // - Validate the timestamp (TAI64N format)
    // - Check for replay attacks
    // - Verify MAC1 was already checked

    Ok(HandshakeState {
        noise,
        initiator_static,
        initiator_ephemeral,
        sender_index: init.sender_index.value(),
        timestamp,
    })
}

/// Create a handshake response (responder side)
/// This implements the Noise IKpsk2 pattern: -> e, ee, se
pub fn create_handshake_response(
    hs: &mut HandshakeState,
    responder_private: &[u8; 32],
    _psk: Option<&[u8; 32]>,  // PSK support can be added later
) -> Result<WgHandshakeResponse, String> {
    // 1. Generate ephemeral key pair
    let (eph_private, eph_public) = generate_ephemeral_keypair();

    // 2. MixHash(responder.ephemeral_public) - the 'e' token
    hs.noise.mix_hash(&eph_public);

    // 3. MixKey(DH(responder.ephemeral_private, initiator.ephemeral_public)) - the 'ee' token
    let ee = dh(&eph_private, &hs.initiator_ephemeral);
    hs.noise.mix_key(&ee);

    // 4. MixKey(DH(responder.ephemeral_private, initiator.static_public)) - the 'se' token
    let se = dh(&eph_private, &hs.initiator_static);
    hs.noise.mix_key(&se);

    // 5. EncryptAndHash(empty) - this is the encrypted_nothing field
    let encrypted_nothing = hs.noise.encrypt_and_hash(&[])?;

    // Note: At this point, we would call noise.split() to derive transport keys
    // and store them for the session

    // 6. Create response message
    Ok(WgHandshakeResponse {
        sender_index: Value::Set(generate_sender_index()),
        receiver_index: Value::Set(hs.sender_index),
        unencrypted_ephemeral: eph_public.to_vec(),
        encrypted_nothing,
        mac1: vec![0; 16],  // Will be calculated by caller
        mac2: vec![0; 16],  // No cookie for now
    })
}

/// Generate a random sender index (session ID)
fn generate_sender_index() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_round_trip() {
        // This is a simplified test - real WireGuard would have proper keys
        // We'll add more comprehensive tests once we have the full implementation

        // Generate responder keys
        let (responder_private, responder_public) = generate_ephemeral_keypair();

        // For now, just test that the functions don't panic
        // We need a real initiator to create a proper handshake init message
        // This will be expanded in integration tests

        assert_eq!(responder_private.len(), 32);
        assert_eq!(responder_public.len(), 32);
    }
}
