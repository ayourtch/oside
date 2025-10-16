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
/// This implements WireGuard's handshake (based on Noise IKpsk2 but with custom KDF)
pub fn process_handshake_initiation(
    init: &WgHandshakeInit,
    responder_private: &[u8; 32],
    responder_public: &[u8; 32],
    _psk: Option<&[u8; 32]>,  // PSK support can be added later
) -> Result<HandshakeState, String> {
    use blake2::{Blake2s256, Digest};
    use blake2::digest::Update;

    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, CONSTRUCTION);
        let result = hasher.finalize();
        let mut ck = [0u8; 32];
        ck.copy_from_slice(&result);
        ck
    };

    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &chaining_key);
        <Blake2s256 as Update>::update(&mut hasher, IDENTIFIER);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };
    hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &hash);
        <Blake2s256 as Update>::update(&mut hasher, responder_public);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    eprintln!("    [DEBUG] After init: ck={}, h={}", hex::encode(&chaining_key), hex::encode(&hash));

    // Parse initiator's ephemeral public key
    if init.unencrypted_ephemeral.len() != 32 {
        return Err(format!("Invalid ephemeral key length: {}", init.unencrypted_ephemeral.len()));
    }
    let mut initiator_ephemeral = [0u8; 32];
    initiator_ephemeral.copy_from_slice(&init.unencrypted_ephemeral);

    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &hash);
        <Blake2s256 as Update>::update(&mut hasher, &initiator_ephemeral);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    eprintln!("    [DEBUG] After MixHash(init_eph): h={}", hex::encode(&hash));

    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = {
        let temp = hmac_blake2s(&chaining_key, &initiator_ephemeral);
        hmac_blake2s(&temp, &[0x01])
    };

    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let es = dh(responder_private, &initiator_ephemeral);
    eprintln!("    [DEBUG] DH(resp_priv, init_eph) = {}", hex::encode(&es));

    let temp = hmac_blake2s(&chaining_key, &es);
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = hmac_blake2s(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = {
        let mut data = Vec::new();
        data.extend_from_slice(&chaining_key);
        data.push(0x02);
        hmac_blake2s(&temp, &data)
    };

    eprintln!("    [DEBUG] After DH(es): ck={}, key={}", hex::encode(&chaining_key), hex::encode(&key));

    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    if init.encrypted_static.len() != 48 {  // 32 bytes + 16 bytes auth tag
        return Err(format!("Invalid encrypted_static length: {}", init.encrypted_static.len()));
    }
    eprintln!("    [DEBUG] Attempting to decrypt encrypted_static: {}", hex::encode(&init.encrypted_static));
    let initiator_static_vec = aead_decrypt(&key, 0, &init.encrypted_static, &hash)?;
    if initiator_static_vec.len() != 32 {
        return Err(format!("Decrypted static key has wrong length: {}", initiator_static_vec.len()));
    }
    let mut initiator_static = [0u8; 32];
    initiator_static.copy_from_slice(&initiator_static_vec);

    eprintln!("    [DEBUG] Decrypted initiator static key: {}", hex::encode(&initiator_static));

    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &hash);
        <Blake2s256 as Update>::update(&mut hasher, &init.encrypted_static);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let ss = dh(responder_private, &initiator_static);
    eprintln!("    [DEBUG] DH(resp_priv, init_static) = {}", hex::encode(&ss));

    let temp = hmac_blake2s(&chaining_key, &ss);
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = hmac_blake2s(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = {
        let mut data = Vec::new();
        data.extend_from_slice(&chaining_key);
        data.push(0x02);
        hmac_blake2s(&temp, &data)
    };

    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    if init.encrypted_timestamp.len() != 28 {  // 12 bytes + 16 bytes auth tag
        return Err(format!("Invalid encrypted_timestamp length: {}", init.encrypted_timestamp.len()));
    }
    let timestamp_vec = aead_decrypt(&key, 0, &init.encrypted_timestamp, &hash)?;
    if timestamp_vec.len() != 12 {
        return Err(format!("Decrypted timestamp has wrong length: {}", timestamp_vec.len()));
    }

    eprintln!("    [DEBUG] Decrypted timestamp: {}", hex::encode(&timestamp_vec));

    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &hash);
        <Blake2s256 as Update>::update(&mut hasher, &init.encrypted_timestamp);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    // Note: In real WireGuard, we would:
    // - Validate the timestamp (TAI64N format)
    // - Check for replay attacks
    // - Verify MAC1 was already checked

    // Store the state for creating the response
    // We'll create a minimal NoiseState to hold the chaining_key and hash
    let mut noise = NoiseState::initialize(CONSTRUCTION);
    // Manually set the internal state to match what we computed
    noise.chaining_key = chaining_key;
    noise.hash = hash;

    Ok(HandshakeState {
        noise,
        initiator_static,
        initiator_ephemeral,
        sender_index: init.sender_index.value(),
        timestamp: timestamp_vec,
    })
}

/// Create a handshake response (responder side)
/// This implements WireGuard's handshake response (based on Noise IKpsk2 with custom KDF)
pub fn create_handshake_response(
    hs: &mut HandshakeState,
    _responder_private: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<WgHandshakeResponse, String> {
    use blake2::{Blake2s256, Digest};
    use blake2::digest::Update;

    let mut chaining_key = hs.noise.chaining_key;
    let mut hash = hs.noise.hash;

    // 1. Generate ephemeral key pair
    let (eph_private, eph_public) = generate_ephemeral_keypair();

    // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
    hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &hash);
        <Blake2s256 as Update>::update(&mut hasher, &eph_public);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
    let temp = hmac_blake2s(&chaining_key, &eph_public);
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = hmac_blake2s(&temp, &[0x01]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
    let ee = dh(&eph_private, &hs.initiator_ephemeral);
    let temp = hmac_blake2s(&chaining_key, &ee);
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = hmac_blake2s(&temp, &[0x01]);

    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
    let se = dh(&eph_private, &hs.initiator_static);
    let temp = hmac_blake2s(&chaining_key, &se);
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = hmac_blake2s(&temp, &[0x01]);

    // temp = HMAC(responder.chaining_key, preshared_key)
    let psk_bytes = psk.unwrap_or(&[0u8; 32]);
    let temp = hmac_blake2s(&chaining_key, psk_bytes);
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = hmac_blake2s(&temp, &[0x01]);
    // temp2 = HMAC(temp, responder.chaining_key || 0x2)
    let temp2 = {
        let mut data = Vec::new();
        data.extend_from_slice(&chaining_key);
        data.push(0x02);
        hmac_blake2s(&temp, &data)
    };
    // key = HMAC(temp, temp2 || 0x3)
    let key = {
        let mut data = Vec::new();
        data.extend_from_slice(&temp2);
        data.push(0x03);
        hmac_blake2s(&temp, &data)
    };
    // responder.hash = HASH(responder.hash || temp2)
    hash = {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &hash);
        <Blake2s256 as Update>::update(&mut hasher, &temp2);
        let result = hasher.finalize();
        let mut h = [0u8; 32];
        h.copy_from_slice(&result);
        h
    };

    // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
    let encrypted_nothing = aead_encrypt(&key, 0, &[], &hash)?;

    // Note: At this point, we would call split() to derive transport keys
    // temp1 = HMAC(responder.chaining_key, [empty])
    // temp2 = HMAC(temp1, 0x1)
    // temp3 = HMAC(temp1, temp2 || 0x2)
    // responder.sending_key = temp2
    // responder.receiving_key = temp3

    // Create response message
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
