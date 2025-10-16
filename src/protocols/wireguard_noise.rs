use crate::protocols::wireguard_crypto::*;
use blake2::{Blake2s256, Digest};
use blake2::digest::Update;

/// Noise protocol state for WireGuard handshake
#[derive(Clone, Debug)]
pub struct NoiseState {
    /// Chaining key (ck in Noise spec)
    pub chaining_key: [u8; 32],

    /// Hash state (h in Noise spec)
    pub hash: [u8; 32],

    /// Current encryption key (derived from chaining_key)
    encryption_key: Option<[u8; 32]>,
}

impl NoiseState {
    /// Initialize Noise state with protocol name
    /// For WireGuard: "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    pub fn initialize(protocol_name: &[u8]) -> Self {
        // Initial hash = HASH(protocol_name)
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, protocol_name);
        let hash_result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_result);

        // Initial chaining key = hash
        let chaining_key = hash;

        NoiseState {
            chaining_key,
            hash,
            encryption_key: None,
        }
    }

    /// MixKey(input_key_material)
    /// Sets ck, k = KDF2(ck, input_key_material)
    pub fn mix_key(&mut self, input_key_material: &[u8]) {
        let (ck, key) = kdf2(&self.chaining_key, input_key_material);
        self.chaining_key = ck;
        self.encryption_key = Some(key);
    }

    /// MixHash(data)
    /// Sets h = HASH(h || data)
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, &self.hash);
        <Blake2s256 as Update>::update(&mut hasher, data);
        let result = hasher.finalize();
        self.hash.copy_from_slice(&result);
    }

    /// MixKeyAndHash(input_key_material)
    /// For PSK: Sets ck, temp, k = KDF3(ck, input_key_material)
    ///          then h = HASH(h || temp)
    pub fn mix_key_and_hash(&mut self, input_key_material: &[u8]) {
        let (ck, temp, key) = kdf3(&self.chaining_key, input_key_material);
        self.chaining_key = ck;
        self.mix_hash(&temp);
        self.encryption_key = Some(key);
    }

    /// EncryptAndHash(plaintext)
    /// Returns ciphertext = AEAD(k, 0, plaintext, h)
    /// Then sets h = HASH(h || ciphertext)
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.encryption_key
            .ok_or("No encryption key set")?;

        // WireGuard uses counter 0 for handshake messages
        let ciphertext = aead_encrypt(&key, 0, plaintext, &self.hash)?;

        self.mix_hash(&ciphertext);

        Ok(ciphertext)
    }

    /// DecryptAndHash(ciphertext)
    /// Returns plaintext = AEAD_DECRYPT(k, 0, ciphertext, h)
    /// Then sets h = HASH(h || ciphertext)
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.encryption_key
            .ok_or("No encryption key set")?;

        // Decrypt with counter 0 and current hash as additional data
        let plaintext = aead_decrypt(&key, 0, ciphertext, &self.hash)?;

        // Mix the ciphertext (not plaintext) into hash
        self.mix_hash(ciphertext);

        Ok(plaintext)
    }

    /// Split() - Derive transport keys
    /// Returns (send_key, receive_key)
    /// For responder: send = T1, receive = T2
    /// For initiator: send = T2, receive = T1
    pub fn split(&self) -> ([u8; 32], [u8; 32]) {
        kdf2(&self.chaining_key, &[])
    }

    /// Get current hash (for debugging/testing)
    pub fn get_hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Get current chaining key (for debugging/testing)
    pub fn get_chaining_key(&self) -> &[u8; 32] {
        &self.chaining_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_initialization() {
        let state = NoiseState::initialize(CONSTRUCTION);

        // Hash should be HASH(CONSTRUCTION)
        let mut hasher = <Blake2s256 as Digest>::new();
        <Blake2s256 as Update>::update(&mut hasher, CONSTRUCTION);
        let expected_hash = hasher.finalize();

        assert_eq!(&state.hash[..], &expected_hash[..]);
        assert_eq!(state.chaining_key, state.hash);
        assert!(state.encryption_key.is_none());
    }

    #[test]
    fn test_mix_hash() {
        let mut state = NoiseState::initialize(CONSTRUCTION);
        let data = b"test data";

        let old_hash = state.hash;
        state.mix_hash(data);

        // Hash should have changed
        assert_ne!(state.hash, old_hash);

        // Chaining key should be unchanged
        assert_eq!(state.chaining_key, old_hash);
    }

    #[test]
    fn test_mix_key() {
        let mut state = NoiseState::initialize(CONSTRUCTION);
        let ikm = [0x42u8; 32];

        assert!(state.encryption_key.is_none());

        state.mix_key(&ikm);

        // Encryption key should now be set
        assert!(state.encryption_key.is_some());

        // Chaining key should have changed
        assert_ne!(state.chaining_key, state.hash);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let mut state1 = NoiseState::initialize(CONSTRUCTION);
        let mut state2 = state1.clone();

        // Set up a key
        let ikm = [0x42u8; 32];
        state1.mix_key(&ikm);
        state2.mix_key(&ikm);

        // Encrypt with state1
        let plaintext = b"Hello, Noise!";
        let ciphertext = state1.encrypt_and_hash(plaintext).unwrap();

        // Decrypt with state2
        let decrypted = state2.decrypt_and_hash(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);

        // Both states should have same hash now
        assert_eq!(state1.hash, state2.hash);
    }

    #[test]
    fn test_split() {
        let mut state = NoiseState::initialize(CONSTRUCTION);
        state.mix_key(&[0x42u8; 32]);

        let (key1, key2) = state.split();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be deterministic
        let (key1_again, key2_again) = state.split();
        assert_eq!(key1, key1_again);
        assert_eq!(key2, key2_again);
    }
}
