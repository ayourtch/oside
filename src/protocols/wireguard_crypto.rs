use blake2::{Blake2sMac, Digest};
use blake2::digest::{Update, Mac, KeyInit, consts::U16, consts::U32};
use chacha20poly1305::{
    aead::{Aead, KeyInit as AeadKeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

// WireGuard protocol constants
pub const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";

/// HMAC using BLAKE2s (32-byte output)
pub fn hmac_blake2s(key: &[u8], data: &[u8]) -> [u8; 32] {
    type Blake2sMac256 = Blake2sMac<U32>;
    let mut mac = <Blake2sMac256 as KeyInit>::new_from_slice(key)
        .expect("Blake2sMac should accept any key size");
    <Blake2sMac256 as Update>::update(&mut mac, data);
    let result = <Blake2sMac256 as Mac>::finalize(mac);
    let code_bytes = result.into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&code_bytes);
    output
}

/// WireGuard KDF with 1 output
/// Returns T1 = HMAC(key, input || 0x01)
pub fn kdf1(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut data = input.to_vec();
    data.push(0x01);
    hmac_blake2s(key, &data)
}

/// WireGuard KDF with 2 outputs
/// Returns (T1, T2) where:
/// T1 = HMAC(key, input || 0x01)
/// T2 = HMAC(key, T1 || input || 0x02)
pub fn kdf2(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut data1 = input.to_vec();
    data1.push(0x01);
    let t1 = hmac_blake2s(key, &data1);

    let mut data2 = Vec::new();
    data2.extend_from_slice(&t1);
    data2.extend_from_slice(input);
    data2.push(0x02);
    let t2 = hmac_blake2s(key, &data2);

    (t1, t2)
}

/// WireGuard KDF with 3 outputs
/// Returns (T1, T2, T3) where:
/// T1 = HMAC(key, input || 0x01)
/// T2 = HMAC(key, T1 || input || 0x02)
/// T3 = HMAC(key, T2 || input || 0x03)
pub fn kdf3(key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (t1, t2) = kdf2(key, input);

    let mut data3 = Vec::new();
    data3.extend_from_slice(&t2);
    data3.extend_from_slice(input);
    data3.push(0x03);
    let t3 = hmac_blake2s(key, &data3);

    (t1, t2, t3)
}

/// Encrypt with ChaCha20-Poly1305
/// counter is used as the nonce (little-endian 64-bit, padded to 96 bits)
/// Returns ciphertext || 16-byte authentication tag
pub fn aead_encrypt(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    auth_data: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());

    // Create nonce: 4 bytes of zeros || 8 bytes counter (little-endian)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: auth_data,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("Encryption failed: {:?}", e))
}

/// Decrypt with ChaCha20-Poly1305
/// counter is used as the nonce (little-endian 64-bit, padded to 96 bits)
/// ciphertext includes the 16-byte authentication tag at the end
/// Returns plaintext or error
pub fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],  // includes 16-byte tag
    auth_data: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());

    // Create nonce: 4 bytes of zeros || 8 bytes counter (little-endian)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: ciphertext,
        aad: auth_data,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| format!("Decryption failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf1() {
        let key = [0u8; 32];
        let input = b"test";
        let output = kdf1(&key, input);
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_kdf2() {
        let key = [0u8; 32];
        let input = b"test";
        let (t1, t2) = kdf2(&key, input);
        assert_eq!(t1.len(), 32);
        assert_eq!(t2.len(), 32);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_kdf3() {
        let key = [0u8; 32];
        let input = b"test";
        let (t1, t2, t3) = kdf3(&key, input);
        assert_eq!(t1.len(), 32);
        assert_eq!(t2.len(), 32);
        assert_eq!(t3.len(), 32);
        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_aead_encrypt_decrypt() {
        let key = [0u8; 32];
        let counter = 0;
        let plaintext = b"Hello, WireGuard!";
        let auth_data = b"additional data";

        let ciphertext = aead_encrypt(&key, counter, plaintext, auth_data).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);  // +16 for tag

        let decrypted = aead_decrypt(&key, counter, &ciphertext, auth_data).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_wrong_key_fails() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let counter = 0;
        let plaintext = b"Hello, WireGuard!";
        let auth_data = b"additional data";

        let ciphertext = aead_encrypt(&key1, counter, plaintext, auth_data).unwrap();
        let result = aead_decrypt(&key2, counter, &ciphertext, auth_data);
        assert!(result.is_err());
    }
}
