# WireGuard Noise Protocol Implementation Plan

## Overview

WireGuard uses the Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s protocol framework. This document outlines the implementation plan for full WireGuard handshake support.

## Current Status

✅ **Completed:**
- Packet structure parsing (WgMessage, WgHandshakeInit, WgHandshakeResponse, etc.)
- MAC1/MAC2 calculation using BLAKE2s
- Curve25519 key generation and derivation
- Basic message encoding/decoding

❌ **Missing:**
- Noise protocol handshake state machine
- ChaCha20-Poly1305 AEAD encryption/decryption
- HKDF key derivation
- Proper handshake state management
- Session key derivation

## Noise Protocol IKpsk2 Pattern

```
IKpsk2:
  <- s
  ...
  -> e, es, s, ss, psk
  <- e, ee, se, psk
```

### Handshake Flow

**Pre-handshake:**
- Initiator knows responder's static public key `Sr`
- Both parties have a pre-shared key (PSK) - optional

**Message 1 (Handshake Initiation):**
```
initiator -> responder: e, es, s, ss
```
- `e`: ephemeral public key (unencrypted)
- `es`: DH(Ei, Sr) - used for encrypting static key
- `s`: static public key (encrypted with es)
- `ss`: DH(Si, Sr) - mixed into key derivation

**Message 2 (Handshake Response):**
```
responder -> initiator: e, ee, se
```
- `e`: ephemeral public key (unencrypted)
- `ee`: DH(Er, Ei) - ephemeral-ephemeral DH
- `se`: DH(Er, Si) - responder ephemeral to initiator static

## Implementation Tasks

### 1. Add Required Crypto Dependencies

**Cargo.toml additions:**
```toml
chacha20poly1305 = "0.10"
hkdf = "0.12"
sha2 = "0.10"  # For HKDF with SHA256 (though WG uses BLAKE2s)
```

Actually, WireGuard uses BLAKE2s for HKDF, so we need BLAKE2s-based HKDF.

### 2. Noise Protocol State Machine

**File: `src/protocols/wireguard_noise.rs`**

```rust
pub struct NoiseState {
    chaining_key: [u8; 32],
    hash: [u8; 32],
    ephemeral_private: Option<[u8; 32]>,
    ephemeral_public: Option<[u8; 32]>,
    remote_static: Option<[u8; 32]>,
    remote_ephemeral: Option<[u8; 32]>,
}

impl NoiseState {
    // Initialize with protocol name
    fn initialize(protocol_name: &[u8]) -> Self;

    // Mix a key into the chaining key
    fn mix_key(&mut self, input_key_material: &[u8]);

    // Mix data into the hash
    fn mix_hash(&mut self, data: &[u8]);

    // Mix a pre-shared key
    fn mix_key_and_hash(&mut self, psk: &[u8]);

    // Encrypt with current chaining key
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8>;

    // Decrypt with current chaining key
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    // Derive transport keys
    fn split(&self) -> (TransportKeys, TransportKeys);
}
```

### 3. WireGuard-Specific Crypto Functions

**File: `src/protocols/wireguard_crypto.rs`**

#### 3.1 HKDF with BLAKE2s

```rust
/// HKDF-Extract using BLAKE2s
fn hkdf_extract(salt: &[u8], input_key_material: &[u8]) -> [u8; 32] {
    // HMAC-BLAKE2s(salt, ikm)
    // Returns 32-byte key
}

/// HKDF-Expand using BLAKE2s
fn hkdf_expand(prk: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    // Expand PRK to output_len bytes
}

/// WireGuard-specific HKDF (2 outputs)
fn kdf2(chaining_key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    // Returns (T1, T2) where:
    // T1 = HMAC(chaining_key, input || 0x01)
    // T2 = HMAC(chaining_key, T1 || input || 0x02)
}

/// WireGuard-specific HKDF (3 outputs)
fn kdf3(chaining_key: &[u8], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    // Returns (T1, T2, T3)
}
```

#### 3.2 AEAD Encryption/Decryption

```rust
/// Encrypt with ChaCha20-Poly1305
fn aead_encrypt(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    auth_data: &[u8],
) -> Vec<u8> {
    // Returns ciphertext || tag (16 bytes)
}

/// Decrypt with ChaCha20-Poly1305
fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],  // includes 16-byte tag
    auth_data: &[u8],
) -> Result<Vec<u8>, Error> {
    // Returns plaintext or error
}
```

### 4. Handshake Initiation Processing (Responder Side)

**Function: `process_handshake_initiation`**

```rust
pub fn process_handshake_initiation(
    init: &WgHandshakeInit,
    responder_private: &[u8; 32],
    responder_public: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<HandshakeState, Error> {
    // 1. Initialize Noise state
    let mut state = NoiseState::initialize(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");

    // 2. Hash protocol identifier and responder public key
    state.mix_hash(CONSTRUCTION);  // "WireGuard v1 zx2c4 Jason@zx2c4.com"
    state.mix_hash(&IDENTIFIER);   // "WireGuard v1 zx2c4 Jason@zx2c4.com"
    state.mix_hash(responder_public);

    // 3. Mix initiator's ephemeral key
    state.mix_hash(&init.unencrypted_ephemeral);

    // 4. Perform DH: es = DH(Ei, Sr)
    let es = dh(responder_private, &init.unencrypted_ephemeral);
    state.mix_key(&es);

    // 5. Decrypt initiator's static public key
    let initiator_static = state.decrypt_and_hash(&init.encrypted_static)?;

    // 6. Perform DH: ss = DH(Si, Sr)
    let ss = dh(responder_private, &initiator_static);
    state.mix_key(&ss);

    // 7. Mix PSK if present
    if let Some(psk) = psk {
        state.mix_key_and_hash(psk);
    }

    // 8. Decrypt and verify timestamp
    let timestamp = state.decrypt_and_hash(&init.encrypted_timestamp)?;

    // 9. Return state for generating response
    Ok(HandshakeState {
        state,
        initiator_static,
        initiator_ephemeral: init.unencrypted_ephemeral,
        sender_index: init.sender_index,
        timestamp,
    })
}
```

### 5. Handshake Response Generation (Responder Side)

**Function: `create_handshake_response`**

```rust
pub fn create_handshake_response(
    hs: &mut HandshakeState,
    responder_private: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> Result<WgHandshakeResponse, Error> {
    // 1. Generate ephemeral key pair
    let (eph_private, eph_public) = generate_ephemeral_keypair();

    // 2. Mix responder's ephemeral key
    hs.state.mix_hash(&eph_public);

    // 3. Perform DH: ee = DH(Er, Ei)
    let ee = dh(&eph_private, &hs.initiator_ephemeral);
    hs.state.mix_key(&ee);

    // 4. Perform DH: se = DH(Er, Si)
    let se = dh(&eph_private, &hs.initiator_static);
    hs.state.mix_key(&se);

    // 5. Mix PSK if present
    if let Some(psk) = psk {
        hs.state.mix_key_and_hash(psk);
    }

    // 6. Encrypt empty payload
    let encrypted_nothing = hs.state.encrypt_and_hash(&[]);

    // 7. Derive transport keys
    let (tx_key, rx_key) = hs.state.split();

    // 8. Create response
    let response = WgHandshakeResponse {
        sender_index: Value::Set(generate_sender_index()),
        receiver_index: Value::Set(hs.sender_index),
        unencrypted_ephemeral: eph_public.to_vec(),
        encrypted_nothing,
        mac1: vec![0; 16],  // Will be calculated later
        mac2: vec![0; 16],  // No cookie for now
    };

    Ok(response)
}
```

### 6. Session Key Management

```rust
pub struct TransportKeys {
    pub key: [u8; 32],
    pub counter: AtomicU64,
}

pub struct WireGuardSession {
    pub local_index: u32,
    pub remote_index: u32,
    pub tx_key: TransportKeys,
    pub rx_key: TransportKeys,
    pub created_at: Instant,
}
```

### 7. Constants

```rust
// WireGuard protocol constants
const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

// Noise protocol constants
const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const EMPTY_KEY: [u8; 32] = [0u8; 32];
```

## Implementation Order

### Phase 1: Core Crypto Primitives (Priority: HIGH)
1. ✅ BLAKE2s hashing (already have via `blake2` crate)
2. ✅ Curve25519 DH (already have via `x25519-dalek`)
3. ⚠️  HKDF with BLAKE2s backend
4. ⚠️  ChaCha20-Poly1305 AEAD

### Phase 2: Noise Protocol Framework (Priority: HIGH)
1. `NoiseState` struct and methods
2. `mix_key`, `mix_hash`, `mix_key_and_hash`
3. `encrypt_and_hash`, `decrypt_and_hash`
4. `split` for transport key derivation

### Phase 3: WireGuard Handshake (Priority: HIGH)
1. `process_handshake_initiation` (responder receives init)
2. `create_handshake_response` (responder sends response)
3. `process_handshake_response` (initiator receives response)
4. Session establishment and key storage

### Phase 4: Data Transport (Priority: MEDIUM)
1. Encrypt transport data packets
2. Decrypt transport data packets
3. Counter management and replay protection
4. Key rotation

### Phase 5: Advanced Features (Priority: LOW)
1. Cookie mechanism for DDoS protection
2. Persistent keepalive
3. Roaming support
4. Under-load queue

## Testing Strategy

### Unit Tests
- Individual crypto primitives (HKDF, AEAD, DH)
- Noise state transitions
- Key derivation vectors

### Integration Tests
- Full handshake between two instances
- Test vectors from WireGuard specification
- Interoperability with official WireGuard implementation

### Test Vectors
WireGuard specification includes test vectors for:
- BLAKE2s hashes
- HKDF outputs
- Handshake intermediate values
- Complete handshake exchanges

## Key Challenges

1. **HKDF with BLAKE2s**: Standard `hkdf` crate uses HMAC-SHA256. We need HMAC-BLAKE2s variant.
2. **Noise Protocol State**: Careful state management to avoid cryptographic errors
3. **Replay Protection**: Need to track packet counters and reject replays
4. **Timing**: Proper timeout and retransmission logic
5. **Key Rotation**: WireGuard rotates keys after ~2^64-1 messages or 120 seconds

## Security Considerations

1. **Constant-Time Operations**: Use constant-time comparison for MACs and tags
2. **Key Zeroization**: Clear sensitive key material from memory when done
3. **RNG Quality**: Use cryptographically secure random number generator (OsRng)
4. **Replay Protection**: Implement anti-replay window
5. **Forward Secrecy**: Ephemeral keys provide forward secrecy

## References

1. WireGuard Whitepaper: https://www.wireguard.com/papers/wireguard.pdf
2. Noise Protocol Framework: https://noiseprotocol.org/noise.html
3. WireGuard Protocol Spec: https://www.wireguard.com/protocol/
4. Noise_IKpsk2 Pattern: https://noiseexplorer.com/patterns/IKpsk2/

## File Structure

```
src/protocols/
├── wireguard.rs              # Packet structures (existing)
├── wireguard_crypto.rs       # Crypto primitives (HKDF, AEAD)
├── wireguard_noise.rs        # Noise protocol state machine
├── wireguard_handshake.rs    # Handshake logic
└── wireguard_session.rs      # Session management

examples/
├── wireguard_server.rs       # Server example (existing)
└── wireguard_client.rs       # Client example (new)
```

## Next Steps

1. Add `chacha20poly1305` and implement AEAD functions
2. Implement BLAKE2s-based HKDF (KDF1, KDF2, KDF3)
3. Create `NoiseState` structure
4. Implement `process_handshake_initiation`
5. Update `wireguard_server.rs` to use real crypto
6. Test with official WireGuard client

## Estimated Effort

- **Phase 1**: 2-3 hours (crypto primitives)
- **Phase 2**: 3-4 hours (Noise protocol)
- **Phase 3**: 4-5 hours (handshake implementation)
- **Phase 4**: 3-4 hours (data transport)
- **Phase 5**: 2-3 hours (advanced features)

**Total**: ~15-20 hours for complete implementation

## Notes

- WireGuard uses little-endian for ChaCha20 counter
- TAI64N timestamps are 12 bytes (TAI64 8 bytes + nanoseconds 4 bytes)
- Session index is random 32-bit value
- Handshake timeout is 180 seconds
- Rekey after 2 minutes or 2^64-1 messages (whichever comes first)
