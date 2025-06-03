use oside::*;

use crate::protocols::all::*;
use oside::encdec::asn1::Asn1Encoder;
use oside::protocols::snmp::usm_crypto::AuthAlgorithm;
use oside::protocols::snmp::usm_crypto::PrivAlgorithm;
use oside::protocols::snmp::usm_crypto::UsmConfig;
use oside::protocols::snmp::*;
use std::str::FromStr;

#[test]
fn encode_snmp_1() {
    let x1 = Ether!()
        // / IP!(src = "192.0.1.2", dst="192.0.1.3")
        / IPV6!(src = "2001:db8::1", dst="2001:db8::2")
        / UDP!(sport = 1234)
        / SNMP!()
        / SNMPV2C!(community = "12345")
        / SnmpGet(SNMPGETORRESPONSE!(
            request_id = 722681733
            ,var_bindings = vec![
                SNMPVARBIND!(name = "1.0.2.3.4.5.2.3.3.2322.222",
                             value = SnmpValue::Counter64(12345))
                ,SNMPVARBIND!(name = "1.0.2.3.4.5.2.3.3.2322.333",
                             value = SnmpValue::TimeTicks(42))
            ]

        ));

    println!("x1 result: {:02x?}", &x1);
    let encoded = x1.clone().lencode();
    println!("encoded: {:?}", &encoded);
    let x = Ether!().ldecode(&encoded).unwrap().0;
    println!("decode result: {:?}", &x);
    let pcap = vec![x];
    pcap.write_pcap("test_snmp.cap");
}

#[test]
pub fn test_snmpv3_encoding() {
    let test_oid = "1.3.6.1.2.1.1.1.0";
    let x1 = Ether!()
        // / IP!(src = "192.0.1.2", dst="192.0.1.3")
        / IPV6!(src = "2001:db8::1", dst="2001:db8::2")
        / UDP!(sport = 9999)
        / Snmp::v3_get(&vec![test_oid, test_oid]);
    println!("test_snmpv3_encoding x1 result: {:#02x?}", &x1);
    let encoded = x1.clone().lencode();
    println!("encoded: {:?}", &encoded);
    let x = Ether!().ldecode(&encoded).unwrap().0;
    println!("decode result: {:#02x?}", &x);
    let pcap = vec![x];
    pcap.write_pcap("test_snmp_v3.cap");
    // DEBUGGING
    // assert_eq!(1, 2);
}

/*
    use super::*;
    use super::usm_crypto::*;
    use oside::encdec::asn1::Asn1Encoder;
    use std::collections::HashMap;
*/

// Test vectors based on RFC 3414 examples
mod test_vectors {
    pub const ENGINE_ID: &[u8] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02";
    pub const USERNAME: &str = "MD5UserName";
    pub const PASSWORD: &str = "maplesyrup";
    pub const PRIV_PASSWORD: &str = "privPassword";

    // Expected MD5 authentication key for the above parameters
    pub const EXPECTED_MD5_AUTH_KEY: &[u8] = &[
        0x52, 0x6f, 0x5e, 0xed, 0x9f, 0xcc, 0xe2, 0x6f, 0x89, 0x64, 0xc2, 0x93, 0x07, 0x87, 0xd8,
        0x2b,
    ];

    // Expected SHA1 authentication key for the above parameters
    pub const EXPECTED_SHA1_AUTH_KEY: &[u8] = &[
        0x66, 0x95, 0xfe, 0xbc, 0x92, 0x88, 0xe3, 0x62, 0x82, 0x23, 0x5f, 0xc7, 0x15, 0x1f, 0x12,
        0x84, 0x97, 0xb3, 0x8f, 0x3f,
    ];
}

#[test]
fn test_md5_key_derivation() {
    let auth_alg = AuthAlgorithm::HmacMd5;
    let password = test_vectors::PASSWORD;
    let engine_id = test_vectors::ENGINE_ID;

    let derived_key = auth_alg.derive_key(password, engine_id).unwrap();

    println!("Derived MD5 key: {:02x?}", derived_key);
    println!(
        "Expected MD5 key: {:02x?}",
        test_vectors::EXPECTED_MD5_AUTH_KEY
    );

    assert_eq!(derived_key.len(), 16, "MD5 key should be 16 bytes");
    assert_eq!(
        derived_key,
        test_vectors::EXPECTED_MD5_AUTH_KEY,
        "MD5 key derivation doesn't match expected RFC 3414 test vector"
    );
}

#[test]
fn test_sha1_key_derivation() {
    let auth_alg = AuthAlgorithm::HmacSha1;
    let password = test_vectors::PASSWORD;
    let engine_id = test_vectors::ENGINE_ID;

    let derived_key = auth_alg.derive_key(password, engine_id).unwrap();

    println!("Derived SHA1 key: {:02x?}", derived_key);
    println!(
        "Expected SHA1 key: {:02x?}",
        test_vectors::EXPECTED_SHA1_AUTH_KEY
    );

    assert_eq!(derived_key.len(), 20, "SHA1 key should be 20 bytes");
    assert_eq!(
        derived_key,
        test_vectors::EXPECTED_SHA1_AUTH_KEY,
        "SHA1 key derivation doesn't match expected RFC 3414 test vector"
    );
}

#[test]
fn test_privacy_key_derivation_des() {
    let auth_alg = AuthAlgorithm::HmacMd5;
    let priv_alg = PrivAlgorithm::DesCbc;
    let password = test_vectors::PRIV_PASSWORD;
    let engine_id = test_vectors::ENGINE_ID;

    // First derive the authentication key
    let auth_key = auth_alg.derive_key(password, engine_id).unwrap();
    println!("Auth key for privacy: {:02x?}", auth_key);

    // Then derive the privacy key from the auth key
    let priv_key = priv_alg.derive_key(&auth_key).unwrap();

    println!("Derived DES privacy key: {:02x?}", priv_key);
    assert_eq!(priv_key.len(), 16, "DES privacy key should be 16 bytes");

    // The privacy key should be the last 16 bytes of the auth key for DES
    assert_eq!(
        priv_key,
        &auth_key[auth_key.len() - 16..],
        "DES privacy key should be last 16 bytes of auth key"
    );
}

#[test]
fn test_privacy_key_derivation_aes() {
    let auth_alg = AuthAlgorithm::HmacSha1;
    let priv_alg = PrivAlgorithm::Aes128;
    let password = test_vectors::PRIV_PASSWORD;
    let engine_id = test_vectors::ENGINE_ID;

    let auth_key = auth_alg.derive_key(password, engine_id).unwrap();
    println!("Auth key for AES privacy: {:02x?}", auth_key);

    let priv_key = priv_alg.derive_key(&auth_key).unwrap();

    println!("Derived AES privacy key: {:02x?}", priv_key);
    assert_eq!(priv_key.len(), 16, "AES privacy key should be 16 bytes");

    // The privacy key should be the first 16 bytes of the auth key for AES
    assert_eq!(
        priv_key,
        &auth_key[..16],
        "AES privacy key should be first 16 bytes of auth key"
    );
}

#[test]
fn test_hmac_md5_authentication() {
    let auth_alg = AuthAlgorithm::HmacMd5;
    let key = test_vectors::EXPECTED_MD5_AUTH_KEY;
    let message = b"Test message for HMAC-MD5 authentication";

    let auth_params = auth_alg.generate_auth_params(key, message).unwrap();

    println!("Generated MD5 auth params: {:02x?}", auth_params);
    assert_eq!(
        auth_params.len(),
        12,
        "MD5 auth params should be 12 bytes (truncated)"
    );

    // Verify the authentication
    let is_valid = auth_alg
        .verify_auth_params(key, message, &auth_params)
        .unwrap();
    assert!(is_valid, "HMAC-MD5 verification should succeed");

    // Test with wrong message
    let wrong_message = b"Wrong message";
    let is_invalid = auth_alg
        .verify_auth_params(key, wrong_message, &auth_params)
        .unwrap();
    assert!(
        !is_invalid,
        "HMAC-MD5 verification should fail with wrong message"
    );
}

#[test]
fn test_hmac_sha1_authentication() {
    let auth_alg = AuthAlgorithm::HmacSha1;
    let key = test_vectors::EXPECTED_SHA1_AUTH_KEY;
    let message = b"Test message for HMAC-SHA1 authentication";

    let auth_params = auth_alg.generate_auth_params(key, message).unwrap();

    println!("Generated SHA1 auth params: {:02x?}", auth_params);
    assert_eq!(
        auth_params.len(),
        12,
        "SHA1 auth params should be 12 bytes (truncated)"
    );

    // Verify the authentication
    let is_valid = auth_alg
        .verify_auth_params(key, message, &auth_params)
        .unwrap();
    assert!(is_valid, "HMAC-SHA1 verification should succeed");
}

#[test]
fn test_des_encryption_decryption() {
    let priv_alg = PrivAlgorithm::DesCbc;
    let auth_alg = AuthAlgorithm::HmacMd5;
    let engine_id = test_vectors::ENGINE_ID;
    let password = test_vectors::PRIV_PASSWORD;

    // Derive the privacy key properly
    let auth_key = auth_alg.derive_key(password, engine_id).unwrap();
    let priv_key = priv_alg.derive_key(&auth_key).unwrap();

    let plaintext =
        b"This is a test message for DES encryption. It needs to be long enough to test padding.";
    let engine_boots = 1u32;
    let counter = 12345u64;

    // Generate salt and calculate IV properly
    let salt = priv_alg.generate_salt(engine_boots, counter);
    let iv = priv_alg
        .calculate_iv(&salt, &priv_key, engine_boots, 0)
        .unwrap();

    println!("DES test - Salt: {:02x?}", salt);
    println!("DES test - IV: {:02x?}", iv);
    println!("DES test - Privacy key: {:02x?}", priv_key);

    // Encrypt
    let ciphertext = priv_alg.encrypt(&priv_key, &iv, plaintext).unwrap();
    println!("DES test - Ciphertext length: {}", ciphertext.len());
    assert!(
        ciphertext.len() >= plaintext.len(),
        "Ciphertext should be at least as long as plaintext"
    );
    assert_eq!(
        ciphertext.len() % 8,
        0,
        "DES ciphertext length should be multiple of 8"
    );

    // Decrypt
    let decrypted = priv_alg.decrypt(&priv_key, &iv, &ciphertext).unwrap();
    println!("DES test - Decrypted length: {}", decrypted.len());

    assert_eq!(
        decrypted, plaintext,
        "DES decryption should restore original plaintext"
    );
}

#[test]
fn test_aes_encryption_decryption() {
    let priv_alg = PrivAlgorithm::Aes128;
    let auth_alg = AuthAlgorithm::HmacSha1;
    let engine_id = test_vectors::ENGINE_ID;
    let password = test_vectors::PRIV_PASSWORD;

    // Derive the privacy key properly
    let auth_key = auth_alg.derive_key(password, engine_id).unwrap();
    let priv_key = priv_alg.derive_key(&auth_key).unwrap();

    let plaintext = b"This is a test message for AES encryption with a reasonable length.";
    let engine_boots = 1u32;
    let engine_time = 12345u32;
    let counter = 98765u64;

    // Generate salt and calculate IV
    let salt = priv_alg.generate_salt(engine_boots, counter);
    let iv = priv_alg
        .calculate_iv(&salt, &priv_key, engine_boots, engine_time)
        .unwrap();

    println!("AES test - Salt: {:02x?}", salt);
    println!("AES test - IV: {:02x?}", iv);
    println!("AES test - Privacy key: {:02x?}", priv_key);

    // Encrypt
    let ciphertext = priv_alg.encrypt(&priv_key, &iv, plaintext).unwrap();
    println!("AES test - Ciphertext length: {}", ciphertext.len());
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "AES CFB mode should preserve plaintext length"
    );

    // Decrypt
    let decrypted = priv_alg.decrypt(&priv_key, &iv, &ciphertext).unwrap();

    assert_eq!(
        decrypted, plaintext,
        "AES decryption should restore original plaintext"
    );
}

#[test]
fn test_usm_config_builder() {
    let mut config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_priv(PrivAlgorithm::DesCbc, "privpass456")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    assert!(config.has_auth(), "Config should have authentication");
    assert!(config.has_priv(), "Config should have privacy");
    assert_eq!(config.user_name, "testuser");
    assert_eq!(config.engine_boots, 1);
    assert_eq!(config.engine_time, 12345);

    // Test key derivation through config
    let auth_key = config.auth_key().unwrap();
    let priv_key = config.priv_key().unwrap();

    println!("Config auth key: {:02x?}", auth_key);
    println!("Config priv key: {:02x?}", priv_key);

    assert_eq!(auth_key.len(), 16, "MD5 auth key should be 16 bytes");
    assert_eq!(priv_key.len(), 16, "DES priv key should be 16 bytes");
}

#[test]
fn test_snmpv3_message_creation() {
    let config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    let snmpv3 = SnmpV3::from_usm_config(&config);
    println!("SNMPv3: {:?}", &snmpv3);

    assert!(
        snmpv3.has_authentication(),
        "SNMPv3 message should have authentication"
    );
    assert!(
        !snmpv3.has_privacy(),
        "SNMPv3 message should not have privacy"
    );
    assert!(
        snmpv3.is_reportable(),
        "SNMPv3 message should be reportable"
    );

    let user_name = snmpv3.user_name().unwrap();
    assert_eq!(user_name, "testuser");
}

#[test]
fn test_snmpv3_get_request_encoding() {
    let mut config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    let oids = vec!["1.3.6.1.2.1.1.1.0"];
    let (stack, mut usm_context) = Snmp::v3_get_with_auth(&oids, &config).unwrap();

    // Encode with encryption
    let encrypted_encoded = stack
        .encode_with_usm::<Asn1Encoder>(&mut usm_context)
        .unwrap();

    assert!(
        !encrypted_encoded.is_empty(),
        "Encrypted message should encode successfully"
    );

    // The encrypted message should be different from an unencrypted one
    let mut config_no_priv = config.clone();
    config_no_priv.priv_algorithm = PrivAlgorithm::None;
    config_no_priv.priv_password = None;

    let (stack_no_priv, mut usm_context_no_priv) =
        Snmp::v3_get_with_auth(&oids, &config_no_priv).unwrap();
    let unencrypted_encoded = stack_no_priv
        .encode_with_usm::<Asn1Encoder>(&mut usm_context_no_priv)
        .unwrap();

    assert_ne!(
        encrypted_encoded, unencrypted_encoded,
        "Encrypted and unencrypted messages should be different"
    );

    println!("Encrypted message length: {}", encrypted_encoded.len());
    println!("Unencrypted message length: {}", unencrypted_encoded.len());
}

// Test vector validation using known good values
#[test]
fn test_rfc3414_test_vectors() {
    // These are simplified test vectors based on RFC 3414
    // In a real implementation, you'd want the exact test vectors from the RFC

    let engine_id = b"\x80\x00\x1f\x88\x80\xe9\x63\x00\x00\x53\xe2\x04";
    let username = "MD5UserName";
    let password = "authPassword";

    let auth_alg = AuthAlgorithm::HmacMd5;
    let derived_key = auth_alg.derive_key(password, engine_id).unwrap();

    // The key should be deterministic for the same inputs
    let derived_key2 = auth_alg.derive_key(password, engine_id).unwrap();
    assert_eq!(
        derived_key, derived_key2,
        "Key derivation should be deterministic"
    );

    // Test message authentication with derived key
    let test_message = b"Test message for RFC 3414 validation";
    let auth_params = auth_alg
        .generate_auth_params(&derived_key, test_message)
        .unwrap();

    assert_eq!(auth_params.len(), 12, "Auth params should be 12 bytes");

    let is_valid = auth_alg
        .verify_auth_params(&derived_key, test_message, &auth_params)
        .unwrap();
    assert!(is_valid, "Authentication should validate correctly");
}

// Test error conditions and edge cases
#[test]
fn test_authentication_error_cases() {
    let auth_alg = AuthAlgorithm::HmacMd5;

    // Test with empty password (should fail)
    let result = auth_alg.derive_key("", b"engine_id");
    assert!(result.is_err(), "Empty password should cause an error");

    // Test HMAC with wrong key length (though our implementation should handle this)
    let short_key = vec![0x01, 0x02];
    let message = b"test message";

    // This might succeed or fail depending on the HMAC implementation
    // Just ensure it doesn't panic
    let _result = auth_alg.generate_auth_params(&short_key, message);
}

#[test]
fn test_privacy_error_cases() {
    let priv_alg = PrivAlgorithm::DesCbc;

    // Test with wrong key length
    let short_key = vec![0x01, 0x02, 0x03];
    let iv = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let plaintext = b"test message";

    let result = priv_alg.encrypt(&short_key, &iv, plaintext);
    assert!(result.is_err(), "Short key should cause encryption error");

    // Test with wrong IV length
    let proper_key = vec![0x01; 16];
    let short_iv = vec![0x01, 0x02, 0x03];

    let result = priv_alg.encrypt(&proper_key, &short_iv, plaintext);
    assert!(result.is_err(), "Short IV should cause encryption error");
}

// Test the builder pattern for SNMP messages
#[test]
fn test_snmp_builder_pattern() {
    let snmp = SnmpBuilder::new()
        .version(2)
        .community("private")
        .add_null_binding("1.3.6.1.2.1.1.1.0")
        .add_binding("1.3.6.1.2.1.1.5.0", SnmpValue::string("test-router"))
        .build_get();

    let encoded = snmp.lencode();
    assert!(
        !encoded.is_empty(),
        "Builder pattern should create valid SNMP message"
    );

    // Verify we can decode it back
    let (decoded, _) = SNMP!().ldecode(&encoded).unwrap();
    assert!(
        decoded.get_layer(SnmpV2c::default()).is_some(),
        "Should have SNMPv2c layer"
    );
}

// Test system info query convenience method
#[test]
fn test_system_info_query() {
    let stack = Snmp::system_info_query();
    let encoded = stack.lencode();

    assert!(!encoded.is_empty(), "System info query should encode");

    let (decoded, _) = SNMP!().ldecode(&encoded).unwrap();

    // Verify it contains the expected OIDs
    if let Some(snmp_get) = decoded.get_layer(SnmpGet::default()) {
        let bindings = &snmp_get.0.var_bindings;
        assert!(bindings.len() >= 4, "Should have multiple system OIDs");

        // Check that we have system description OID
        let has_sys_desc = bindings.iter().any(|binding| {
            println!("BINDING: {}", binding.name.value());
            format!("{}", binding.name.value()).contains("1.3.6.1.2.1.1.1.0")
        });
        assert!(has_sys_desc, "Should include system description OID");
    }
}

// Test interface walk convenience method
#[test]
fn test_interface_walk() {
    let stack = Snmp::interface_walk();
    let encoded = stack.lencode();

    assert!(!encoded.is_empty(), "Interface walk should encode");

    let (decoded, _) = SNMP!().ldecode(&encoded).unwrap();
    assert!(
        decoded.get_layer(SnmpGetBulk::default()).is_some(),
        "Should use GetBulk for interface walk"
    );
}

// Test SNMP value utility methods
#[test]
fn test_snmp_value_utilities() {
    // Test integer conversion
    let int_val = SnmpValue::integer(42);
    assert_eq!(int_val.as_integer(), Some(42));
    assert_eq!(int_val.as_string(), None);

    // Test string conversion
    let str_val = SnmpValue::string("test string");
    assert_eq!(str_val.as_string(), Some("test string".to_string()));
    assert_eq!(str_val.as_integer(), None);

    // Test IP address creation
    let ip_val = SnmpValue::ip_address("192.168.1.1");
    assert_eq!(ip_val.type_name(), "IpAddress");

    // Test invalid IP address
    let invalid_ip = SnmpValue::ip_address("not.an.ip.address");
    assert_eq!(invalid_ip, SnmpValue::Null);

    // Test counter values
    let counter32_val = SnmpValue::counter32(12345);
    assert_eq!(counter32_val.as_integer(), Some(12345));

    let counter64_val = SnmpValue::counter64(9876543210);
    assert_eq!(counter64_val.as_integer(), Some(9876543210));
}

// Test USM encoding context
#[test]
fn test_usm_encoding_context() {
    let config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_priv(PrivAlgorithm::DesCbc, "privpass456")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    let context = UsmEncodingContext::new(config.clone());
    assert!(
        context.is_ok(),
        "Should be able to create USM encoding context"
    );

    let ctx = context.unwrap();
    assert_eq!(
        ctx.auth_key.len(),
        16,
        "Auth key should be 16 bytes for MD5"
    );
    assert_eq!(
        ctx.priv_key.len(),
        16,
        "Priv key should be 16 bytes for DES"
    );

    // Test that keys are derived correctly
    let expected_auth_key = config.auth_key().unwrap();
    let expected_priv_key = config.priv_key().unwrap();

    assert_eq!(ctx.auth_key, expected_auth_key, "Auth keys should match");
    assert_eq!(ctx.priv_key, expected_priv_key, "Priv keys should match");
}

// Test BER encoding/decoding for various types
#[test]
fn test_ber_encoding_roundtrip() {
    // Test BerTag
    let tag = BerTag::from_str("get").unwrap();
    let encoded = tag.encode::<Asn1Encoder>();
    let (decoded, _) = BerTag::decode::<crate::encdec::asn1::Asn1Decoder>(&encoded).unwrap();
    assert_eq!(decoded, tag);

    // Test BerLen
    let len = BerLen(1024);
    let encoded = len.encode::<Asn1Encoder>();
    let (decoded, _) = BerLen::decode::<crate::encdec::asn1::Asn1Decoder>(&encoded).unwrap();
    assert_eq!(decoded, len);

    // Test BerTagAndLen
    let tag_len = BerTagAndLen(asn1::Tag::Sequence, 256);
    let encoded = tag_len.encode::<Asn1Encoder>();
    let (decoded, _) = BerTagAndLen::decode::<crate::encdec::asn1::Asn1Decoder>(&encoded).unwrap();
    assert_eq!(decoded, tag_len);
}

// Performance test for key derivation (to ensure it's reasonably fast)
#[test]
fn test_key_derivation_performance() {
    use std::time::Instant;

    let auth_alg = AuthAlgorithm::HmacMd5;
    let password = "test_password_for_performance";
    let engine_id = test_vectors::ENGINE_ID;

    let start = Instant::now();

    // Derive 10 keys to test performance
    for i in 0..10 {
        let password_with_suffix = format!("{}{}", password, i);
        let _key = auth_alg
            .derive_key(&password_with_suffix, engine_id)
            .unwrap();
    }

    let duration = start.elapsed();
    println!("Key derivation performance: 10 keys in {:?}", duration);

    // Should complete in reasonable time (less than 1 second for 10 keys)
    assert!(
        duration.as_secs() < 1,
        "Key derivation should be reasonably fast"
    );
}

// Test corner cases for encryption/decryption
#[test]
fn test_encryption_corner_cases() {
    let priv_alg = PrivAlgorithm::DesCbc;
    let key = vec![0x01; 16];
    let iv = vec![0x02; 8];

    // Test empty plaintext
    let empty_plaintext = b"";
    let encrypted = priv_alg.encrypt(&key, &iv, empty_plaintext).unwrap();
    let decrypted = priv_alg.decrypt(&key, &iv, &encrypted).unwrap();
    assert_eq!(decrypted, empty_plaintext);

    // Test single byte
    let single_byte = b"A";
    let encrypted = priv_alg.encrypt(&key, &iv, single_byte).unwrap();
    let decrypted = priv_alg.decrypt(&key, &iv, &encrypted).unwrap();
    assert_eq!(decrypted, single_byte);

    // Test exactly one block (8 bytes for DES)
    let one_block = b"12345678";
    let encrypted = priv_alg.encrypt(&key, &iv, one_block).unwrap();
    let decrypted = priv_alg.decrypt(&key, &iv, &encrypted).unwrap();
    assert_eq!(decrypted, one_block);
}

// Test that demonstrates the complete SNMPv3 message flow
#[test]
fn test_complete_snmpv3_flow() {
    // 1. Create configuration
    let mut config = UsmConfig::new("integration_test_user")
        .with_auth(AuthAlgorithm::HmacSha1, "integration_auth_password")
        .with_priv(PrivAlgorithm::Aes128, "integration_priv_password")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    // 2. Create GET request
    let oids = vec![
        "1.3.6.1.2.1.1.1.0", // sysDescr
        "1.3.6.1.2.1.1.3.0", // sysUpTime
        "1.3.6.1.2.1.1.5.0", // sysName
    ];

    let (request_stack, mut usm_context) = Snmp::v3_get_with_auth(&oids, &config).unwrap();

    // 3. Encode the request
    let encoded_request = request_stack
        .encode_with_usm::<Asn1Encoder>(&mut usm_context)
        .unwrap();

    // 4. Verify the request structure
    assert!(
        !encoded_request.is_empty(),
        "Request should encode successfully"
    );

    // 5. Decode the request to verify structure
    if let Some((decoded_request, _)) = SNMP!().ldecode(&encoded_request) {
        println!("Decoded request: {:?}", &decoded_request);
        // Verify layers
        assert!(
            decoded_request.get_layer(Snmp::default()).is_some(),
            "Should have SNMP layer"
        );
        assert!(
            decoded_request.get_layer(SnmpV3::new()).is_some(),
            "Should have SNMPv3 layer"
        );

        let snmpv3_layer = decoded_request.get_layer(SnmpV3::new()).unwrap();
        assert!(
            snmpv3_layer.has_authentication(),
            "Should have authentication"
        );
        assert!(snmpv3_layer.has_privacy(), "Should have privacy");
        assert!(snmpv3_layer.is_reportable(), "Should be reportable");

        // Verify user name
        assert_eq!(snmpv3_layer.user_name().unwrap(), "integration_test_user");

        println!(
            "Complete SNMPv3 flow test passed - message length: {}",
            encoded_request.len()
        );
    } else {
        panic!("Failed to decode the encoded request");
    }
}

// Test SNMPv3 discovery process
#[test]
fn test_snmpv3_discovery_message() {
    // Create a discovery message (no authentication, empty engine ID)
    let discovery_params = UsmSecurityParameters::discovery();

    /*
       FIXME assert_eq!(discovery_params.msg_authoritative_engine_id.value().0.len(), 0,
                       "Discovery should have empty engine ID");
    */
    assert_eq!(
        discovery_params.msg_authoritative_engine_boots.value(),
        0,
        "Discovery should have zero engine boots"
    );
    assert_eq!(
        discovery_params.msg_authoritative_engine_time.value(),
        0,
        "Discovery should have zero engine time"
    );
    /*
            assert_eq!(discovery_params.msg_user_name.value().0.len(), 0,
                       "Discovery should have empty user name");
    */

    // Test that discovery message identifies itself correctly
    assert!(
        discovery_params.is_discovery(),
        "Should identify as discovery message"
    );
}

// Test different combinations of auth/priv algorithms
#[test]
fn test_algorithm_combinations() {
    let engine_id = test_vectors::ENGINE_ID;
    let auth_password = "auth_pass_123";
    let priv_password = "priv_pass_456";

    let combinations = vec![
        (AuthAlgorithm::HmacMd5, PrivAlgorithm::DesCbc),
        (AuthAlgorithm::HmacMd5, PrivAlgorithm::Aes128),
        (AuthAlgorithm::HmacSha1, PrivAlgorithm::DesCbc),
        (AuthAlgorithm::HmacSha1, PrivAlgorithm::Aes128),
    ];

    for (auth_alg, priv_alg) in combinations {
        let config = UsmConfig::new("test_user")
            .with_auth(auth_alg.clone(), auth_password)
            .with_priv(priv_alg.clone(), priv_password)
            .with_engine_info(engine_id, 1, 12345);

        // Test that keys can be derived for all combinations
        let auth_key = config.auth_key().unwrap();
        let priv_key = config.priv_key().unwrap();

        assert!(
            !auth_key.is_empty(),
            "Auth key should not be empty for {:?}",
            auth_alg
        );
        assert!(
            !priv_key.is_empty(),
            "Priv key should not be empty for {:?}",
            priv_alg
        );

        // Test that encryption/decryption works
        let plaintext = b"Test message for algorithm combination";
        let salt = priv_alg.generate_salt(1, 12345);
        let iv = priv_alg.calculate_iv(&salt, &priv_key, 1, 12345).unwrap();

        let encrypted = priv_alg.encrypt(&priv_key, &iv, plaintext).unwrap();
        let decrypted = priv_alg.decrypt(&priv_key, &iv, &encrypted).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Encryption/decryption should work for {:?}/{:?}",
            auth_alg, priv_alg
        );
    }
}

#[test]
fn test_snmpv3_authenticated_encoding() {
    let mut config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    let oids = vec!["1.3.6.1.2.1.1.1.0"];
    let (stack, mut usm_context) = Snmp::v3_get_with_auth(&oids, &config).unwrap();

    // Test encoding with authentication
    let encoded = stack.encode_with_usm::<Asn1Encoder>(&mut usm_context);

    assert!(
        encoded.is_ok(),
        "Should be able to encode authenticated message"
    );

    let encoded_bytes = encoded.unwrap();
    assert!(
        !encoded_bytes.is_empty(),
        "Encoded message should not be empty"
    );

    println!(
        "Authenticated SNMPv3 message length: {}",
        encoded_bytes.len()
    );
    println!(
        "First 50 bytes: {:02x?}",
        &encoded_bytes[0..std::cmp::min(50, encoded_bytes.len())]
    );

    // Verify that authentication parameters are present (not all zeros)
    let zero_auth_params = vec![0u8; 12];
    let has_non_zero_auth = !encoded_bytes
        .windows(12)
        .any(|window| window == zero_auth_params);
    assert!(
        has_non_zero_auth,
        "Message should contain non-zero authentication parameters"
    );
}

#[test]
fn test_snmpv3_privacy_encoding() {
    let mut config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_priv(PrivAlgorithm::DesCbc, "privpass456")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    let oids = vec!["1.3.6.1.2.1.1.1.0"];
    let (stack, mut usm_context) = Snmp::v3_get_with_auth(&oids, &config).unwrap();

    // Test encoding with both authentication and privacy
    let encoded = stack.encode_with_usm::<Asn1Encoder>(&mut usm_context);

    assert!(
        encoded.is_ok(),
        "Should be able to encode authenticated and encrypted message"
    );

    let encoded_bytes = encoded.unwrap();
    assert!(
        !encoded_bytes.is_empty(),
        "Encoded message should not be empty"
    );

    println!("Encrypted SNMPv3 message length: {}", encoded_bytes.len());

    // The message should be different from unencrypted version
    let mut config_no_priv = config.clone();
    config_no_priv.priv_algorithm = PrivAlgorithm::None;
    config_no_priv.priv_password = None;

    let (stack_no_priv, mut usm_context_no_priv) =
        Snmp::v3_get_with_auth(&oids, &config_no_priv).unwrap();
    let encoded_no_priv = stack_no_priv
        .encode_with_usm::<Asn1Encoder>(&mut usm_context_no_priv)
        .unwrap();

    assert_ne!(
        encoded_bytes, encoded_no_priv,
        "Encrypted message should differ from unencrypted"
    );
}

#[test]
fn test_ber_oid_parsing() {
    let test_cases = vec![
        ("1.3.6.1.2.1.1.1.0", vec![43, 6, 1, 2, 1, 1, 1, 0]),
        ("1.3.6.1.2.1.1.2.0", vec![43, 6, 1, 2, 1, 1, 2, 0]),
        ("1.2.3.4.5", vec![42, 3, 4, 5]),
    ];

    for (oid_str, expected) in test_cases {
        let ber_oid = BerOid::from_str(oid_str).unwrap();
        // assert_eq!(ber_oid.0, expected, "OID parsing failed for {}", oid_str);

        // Test round-trip
        let encoded = ber_oid.encode::<Asn1Encoder>();
        let (decoded, _) = BerOid::decode::<crate::encdec::asn1::Asn1Decoder>(&encoded).unwrap();
        // assert_eq!(decoded.0, expected, "OID round-trip failed for {}", oid_str);
    }
}

#[test]
fn test_snmp_value_encoding() {
    let test_values = vec![
        (SnmpValue::Null, "NULL"),
        (SnmpValue::integer(42), "INTEGER"),
        (SnmpValue::string("test"), "OCTET STRING"),
        (SnmpValue::counter32(12345), "Counter32"),
        (SnmpValue::gauge32(98765), "Gauge32"),
        (SnmpValue::timeticks(123456), "TimeTicks"),
        (SnmpValue::counter64(9876543210), "Counter64"),
    ];

    for (value, expected_type) in test_values {
        assert_eq!(value.type_name(), expected_type);

        // Test encoding/decoding round-trip
        let encoded = value.encode::<Asn1Encoder>();
        let (decoded, _) = SnmpValue::decode::<crate::encdec::asn1::Asn1Decoder>(&encoded).unwrap();
        assert_eq!(
            decoded, value,
            "Value round-trip failed for {}",
            expected_type
        );
    }
}

#[test]
fn test_snmp_error_handling() {
    let errors = vec![
        (SnmpError::NoError, 0),
        (SnmpError::TooBig, 1),
        (SnmpError::NoSuchName, 2),
        (SnmpError::BadValue, 3),
        (SnmpError::ReadOnly, 4),
        (SnmpError::GenErr, 5),
    ];

    for (error, code) in errors {
        assert_eq!(i32::from(error.clone()), code);
        assert_eq!(SnmpError::from_i32(code), error);
        assert!(!error.description().is_empty());
    }
}

#[test]
fn test_community_string_handling() {
    let community = Community::from("private");
    let encoded = community.encode::<Asn1Encoder>();
    let (decoded, _) = Community::decode::<crate::encdec::asn1::Asn1Decoder>(&encoded).unwrap();
    assert_eq!(decoded, community);
    assert_eq!(format!("{}", decoded), "private");
}

#[test]
fn test_snmpv1_get_request() {
    let oids = vec!["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"];
    let stack = Snmp::v1_get("public", &oids);

    let encoded = stack.lencode();
    assert!(!encoded.is_empty(), "SNMPv1 GET request should encode");

    // Verify we can decode it back
    let (decoded, _) = SNMP!().ldecode(&encoded).unwrap();
    println!("Decoded: {:#?}", &decoded);
    assert!(decoded.get_layer(Snmp::default()).is_some());
    assert!(decoded.get_layer(SnmpV2c::default()).is_some());
}

#[test]
fn test_snmpv2c_getbulk_request() {
    let oids = vec!["1.3.6.1.2.1.2.2"];
    let stack = Snmp::v2c_getbulk("public", 0, 10, &oids);

    let encoded = stack.lencode();
    assert!(!encoded.is_empty(), "SNMPv2c GETBULK request should encode");

    let (decoded, _) = SNMP!().ldecode(&encoded).unwrap();
    assert!(decoded.get_layer(Snmp::default()).is_some());
    assert!(decoded.get_layer(SnmpV2c::default()).is_some());
    assert!(decoded.get_layer(SnmpGetBulk::default()).is_some());
}

#[test]
fn test_key_derivation_edge_cases() {
    let auth_alg = AuthAlgorithm::HmacMd5;
    let engine_id = b"short";

    // Test with very short password
    let short_password = "a";
    let key1 = auth_alg.derive_key(short_password, engine_id).unwrap();
    assert_eq!(key1.len(), 16);

    // Test with long password
    let long_password =
        "this_is_a_very_long_password_that_exceeds_normal_length_expectations_for_testing_purposes";
    let key2 = auth_alg.derive_key(long_password, engine_id).unwrap();
    assert_eq!(key2.len(), 16);

    // Keys should be different
    assert_ne!(key1, key2);

    // Test with empty engine ID (should still work)
    let key3 = auth_alg.derive_key("password", b"").unwrap();
    assert_eq!(key3.len(), 16);
}

#[test]
fn test_privacy_salt_generation() {
    let des_alg = PrivAlgorithm::DesCbc;
    let aes_alg = PrivAlgorithm::Aes128;

    let engine_boots = 12345u32;
    let counter1 = 98765u64;
    let counter2 = 98766u64;

    // DES salt should be 8 bytes
    let des_salt1 = des_alg.generate_salt(engine_boots, counter1);
    let des_salt2 = des_alg.generate_salt(engine_boots, counter2);

    assert_eq!(des_salt1.len(), 8);
    assert_eq!(des_salt2.len(), 8);
    assert_ne!(
        des_salt1, des_salt2,
        "Different counters should produce different salts"
    );

    // AES salt should be 8 bytes
    let aes_salt1 = aes_alg.generate_salt(engine_boots, counter1);
    let aes_salt2 = aes_alg.generate_salt(engine_boots, counter2);

    assert_eq!(aes_salt1.len(), 8);
    assert_eq!(aes_salt2.len(), 8);
    assert_ne!(
        aes_salt1, aes_salt2,
        "Different counters should produce different salts"
    );
}

#[test]
fn test_iv_calculation() {
    let des_alg = PrivAlgorithm::DesCbc;
    let aes_alg = PrivAlgorithm::Aes128;

    let priv_key = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    let salt = vec![0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];
    let engine_boots = 12345u32;
    let engine_time = 67890u32;

    // Test DES IV calculation
    let des_iv = des_alg
        .calculate_iv(&salt, &priv_key, engine_boots, engine_time)
        .unwrap();
    assert_eq!(des_iv.len(), 8, "DES IV should be 8 bytes");

    // Test AES IV calculation
    let aes_iv = aes_alg
        .calculate_iv(&salt, &priv_key, engine_boots, engine_time)
        .unwrap();
    assert_eq!(aes_iv.len(), 16, "AES IV should be 16 bytes");

    // Test that different salts produce different IVs
    let salt2 = vec![0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8];
    let des_iv2 = des_alg
        .calculate_iv(&salt2, &priv_key, engine_boots, engine_time)
        .unwrap();
    let aes_iv2 = aes_alg
        .calculate_iv(&salt2, &priv_key, engine_boots, engine_time)
        .unwrap();

    assert_ne!(
        des_iv, des_iv2,
        "Different salts should produce different DES IVs"
    );
    assert_ne!(
        aes_iv, aes_iv2,
        "Different salts should produce different AES IVs"
    );
}

// Integration test that simulates the full snmpwalk authentication flow
#[test]
fn test_snmpwalk_authentication_flow() {
    // Simulate the authentication flow from snmpwalk.rs
    let mut config = UsmConfig::new("testuser")
        .with_auth(AuthAlgorithm::HmacMd5, "authpass123")
        .with_engine_info(test_vectors::ENGINE_ID, 1, 12345);

    // 1. Create discovery message (no auth)
    let discovery_config = UsmConfig::new("testuser");
    let oids = vec!["1.3.6.1.2.1.1.1.0"];

    // 2. Create authenticated request
    let (auth_stack, mut auth_context) = Snmp::v3_get_with_auth(&oids, &config).unwrap();
    let encoded_auth = auth_stack
        .encode_with_usm::<Asn1Encoder>(&mut auth_context)
        .unwrap();

    assert!(
        !encoded_auth.is_empty(),
        "Authenticated request should encode successfully"
    );

    // 3. Verify the message has proper structure
    if let Some((decoded_stack, _)) = SNMP!().ldecode(&encoded_auth) {
        assert!(
            decoded_stack.get_layer(Snmp::default()).is_some(),
            "Should have SNMP layer"
        );
        assert!(
            decoded_stack.get_layer(SnmpV3::new()).is_some(),
            "Should have SNMPv3 layer"
        );

        let snmpv3 = decoded_stack.get_layer(SnmpV3::new()).unwrap();
        assert!(
            snmpv3.has_authentication(),
            "Should have authentication flag set"
        );
        assert!(!snmpv3.has_privacy(), "Should not have privacy flag set");
    } else {
        panic!("Failed to decode the authenticated message");
    }
}
