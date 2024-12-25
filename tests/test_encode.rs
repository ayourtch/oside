use oside::Value::Random;
use oside::*;
#[macro_use]
extern crate oside_derive;
use oside::protocols::all::*;
use serde::{Deserialize, Serialize};

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct testProto {
    #[nproto(default = 4, encode = Skip)]
    pub version: Value<u8>,
    pub tos: Value<u8>,
    pub mac1: Value<MacAddr>,
    #[nproto(default = Random)]
    pub mac2: Value<MacAddr>,
    #[nproto(default = "00:01:02:03:04:05")]
    pub mac3: Value<MacAddr>,
    #[nproto(default = Random)]
    pub id: Value<u16>,
}

#[test]
fn test_multiple_layer_instances() {
    let x = Ether!() / IP!() / UDP!(dport = 1111) / UDP!(dport = 2222);
    let udp = &x[UDP!()];
    // We always return the *first* occurrence
    assert_eq!(udp.dport.value(), 1111);
}

#[test]
fn test_multiple_layer_instances_innermost() {
    let x = Ether!() / IP!() / UDP!(dport = 1111) / UDP!(dport = 2222);
    if let Some(udp) = x.get_innermost_layer(UDP!()) {
        assert_eq!(udp.dport.value(), 2222);
    }
}

#[test]
fn encode_arp() {
    let x = Ether!(src = "02:02:02:02:02:02")
        / ARP!(
            psrc = "1.1.1.1",
            pdst = "2.2.2.2",
            hwdst = "ff:ff:ff:ff:ff:ff"
        );
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    assert_eq!(filled[Ether!()].etype, Value::Set(0x0806));
    let encoded = filled.clone().lencode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
}

#[test]
fn make_random_encode() {
    let x = Ether!(src = "02:02:02:02:02:02")
        / IP!(src = "10.10.10.10", dst = "11.11.11.11", id = 42, tos = 33)
        / UDP!();
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    assert_eq!(filled[IP!()].proto, Value::Set(17));
    let encoded = filled.clone().lencode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    assert_eq!(encoded[12], 0x08);
    assert_eq!(encoded[13], 0x00);
}

#[test]
fn make_tcp_checksum_tiny() {
    let x = IP!(id = 1) / TCP!(sport = 20, dport = 80);
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    let encoded = filled.clone().lencode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    // IP checksum
    assert_eq!(encoded[10], 0x7c);
    assert_eq!(encoded[11], 0xcd);
    // TCP checksum
    assert_eq!(encoded[36], 0x91);
    assert_eq!(encoded[37], 0x7c);
}

#[test]
fn make_udp_checksum_tiny() {
    let x = IP!(id = 1) / UDP!(sport = 53, dport = 53);
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    let encoded = filled.clone().lencode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    // IP checksum
    assert_eq!(encoded[10], 0x7c);
    assert_eq!(encoded[11], 0xce);
    // UDP checksum
    assert_eq!(encoded[26], 0x01);
    assert_eq!(encoded[27], 0x72);
}

#[test]
fn make_udp_checksum_payload() {
    let x = IP!(id = 1) / UDP!(sport = 1234, dport = 1234) / "xxx".to_string();
    eprintln!("Initial: {:02x?}", &x);
    let filled = x.fill();
    let encoded = filled.clone().lencode();
    eprintln!("Filled: {:02x?}", &filled);
    eprintln!("Encoded: {:02x?}", &encoded);
    // IP checksum
    assert_eq!(encoded[10], 0x7c);
    assert_eq!(encoded[11], 0xcb);
    // UDP checksum
    assert_eq!(encoded[26], 0x07);
    assert_eq!(encoded[27], 0xb9);
}

#[test]
fn make_geneve() {
    use oside::protocols::geneve::Geneve;
    let x = Ether!()
        / IP!(src = "192.168.1.1", dst = "192.168.2.2")
        / UDP!()
        / GENEVE!(vni = 0x223344)
        / Ether!()
        / IP!(src = "192.0.2.1", dst = "192.0.2.2")
        / UDP!(dport = 234)
        / "testing".to_string();
    eprintln!("Geneve: {:x?}", &x);
    let encoded = x.clone().lencode();
    eprintln!("Encoded Geneve: {:02x?}", &encoded);
    let z = Ether!().ldecode(&encoded).unwrap().0;
    println!("decode result: {:?}", &z);
}
