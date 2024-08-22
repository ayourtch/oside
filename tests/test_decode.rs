use oside::*;

use oside::protocols::all::*;

#[test]
fn decode_test_1() {
    use oside::*;

    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x00\x4523456789\x111234567890123456789012a".as_bytes())
        .unwrap()
        .0;
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(IP!()), vec![1]);
    assert_eq!(x.indices_of(UDP!()), vec![2]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x800));

    eprintln!("{:?}", &x);
}

#[test]
fn decode_test_icmp() {
    use oside::*;

    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x00\x4523456789\x011234567890123456789012a".as_bytes())
        .unwrap()
        .0;
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(IP!()), vec![1]);
    assert_eq!(x.indices_of(ICMP!()), vec![2]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x800));

    eprintln!("{:?}", &x);
}

#[test]
fn decode_test_raw() {
    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x0112345678901234567890123456789012a".as_bytes())
        .unwrap()
        .0;
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(IP!()), vec![]);
    assert_eq!(x.indices_of(Raw!()), vec![1]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x801));

    eprintln!("{:?}", &x);
}

#[test]
fn decode_arp_canonical() {
    let bytes: Vec<u8> = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0xa0, 0x00, 0xa0, 0xb0, 0x0c, 0x01, 0x01,
        0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x02, 0x02, 0x02,
    ];
    let x = Ether!().decode(&bytes).unwrap().0;
    println!("decode result: {:?}", &x);
    let arp = &x[ARP!()];
    assert_eq!(arp.hwsrc, "00:A0:00:A0:B0:0C".into());
    assert_eq!(arp.psrc, "1.1.1.1".into());
    assert_eq!(arp.hwdst, "FF:FF:FF:FF:FF:FF".into());
    assert_eq!(arp.pdst, "2.2.2.2".into());
}

#[test]
fn decode_arp_strange() {
    let bytes: Vec<u8> = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x04, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
        0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0x02, 0x02, 0x02,
    ];
    let x = Ether!().decode(&bytes).unwrap().0;
    println!("decode result: {:?}", &x);
    let arp = &x[ARP!()];
    assert_eq!(
        arp.hwsrc,
        Value::Set(ArpHardwareAddress::Bytes(vec![0, 0, 0, 0]))
    );
    assert_eq!(
        arp.psrc,
        Value::Set(ArpProtocolAddress::Bytes(vec![0, 0, 1, 1, 1, 1]))
    );
    assert_eq!(
        arp.hwdst,
        Value::Set(ArpHardwareAddress::Bytes(vec![255, 255, 255, 255]))
    );
    assert_eq!(
        arp.pdst,
        Value::Set(ArpProtocolAddress::Bytes(vec![255, 255, 2, 2, 2, 2]))
    );
}

#[test]
fn decode_test_dot1q() {
    use oside::*;

    let x = Ether!()
        .decode(b"AAAAAABBBBBB\x81\x00\x02\x21\x08\x00\x4523456789\x111234567890123456789012a")
        .unwrap()
        .0;
    println!("decode result: {:?}", &x);
    assert_eq!(x.indices_of(Ether!()), vec![0]);
    assert_eq!(x.indices_of(Dot1Q!()), vec![1]);
    assert_eq!(x.indices_of(IP!()), vec![2]);
    assert_eq!(x.indices_of(UDP!()), vec![3]);
    let eth = &x[Ether!()];
    assert_eq!(eth.dst, "41:41:41:41:41:41".into());
    assert_eq!(eth.src, "42:42:42:42:42:42".into());
    assert_eq!(eth.etype, Value::Set(0x8100));
    let dot1q = &x[Dot1Q!()];
    assert_eq!(dot1q.vlan, Value::Set(545));

    eprintln!("{:?}", &x);
}
