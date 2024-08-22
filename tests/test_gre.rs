use oside::*;

use oside::protocols::all::*;

#[test]
fn decode_gre_first_test() {
    let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100088be7e088837100100010000000054b20307eeed6cab051f0c74080045000029250e000039116cb059bb82400a000a0b2703e1f60015fab0ee1c108eee4ece4a36cd840096";
    let packet_bytes = &hex::decode(packet).unwrap();
    let x = Ether!().decode(&packet_bytes);
    println!("decode result: {:02x?}", &x);
    assert_eq!(x.is_some(), true);
    let (x, len) = x.unwrap();
    let gre = x.get_layer(GRE!());
    assert_eq!(gre.is_some(), true);
    let gre = gre.unwrap();
    assert_eq!(gre.version, Value::Set(0));
    assert_eq!(gre.seqnum_present, Value::Set(true));
    assert_eq!(gre.sequence_number, Value::Set(2114488375));
}

#[test]
fn encode_erspan_version() {
    let x1 = Ether!() / IP!() / GRE!() / Erspan!(version = ErspanType::Type2);
    let x2 = Ether!() / IP!() / GRE!() / Erspan!(version = 1);

    println!("x1 result: {:02x?}", &x1);
    println!("x2 result: {:02x?}", &x2);
    assert_eq!(x1[Erspan!()].version, x2[Erspan!()].version);
}
