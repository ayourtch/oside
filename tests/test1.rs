use oside::Value::Random;
use oside::*;
#[macro_use]
extern crate oside_derive;
use serde::{Deserialize, Serialize};
use serde_json;

use oside::protocols::all::*;

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
fn serialize_1() {
    let tp = Ether!() / IP!(src = "192.0.2.1") / UDP!() / TestProto!();
    let j = serde_json::to_string(&tp).unwrap();
    eprintln!("JSON: {}", j);
    let p: LayerStack = serde_json::from_str(&j).unwrap();
    eprintln!("deserialized: {:?}", &p);
    assert_eq!(tp.layers.len(), p.layers.len());
}

#[test]
fn it_works() {
    use oside::*;
    let ip = Ip {
        ..Default::default()
    };
    eprintln!("{:?}", ip);
    assert_eq!(2 + 2, 4);
}

#[test]
fn test_inet_csum1() {
    let dat = b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7";
    let sum = get_inet_sum(dat);
    assert_eq!(sum, 0x2ddf0);
    let folded_sum = fold_u32(sum);
    assert_eq!(folded_sum, 8717);
}

#[test]
fn make_random() {
    let x = Ether!().set_src(Random) / IP!().set_src(Random);
    let filled = x.fill();
    eprintln!("Filled: {:?}", &filled);
}

#[test]
fn show_type_id() {
    let x = Ether!() / IP!() / UDP!();
    let eth = &x[Ether!()];
    let ip = &x[IP!()];
    let udp = &x[UDP!()];

    let eth_type = TypeId::of::<ether>();
    let ip_type = TypeId::of::<Ip>();
    let udp_type = TypeId::of::<Udp>();

    eprintln!("eth type id: {:?}", eth.get_layer_type_id());
    eprintln!(
        "eth type id by index: {:?}",
        &x.layers[0].get_layer_type_id()
    );
    eprintln!("ip type id: {:?}", ip.get_layer_type_id());
    eprintln!(
        "ip type id by index: {:?}",
        &x.layers[1].get_layer_type_id()
    );
    eprintln!("udp type id: {:?}", udp.get_layer_type_id());
    eprintln!(
        "udp type id by index: {:?}",
        &x.layers[2].get_layer_type_id()
    );
    assert_eq!(eth.get_layer_type_id(), eth_type);
    assert_eq!(x.layers[0].get_layer_type_id(), eth_type);
    assert_eq!(ip.get_layer_type_id(), ip_type);
    assert_eq!(x.layers[1].get_layer_type_id(), ip_type);
    assert_eq!(udp.get_layer_type_id(), udp_type);
    assert_eq!(x.layers[2].get_layer_type_id(), udp_type);
}

#[test]
fn custom_proto() {
    use oside::*;
    let px = TestProto!().tos(2);
    println!("created: {:?}", &px);
    assert_eq!(px.version, Value::Set(4));
    assert_eq!(px.tos, Value::Set(2));
    assert_eq!(px.mac2, Value::Random);
    assert_eq!(px.mac3, "00:01:02:03:04:05".into());
    let fx = px.clone().to_stack().fill();
    println!("filled: {:?}", &fx);
    assert_ne!(fx[TestProto!()].mac2, Value::Random);
    let bytes = fx.lencode();
    println!("bytes: {:?}", &bytes);
    assert_eq!(bytes[0], 2); // tos
}
