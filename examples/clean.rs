use oside::protocols::all::*;
use oside::*;
use std::convert::TryFrom;

fn get_dst() -> MacAddr {
    MacAddr::from("22:22:22:22:22:22")
}

fn main() {
    let layers = Ether!(src = "00:01:02:03:04:05").dst(Value::Func(get_dst))
        / ARP!(hwsrc = "00:02:03:04:05:06")
        / IP!(src = "192.0.2.1", dst = "2.2.2.2")
        / UDP!(sport = 1234).dport(22)
        / UDP!().dport(22).sport(222)
        / Raw!("Testing12345".into());

    println!("Layers ({}): {:#?}", layers.layers.len(), &layers);

    let udp = &layers[UDP!()];
    println!("UDP Sport: {}", udp.sport);

    println!("Set: {:?}", &layers);
    let filled = layers.fill();
    println!("Filled: {:?}", &filled);
    let bytes = filled.encode();
    println!("Encoded bytes: {:02x?}", &bytes);

    let ip = &IANA_LAYERS_BY_Proto[&4];
    println!("IP: {:?}", ip);
    let ll = (ip.MakeLayer)();

    let ll = LayerStack::gg::<Ip>(ll).src("1.1.1.1");
    println!("IP by name: {:?}", ll);
    let x = Ether!()
        .decode("AAAAAABBBBBB\x08\x0012345678901234567890123456789012a".as_bytes())
        .unwrap()
        .0;
    println!("x: {:?}", &x);
    println!("xb: {:?}", x.encode());
}
