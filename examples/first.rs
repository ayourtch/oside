use oside::*;
use std::any::Any;
use std::any::TypeId;
use std::boxed::Box;
use std::convert::TryFrom;

use oside::protocols::all::*;

/*
macro_rules! IP {
    () => {{
        {
            let mut ip: Ip = Default::default();
            ip
        }
    }};

    ($ip:ident, $ident:ident=$e:expr) => {{
        {
            $ip.$ident = $e.into();
        }
    }};
    ($ip: ident, $ident:ident=$e:expr, $($x_ident:ident=$es:expr),+) => {{
        {
            IP!($ip, $ident=$e);
            IP!($ip, $($x_ident=$es),+);
        }
    }};

    ($ident:ident=$e:expr) => {{
        {
            let mut ip: Ip = Default::default();
            IP!(ip, $ident=$e);
            ip
        }
    }};
    ($ident:ident=$e:expr, $($s_ident:ident=$es:expr),+) => {{
        {
            let mut ip = IP!($ident=$e);
            IP!(ip, $($s_ident=$es),+);
            ip
        }
    }};
}

*/

use oside::protocols::all::IpOption::*;
use oside::FromStringHashmap;
use std::collections::HashMap;

fn main() {
    let ip = Ip::default();
    let udp = Udp::default();

    let mut ip = IP!(
        src = "1.1.1.1",
        dst = [2, 2, 2, 22],
        id = 12,
        ttl = 32,
        options = [NOP(), NOP(), NOP()]
    );

    let mut hip: HashMap<String, String> = HashMap::new();

    hip.insert("src".into(), "1.1.1.1".into());
    hip.insert("dst".into(), "1.2.3.4".into());
    hip.insert("chksum".into(), "1234".into());

    ip = Ip::from_string_hashmap(hip);
    println!("first ip {:#?}", &ip);

    let layers3 = IP!() / udp.clone();

    let layers = IP!(flags = "MF,DF,offset=32")
        .version(5)
        .id(22)
        .ihl(123)
        .src([1, 1, 1, 1])
        .dst("2.2.2.2")
        .options([NOP(), NOP(), SourceRoute(["1.1.1.1".into()].into())])
        / Udp::new()
        / Udp::new();
    let layers2 = layers.clone();

    let layers4 = UDP!() / IP!();

    println!("{:#?}", &layers);
    println!("{:#?}", &layers3);
    println!("{:#?}", &layers4);

    let ip_type = TypeId::of::<Ip>();
    let udp_type = TypeId::of::<Udp>();
    for node in &layers.layers {
        println!(
            "ip: {} udp: {}",
            node.type_id_is(ip_type),
            node.type_id_is(udp_type)
        );
    }

    let new_ip = &layers[ip_type];
    println!("IP: {:#?}, {}", &new_ip, new_ip.type_id_is(ip_type));
    let downcast = new_ip.downcast_ref::<Ip>().unwrap();
    println!("Downcast: {:#?}", &downcast.src);

    println!("Source: {:#?}", Ip::of(&layers).src);
    println!("UDP: {:#?}", Udp::of(&layers).sport);

    let my_udp = &layers[UDP!()];
    let mut my_src_ip = layers[IP!()].src.clone();

    let data: Vec<u8> = layers.fill().encode();

    println!("Data: {:02x?}", &data);
}
