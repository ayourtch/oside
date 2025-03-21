use oside::*;
use std::any::TypeId;

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

    let ipv6_test = Ether!(src = "00:01:02:03:04:05")
        / IPV6!(
            src = "2001:db8:1::1",
            dst = "2001:db8:2::2",
            payload_length = 3
        )
        / UDP!()
        / Raw!("testing1235".into());

    {
        use oside::WritePcap;

        let mut packets = vec![];
        let mut ipv6_clone = ipv6_test.clone();
        packets.push(ipv6_test);

        if let Some((idx, ip6)) = ipv6_clone.find_layer(IPV6!()) {
            ipv6_clone.layers[idx] = IP!(src = "192.0.2.22", dst = "192.0.2.23").embox();
        }
        packets.push(ipv6_clone);
        packets.write_pcap("ipv6.pcap");
    }

    let ipv4_test =
        Ether!(src = "00:01:02:03:04:05") / IP!(src = "192.0.2.1", dst = "192.0.2.1") / UDP!();

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
    let my_src_ip = layers[IP!()].src.clone();

    let data: Vec<u8> = layers.fill().lencode();

    println!("Data: {:02x?}", &data);
}
