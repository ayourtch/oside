use oside::Value::Random;
use oside::*;
#[macro_use]
extern crate oside_derive;

use oside::protocols::all::*;

extern crate pcap_parser;
use std::fs::File;
use std::path::PathBuf;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::LegacyPcapReader;
use pcap_parser::*;
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

fn get_pcap_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from(file!());
    path.pop();
    path.pop();
    path.push("pcap");
    path.push(name);
    path
}
pub fn read_pcap(pcapname: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![];
    let path = get_pcap_path(pcapname);
    let file = File::open(path).expect(&format!("File open failed for {}", &pcapname));
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    let mut num_blocks = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;

                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(b) => {
                        out.push(b.data.to_vec());
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    out
}

pub fn decode_pcap(pcapname: &str) -> Vec<LayerStack> {
    let d = read_pcap(pcapname);
    d.into_iter()
        .map(|x| Ether!().decode(&x).unwrap().0)
        .collect()
}

pub fn decode_encode_pcap(name: &str) {
    let packets = read_pcap(name);
    for d in packets {
        println!("data: {:?}", &d);
        let pkt = Ether!().decode(&d).unwrap().0;
        println!("pkt: {:?}", &pkt);
        let pkt_filled = pkt.fill();
        println!("pkt_filled: {:?}", &pkt_filled);
        let pkt_encoded = pkt_filled.encode();
        println!("pkt_encoded: {:?}", &pkt_encoded);
        assert_eq!(d.len(), pkt_encoded.len());
        for i in 0..d.len() {
            assert_eq!((i, d[i]), (i, pkt_encoded[i]));
        }
    }
}

#[test]
pub fn test_decode_encode_pcaps() {
    decode_encode_pcap("pcap1.pcap");
    decode_encode_pcap("pcap2.pcap");
    decode_encode_pcap("pcap3.pcap");
}

#[test]
pub fn test_pcap1() {
    let packets = decode_pcap("pcap1.pcap");
    for p in packets {
        println!("p: {:?}", &p);
        let bytes = p.encode();
        println!("bytes: {:?}", &bytes);
    }
}

#[test]
pub fn test_pcap2_plain() {
    let packets = decode_pcap("pcap2.pcap");
    for p in packets {
        println!("p: {:?}", &p);
    }
}

#[test]
pub fn test_pcap3_nomod() {
    let packets = read_pcap("pcap3.pcap");
    for d in packets {
        println!("p: {:?}", &d);
        let p = Ether!().decode(&d).unwrap().0;
        println!("p: {:?}", &p);
        let mut pn = p.clone();
        if let Some(t) = pn.get_layer_mut(TCP!()) {
            //    t.modify_chksum(Value::Auto);
        }
        println!("pn_start: {:?}", &pn);
        let pn_filled = pn.fill();
        println!("pn_filled: {:?}", &pn_filled);
        let pn_encoded = pn_filled.encode();
        println!("pn_encoded: {:?}", &pn_encoded);

        assert_eq!(d.len(), pn_encoded.len());
        for i in 0..d.len() {
            assert_eq!((i, d[i]), (i, pn_encoded[i]));
        }
    }
}

#[test]
pub fn test_pcap3_csum() {
    let packets = read_pcap("pcap3.pcap");
    for d in packets {
        println!("p: {:02x?}", &d);
        let p = Ether!().decode(&d).unwrap().0;
        println!("p: {:02x?}", &p);
        let mut pn = p.clone();
        if let Some(t) = pn.get_layer_mut(TCP!()) {
            t.modify_chksum(Value::Auto);
        }
        println!("pn_start: {:?}", &pn);
        let pn_filled = pn.fill();
        println!("pn_filled: {:?}", &pn_filled);
        let pn_encoded = pn_filled.encode();
        println!("pn_encoded: {:?}", &pn_encoded);

        assert_eq!(d.len(), pn_encoded.len());
        for i in 0..d.len() {
            assert_eq!((i, d[i]), (i, pn_encoded[i]));
        }
    }
}

#[test]
pub fn test_pcap_vxlan1() {
    use oside::protocols::vxlan::Vxlan;

    let packets = read_pcap("vxlan1.pcap");
    for d in packets {
        println!("p: {:02x?}", &d);
        let p = Ether!().decode(&d).unwrap().0;
        println!("p_decoded: {:02x?}", &p);
        assert_eq!(p[VXLAN!()].vni, Value::Set(0x010203));
        let mut pn = p.clone();
    }
}

#[test]
pub fn test_pcap_vxlan2() {
    use oside::protocols::vxlan::Vxlan;

    let packets = read_pcap("vxlan2.pcap");
    for d in packets {
        println!("p: {:02x?}", &d);
        let p = Ether!().decode(&d).unwrap().0;
        println!("P_DECODED: {:02x?}", &p);
        assert_eq!(p[VXLAN!()].vni, Value::Set(0x010203));
        let mut pn = p.clone();
    }
}

#[test]
pub fn test_pcap_dhcp() {
    use oside::protocols::bootp::Bootp;

    let packets = read_pcap("dhcp.pcap");
    for d in packets {
        // println!("p: {:02x?}", &d);
        let p = Ether!().decode(&d).unwrap().0;
        println!("p_decoded: {:02x?}", &p);
    }
}
