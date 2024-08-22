use oside::Value::Random;
use oside::*;
#[macro_use]
extern crate oside_derive;

use oside::protocols::all::*;
use oside::protocols::pcap_file::*;

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

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn read_pcap_bytes(name: &str) -> Vec<u8> {
    let path = get_pcap_path(name);
    get_file_as_byte_vec(path.to_str().unwrap())
}

pub fn read_pcap(pcapname: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![];
    let path = get_pcap_path(pcapname);
    let file = File::open(path).expect("File open failed");
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

#[test]
pub fn test_read_pcap_bytes() {
    let bytes = read_pcap_bytes("pcap_3pkts.pcap");
    println!("Bytes: {:02x?}", &bytes);
    let pcap = PcapFile!().decode(&bytes).unwrap().0;
    println!("Pcap: {:#02x?}", &pcap);
}

#[test]
pub fn test_read_reencode_pcap_bytes() {
    let bytes = read_pcap_bytes("pcap_3pkts.pcap");
    let (pcap, len) = PcapFile!().decode(&bytes).unwrap();
    println!("Pcap ({}): {:#02x?}", len, &pcap);
    let pcap_out = pcap.encode();
    // std::fs::write("kaka-pcap.pcap", pcap_out.clone()).unwrap();

    println!("PcapOut: {:02x?}", &pcap_out);
    println!("Bytes  : {:02x?}", &bytes);
    assert_eq!(pcap_out.len(), bytes.len());

    for i in 0..bytes.len() {
        assert_eq!((i, pcap_out[i]), (i, bytes[i]));
    }
}

#[test]
pub fn test_write_pcap_from_scratch() {
    let mut pcap = PcapFile!();
    for i in 0..3 {
        let p = Ether!() / IP!() / GRE!() / IP!() / UDP!();
        let pp = PcapPacket!(data = p.encode());
        pcap.push(pp);
    }
    println!("PCAP: {:02x?}", &pcap);

    if std::env::var("WRITE_PCAP").is_ok() {
        pcap.write("gre-pcap.pcap").unwrap();
    }
}

#[test]
pub fn test_write_pcap_with_erspan() {
    /* not really much of a test, was just using it to write a hex into a pcap
     */
    let mut pcap = PcapFile!();
    let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100088be7e088837100100010000000054b20307eeed6cab051f0c74080045000029250e000039116cb059bb82400a000a0b2703e1f60015fab0ee1c108eee4ece4a36cd840096";
    let pkt_encode = hex::decode(packet).unwrap();
    pcap.push(PcapPacket!(data = pkt_encode));

    if std::env::var("WRITE_PCAP").is_ok() {
        pcap.write("erspan-pcap.pcap").unwrap();
    }
}
