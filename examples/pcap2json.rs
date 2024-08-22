use oside::protocols::all::*;
use oside::protocols::pcap_file::*;
use oside::*;

use std::convert::TryFrom;

fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;
    let mut f = File::open(&filename).expect("no file found");
    let metadata = std::fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read(&mut buffer).expect("buffer overflow");

    buffer
}

fn main() {
    let fname = std::env::args().nth(1).unwrap();
    let bytes = get_file_as_byte_vec(&fname);
    // println!("Bytes: {:02x?}", &bytes);
    let binding = PcapFile!().decode(&bytes).unwrap();
    let pcap = binding.0.get_layer(PcapFile!()).unwrap();
    // println!("Pcap: {:#02x?}", &pcap.d);
    println!("[");
    let mut first = true;
    for p in &pcap.d.packets {
        if first {
            first = false;
        } else {
            println!(",");
        }
        // println!("data: {:02x?}", &p.data);
        let pkt = Ether!().decode(&p.data).unwrap().0;
        let j = serde_json::to_string(&pkt.layers).unwrap();
        println!("{}", j);
    }
    println!("]");
}
