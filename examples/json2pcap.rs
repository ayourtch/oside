use oside::protocols::pcap_file::*;
use oside::*;

fn main() {
    let fname = std::env::args().nth(1).unwrap();
    let pcap_fname = std::env::args().nth(2).unwrap();
    let json_str = std::fs::read_to_string(&fname).unwrap();

    let pkts: Vec<Vec<Box<dyn oside::Layer>>> = serde_json::from_str(&json_str).unwrap();

    let mut pcap = PcapFile!();
    for p in pkts {
        let p = LayerStack {
            filled: true,
            layers: p,
        };
        let pp = PcapPacket!(data = p.lencode());
        pcap.push(pp);
    }

    pcap.write(&pcap_fname).unwrap();
}
