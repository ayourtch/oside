use crate::encdec::binary_little_endian::BinaryLittleEndian;
use crate::*;
use serde::{Deserialize, Serialize};

/*
 * This is a toy pcap encoder/decoder
 */

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct pcapFile {
    #[nproto(default = 0xd4c3b2a1)]
    pub magic_number: Value<u32>, // magic number  0xa1b2c3d4: no swap required, 0xd4c3b2a1: swapped
    #[nproto(encode = encode_data, decode = decode_data)]
    pub d: pcapFileData,
}

/* a few convenience methods */

impl pcapFile {
    pub fn push(&mut self, pkt: pcapPacket) {
        self.d.packets.push(pkt);
    }

    pub fn write(&self, fname: &str) -> Result<(), std::io::Error> {
        std::fs::write(fname, self.clone().to_stack().encode())
    }
}
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct pcapFileData {
    #[nproto(default = 2)]
    pub version_major: Value<u16>, // major version number
    #[nproto(default = 4)]
    pub version_minor: Value<u16>, // minor version number
    #[nproto(default = 0)]
    pub thiszone: Value<i32>, // GMT to local correction
    #[nproto(default = 0)]
    pub sigfigs: Value<u32>, // accuracy of timestamps
    #[nproto(fill = fill_snaplen)]
    pub snaplen: Value<u32>, // max length of captured packets, in octets
    #[nproto(default = 1)]
    pub network: Value<u32>, // data link type
    #[nproto(encode = encode_packets, decode = decode_packets)]
    pub packets: Vec<pcapPacket>, // encoded packets
}

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(non_greedy_decode)]
pub struct pcapPacket {
    pub ts_sec: Value<u32>,  /* timestamp seconds */
    pub ts_usec: Value<u32>, /* timestamp microseconds */
    #[nproto(fill = fill_len_auto)]
    pub incl_len: Value<u32>, /* number of octets of packet saved in file */
    #[nproto(fill = fill_len_auto)]
    pub orig_len: Value<u32>, /* actual length of packet */
    #[nproto(decode = decode_packet_data, set = set_packet_data )]
    pub data: Vec<u8>, /* incl_len bytes worth of data */
}

fn encode_data<E: Encoder>(
    me: &pcapFile,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    me.d.encode_with_encoder::<BinaryLittleEndian>(stack, my_index, encoded_layers)
}

fn decode_data<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut pcapFile,
) -> Option<(pcapFileData, usize)> {
    let buf = &buf[ci..];

    let mut vp: Vec<pcapPacket> = vec![];
    let mut ci = 0;

    let dec = match me.magic_number.value() {
        0xa1b2c3d4 => PcapFileData!().decode_with_decoder::<BinaryBigEndian>(buf),
        0xd4c3b2a1 => PcapFileData!().decode_with_decoder::<BinaryLittleEndian>(buf),
        x => {
            panic!("Architecture {:02x?} not supported", x);
        }
    };
    dec.map(|(lyr, delta)| (lyr.layers_of(PcapFileData!())[0].clone(), delta))
}

fn encode_packets<E: Encoder>(
    me: &pcapFileData,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for p in &me.packets {
        let po = p.encode_with_encoder::<E>(stack, my_index, encoded_layers);
        out.extend_from_slice(&po);
    }
    out
}

fn decode_packets<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut pcapFileData,
) -> Option<(Vec<pcapPacket>, usize)> {
    let buf = &buf[ci..];

    let mut vp: Vec<pcapPacket> = vec![];
    let mut ci = 0;
    while ci < buf.len() {
        if let Some((stk, delta)) = PcapPacket!().decode_with_decoder::<D>(&buf[ci..]) {
            let mut pkts = stk
                .layers_of(PcapPacket!())
                .into_iter()
                .map(|p| p.clone())
                .collect::<Vec<pcapPacket>>();
            vp.extend_from_slice(&pkts);
            ci += delta;
        } else {
            break;
        }
    }
    Some((vp, ci))
}

fn fill_snaplen(layer: &pcapFileData, stack: &LayerStack, my_index: usize) -> Value<u32> {
    use std::convert::TryInto;

    let mut snaplen = layer.snaplen.value();
    for p in &layer.packets {
        let u32_len: u32 = p.data.len().try_into().unwrap();
        if snaplen < u32_len {
            snaplen = u32_len;
        }
    }
    Value::Set(0)
}

fn decode_packet_data<D: Decoder>(
    buf: &[u8],
    ci: usize,
    me: &mut pcapPacket,
) -> Option<(Vec<u8>, usize)> {
    let buf = &buf[ci..];

    let plen = me.incl_len.value() as usize;
    D::decode_vec(buf, plen)
}

fn fill_len_auto(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> Value<u16> {
    Value::Auto
}

fn set_packet_data(mut me: pcapPacket, data: Vec<u8>) -> pcapPacket {
    use std::convert::TryInto;

    let u32_len: u32 = data.len().try_into().unwrap();
    if me.incl_len.is_auto() {
        me.incl_len = Value::Set(u32_len);
    }
    if me.orig_len.is_auto() {
        me.orig_len = Value::Set(u32_len);
    }
    me.data = data;
    me
}
