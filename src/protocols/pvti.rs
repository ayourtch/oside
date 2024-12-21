use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PVTIChunk {
    pub total_chunk_length: Value<u16>,
    pub _pad0: Value<u16>,
    pub _pad1: Value<u32>,
    pub data: Vec<u8>,
}

impl Decode for PVTIChunk {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((mac_vec, count)) = D::decode_vec(buf, 6) {
            None
            // Some((MacAddr::from(&mac_vec[..]), count))
        } else {
            None
        }
    }
}
impl Encode for PVTIChunk {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        panic!("FIXME");
        self.data.to_vec()
    }
}

const PVTI_ALIGN_BYTES: u8 = 9;

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PVTI {
    pub seq: Value<u32>,
    pub stream_index: Value<u8>,
    pub chunk_count: Value<u8>,
    pub reass_chunk_count: Value<u8>,
    pub mandatory_flags_mask: Value<u8>,
    pub flags_value: Value<u8>,
    #[nproto(default = PVTI_ALIGN_BYTES)]
    pub pad_bytes: Value<u8>,
    #[nproto(decode = decode_pvti_pad, encode = encode_pvti_pad)]
    pub pad: Vec<u8>,
    #[nproto(decode = decode_pvti_chunks, encode = encode_pvti_chunks)]
    pub chunks: Vec<PVTIChunk>,
}

fn decode_pvti_pad<D: Decoder>(buf: &[u8], me: &mut PVTI) -> Option<(Vec<u8>, usize)> {
    let pad_length = me.pad_bytes.value() as usize;
    D::decode_vec(buf, pad_length)
}

fn encode_pvti_pad<E: Encoder>(
    my_layer: &PVTI,
    _stack: &LayerStack,
    _my_index: usize,
    _encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    vec![0xca; my_layer.pad_bytes.value() as usize]
}

fn decode_pvti_chunks<D: Decoder>(buf: &[u8], me: &mut PVTI) -> Option<(Vec<PVTIChunk>, usize)> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    let chunk_count = me.chunk_count.value() as usize;

    for _ in 0..chunk_count {
        if let Some((chunk, chunk_size)) = PVTIChunk::decode::<D>(&buf[offset..]) {
            chunks.push(chunk);
            offset += chunk_size;
        } else {
            return None;
        }
    }

    Some((chunks, offset))
}

fn encode_pvti_chunks<E: Encoder>(
    my_layer: &PVTI,
    stack: &LayerStack,
    my_index: usize,
    encoded_layers: &EncodingVecVec,
) -> Vec<u8> {
    let mut result = Vec::new();
    panic!("FIXME");
    for chunk in &my_layer.chunks {
        result.extend(chunk.encode::<E>());
    }
    result
}
