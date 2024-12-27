use crate::*;
use serde::{Deserialize, Serialize};

#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(encoder(BinaryBigEndian))]
#[nproto(register(ETHERTYPE_LAYERS, Ethertype = 0x6558))]
pub struct ether {
    #[nproto(fill = fill_dmac, default = "01:02:03:04:05:06")]
    // #[nproto(default = "01:02:03:04:05:06")]
    // #[nproto(fill = fill_dmac)]
    // #[nproto(default = Random)]
    pub dst: Value<MacAddr>,
    #[nproto(fill = "00:00:00:00:00:00")]
    pub src: Value<MacAddr>,
    #[nproto(next: ETHERTYPE_LAYERS => Ethertype)]
    pub etype: Value<u16>,
    //#[nproto(fill = fill_crc)]
    // pub crc: Value<u32>,
}

fn fill_dmac(layer: &dyn Layer, stack: &LayerStack, my_index: usize) -> MacAddr {
    MacAddr::from("ff:ff:ff:ff:ff:ff")
}
