use crate::*;
use serde::{Deserialize, Serialize};

#[derive(
    FromStringHashmap, NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize,
)]
#[nproto(decode_suppress)]
pub struct raw {
    #[nproto(decode = Skip)]
    pub data: Vec<u8>,
}

#[typetag::serde]
impl Layer for String {
    fn embox(self) -> Box<dyn Layer> {
        Box::new(self)
    }
    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }
    fn fill(&self, stack: &LayerStack, my_index: usize, out_stack: &mut LayerStack) {
        out_stack.layers.push(Box::new(self.clone()))
    }
    fn lencode(
        &self,
        stack: &LayerStack,
        my_index: usize,
        encoded_layers: &EncodingVecVec,
    ) -> Vec<u8> {
        self.as_bytes().to_owned()
    }
}
