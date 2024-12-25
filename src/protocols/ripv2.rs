use crate::*;
use serde::{Deserialize, Serialize};

// RIPv2 Command Types
#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RipCommand {
    Request = 1,
    Response = 2,
    Unknown(u8),
}

impl Default for RipCommand {
    fn default() -> Self {
        RipCommand::Request
    }
}

// Implement Distribution for RipCommand for random value generation
impl Distribution<RipCommand> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RipCommand {
        match rng.gen_range(1..=2) {
            1 => RipCommand::Request,
            2 => RipCommand::Response,
            x => RipCommand::Unknown(x),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseRipCommandError;

impl FromStr for RipCommand {
    type Err = ParseRipCommandError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "request" => Ok(RipCommand::Request),
            "response" => Ok(RipCommand::Response),
            x => {
                let res = s.parse();
                if res.is_err() {
                    return Err(ParseRipCommandError);
                }
                Ok(RipCommand::Unknown(res.unwrap()))
            }
        }
    }
}

impl Encode for RipCommand {
    fn encode<E: Encoder>(&self) -> Vec<u8> {
        match self {
            RipCommand::Request => E::encode_u8(1),
            RipCommand::Response => E::encode_u8(2),
            RipCommand::Unknown(val) => E::encode_u8(*val),
        }
    }
}

impl Decode for RipCommand {
    fn decode<D: Decoder>(buf: &[u8]) -> Option<(Self, usize)> {
        if let Some((val, size)) = D::decode_u8(buf) {
            let cmd = match val {
                1 => RipCommand::Request,
                2 => RipCommand::Response,
                x => RipCommand::Unknown(x),
            };
            Some((cmd, size))
        } else {
            None
        }
    }
}

// RIPv2 Address Family Identifiers
#[derive(FromRepr, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u16)]
pub enum RipAfi {
    Ip = 2, // IP (IP version 4)
}

impl Default for RipAfi {
    fn default() -> Self {
        RipAfi::Ip
    }
}

// Implement Distribution for RipAfi for random value generation
impl Distribution<RipAfi> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> RipAfi {
        RipAfi::Ip // Currently only IP is supported
    }
}

// RIPv2 Route Table Entry (RTE)
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RipEntry {
    #[nproto(default = 2)] // IP (IP version 4)
    pub address_family: Value<u16>,
    #[nproto(default = 0)]
    pub route_tag: Value<u16>,
    pub address: Value<Ipv4Address>,
    pub subnet_mask: Value<Ipv4Address>,
    pub next_hop: Value<Ipv4Address>,
    pub metric: Value<u32>,
}

impl AutoEncode for Vec<RipEntry> {}
impl AutoDecode for Vec<RipEntry> {}

// RIPv2 Packet
#[derive(NetworkProtocol, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[nproto(register(UDP_SRC_PORT_APPS, SrcPort = 520))]
#[nproto(register(UDP_DST_PORT_APPS, DstPort = 520))]
pub struct Rip {
    pub command: Value<RipCommand>,
    #[nproto(default = 2)] // Version 2
    pub version: Value<u8>,
    #[nproto(default = 0)] // Must be zero (reserved)
    pub zero: Value<u16>,
    pub entries: Vec<RipEntry>,
}

impl RipEntry {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Rip {
    pub fn new() -> Self {
        Default::default()
    }

    // Helper method to create a RIP request packet
    pub fn request() -> Self {
        Rip {
            command: Value::Set(RipCommand::Request),
            version: Value::Set(2),
            zero: Value::Set(0),
            entries: vec![],
        }
    }

    // Helper method to create a RIP response packet
    pub fn response() -> Self {
        Rip {
            command: Value::Set(RipCommand::Response),
            version: Value::Set(2),
            zero: Value::Set(0),
            entries: vec![],
        }
    }

    // Add a route entry to the RIP packet
    pub fn add_entry(&mut self, entry: RipEntry) {
        self.entries.push(entry);
    }
}

// Implementation of RIP entry builder for more ergonomic route creation
impl RipEntry {
    pub fn builder() -> RipEntryBuilder {
        RipEntryBuilder::new()
    }
}

pub struct RipEntryBuilder {
    entry: RipEntry,
}

impl RipEntryBuilder {
    pub fn new() -> Self {
        RipEntryBuilder {
            entry: RipEntry::new(),
        }
    }

    pub fn address_family(mut self, af: RipAfi) -> Self {
        self.entry.address_family = Value::Set(af as u16);
        self
    }

    pub fn route_tag(mut self, tag: u16) -> Self {
        self.entry.route_tag = Value::Set(tag);
        self
    }

    pub fn address<T: Into<Ipv4Address>>(mut self, addr: T) -> Self {
        self.entry.address = Value::Set(addr.into());
        self
    }

    pub fn subnet_mask<T: Into<Ipv4Address>>(mut self, mask: T) -> Self {
        self.entry.subnet_mask = Value::Set(mask.into());
        self
    }

    pub fn next_hop<T: Into<Ipv4Address>>(mut self, hop: T) -> Self {
        self.entry.next_hop = Value::Set(hop.into());
        self
    }

    pub fn metric(mut self, metric: u32) -> Self {
        self.entry.metric = Value::Set(metric);
        self
    }

    pub fn build(self) -> RipEntry {
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rip_request() {
        let rip = Rip::request();
        assert_eq!(rip.command, Value::Set(RipCommand::Request));
        assert_eq!(rip.version, Value::Set(2));
        assert_eq!(rip.zero, Value::Set(0));
        assert_eq!(rip.entries.len(), 0);
    }

    #[test]
    fn test_rip_response() {
        let rip = Rip::response();
        assert_eq!(rip.command, Value::Set(RipCommand::Response));
        assert_eq!(rip.version, Value::Set(2));
        assert_eq!(rip.zero, Value::Set(0));
        assert_eq!(rip.entries.len(), 0);
    }

    #[test]
    fn test_rip_entry_builder() {
        let entry = RipEntry::builder()
            .address_family(RipAfi::Ip)
            .route_tag(0)
            .address("192.168.1.0")
            .subnet_mask("255.255.255.0")
            .next_hop("192.168.1.1")
            .metric(1)
            .build();

        assert_eq!(entry.address_family, Value::Set(RipAfi::Ip as u16));
        assert_eq!(entry.route_tag, Value::Set(0));
        assert_eq!(entry.address, Value::Set(Ipv4Address::from("192.168.1.0")));
        assert_eq!(
            entry.subnet_mask,
            Value::Set(Ipv4Address::from("255.255.255.0"))
        );
        assert_eq!(entry.next_hop, Value::Set(Ipv4Address::from("192.168.1.1")));
        assert_eq!(entry.metric, Value::Set(1));
    }
}
