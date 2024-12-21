# Oside

Oside (Oxidize OSI model) is a packet parsing/creation framework heavily inspired by the venerable Scapy.

The focus, much like the Scapy's, is a very flexible packet manipulation
without too much of the paperwork. As a result, it is entirely possible to create
completely invalid or non-conforming packets. Also, "because I can",
as an exercise and an illustration, the library contains as well a pcap file format reader/writer.

The framework is currently in "feasibility study/proof of concept" stage, which means that everything
can absolutely entirely change without any notice, so you have been warned.
For this precise reason the code is the documentation at this point in time.

# Design and usage

The two foundational concepts are "Layer", which represents a network
protocol layer, and "LayerStack", which represents a vector of boxed layers.

The construction of a stack is usually done two ways:

1) by parsing binary data bytes

```rust
use oside::*;
use oside::protocols::all::*;

let packetbytes = b"\0x00\x00";

if let Some((layers, plen)) = Ether!().decode(packetbytes) {
  println!("bytes consumed: {}, layerstack: {:?}", plen, &layers);
} else {
  println!("Error parsing!");
}
```

2) by constructing the layerstack from logical layers.

```rust
use oside::*;
use oside::protocols::all::*;

fn get_dst() -> MacAddr {
    MacAddr::from("22:22:22:22:22:22")
}

let layers = Ether!(src = "00:01:02:03:04:05").dst(Value::Func(get_dst))
        / ARP!(hwsrc = "00:02:03:04:05:06")
        / IP!(src = "192.0.2.1", dst = "2.2.2.2")
        / UDP!(sport = 1234).dport(22)
        / UDP!().dport(22).sport(222)
        / Raw!("Testing12345".into());
```

That there are two ways of initalizing a layer, which can be combined - either
as the set of name+value pair parameters of the macro, or as setter
functions that are executed on an instance of the layer, which return
a new instance with the corresponding fields set.

The name+value paramers are a bit more magical in that they attempt
to perform the necessary conversions - for example, above in the case
of IP!(src = "192.0.2.1") the string is converted to i
*Value<Ipv4Address>* behind the scenes.

Why using *Value<T>* instead of simply *T* ? Because it allows
to encode the intentioned value of the field beyond
the literal value, which is convenient for fields like checksums,
where one can set them to "Auto", and they will be calculated
during the process of building the bytes for the wire representation:

```rust
enum Value<T> {
    Auto,
    Random,
    Func(fn() -> T),
    Set(T),
}
```

This process involves two steps:
1) "fill" - preliminary step, at this step the values like "Random" and "Auto" are set, and a new LayerStack is returned.
2) "encode" - the actual encoding of the LayerStack, fields converted to bytes.

Since this is not an obvious process, the LayerStack has a flag on whether
it has been created as a result of a fill or not - thus simply calling
encode() will do the necessary actions behind the scenes:

```rust
use oside::*;
use oside::protocols::all::*;


let layers = Ether!(src = "00:01:02:03:04:05")
        / ARP!(hwsrc = "00:02:03:04:05:06");
let bytes: Vec<u8> = layers.encode();
```

# Accessing the parsed layers

Let's assume we have a following layerstack:

```rust
use oside::*;
use oside::protocols::all::*;

let layers = Ether!() / IP!() / UDP!() / Ether!() / IP!();
```

A simple way to access the UDP layer would be:

```rust
use oside::*;
use oside::protocols::all::*;

let layers = Ether!() / UDP!().dport(123);

let udp = &layers[UDP!()];
if udp.dport.value() == 123  {
  println!("NTP packet");
}
```

Much like you would expect with the array subscripting, it will
panic in case the parsed packet does not contain the respective layer,
so it is good mostly for quick scripting tasks, or after you have verified
that the given layer does exist.

A more robust approach is to use *.get_layer(...)* method:

```rust
use oside::*;
use oside::protocols::all::*;

let layers = Ether!() / UDP!().dport(123) / UDP!().dport(1000);

if let Some(udp) = layers.get_layer(UDP!()) {
  println!("This is a UDP packet with destination port {}", udp.dport.value());
}

if let Some(udp) = layers.get_innermost_layer(UDP!()) {
  println!("This packet's innermost UDP layer has destination port {}", udp.dport.value());
}


```

Note that both the [] and *.get_layer* match the *first* occurrence of a given layer type
within the stack. The rationale is that this approach is less error prone in the face of
potential protocol injections. E.g. imagine the access control list which would match an IP
source address - matching on innermost instance of layer would allow evasion. If you really
want innermost layer - use *.get_innermost_layer* method.

# Crafting reply packets

Below is an example of a simple ARP responder implementation which will
respond to ARP request with any target with its own MAC address:

```rust
use oside::*;
use oside::protocols::all::*;

// test data with ARP request to make the example work
// This data would be a frame received from interface
let data: Vec<u8> = vec![255, 255, 255, 255, 255, 255,
                         82, 84, 0, 18, 52, 86, 8, 6, 0, 1, 8, 0, 6, 4, 0, 1,
                         82, 84, 0, 18, 52, 86, 192, 168, 76, 9,
                         0, 0, 0, 0, 0, 0, 192, 168, 76, 99];
let sca = Ether!().decode(&data).unwrap().0;
let addr = "01:02:03:04:05:06";

if let Some(arp) = sca.get_layer(ARP!()) {
    if arp.op.value() == 1 {
        println!("ARP request!");
        let reply = Ether!(src = addr, dst = sca[Ether!()].src.clone())
            / ARP!(
                op = 2,
                hwdst = arp.hwsrc.value(),
                pdst = arp.psrc.value(),
                hwsrc = addr,
                psrc = sca[ARP!()].pdst.value()
            );
        println!("Reply: {:?}", &reply);
        let bytes = reply.encode();
        // Send the bytes into the interface here
    }
}
```

# Serde support

The LayerStack struct types also implement Serialize/Deserialize, which rather easily allows to transform the parsed packets into other formats:

```text
cargo run --example pcap2json -- pcap/pcap_3pkts.pcap

[
[{"layertype":"ether","dst":"52:54:00:12:34:56","src":"52:55:C0:A8:4C:02","etype":2048},{"layertype":"Ip","version":4,"ihl":5,"tos":0,"len":64,"id":6745,"flags":"<auto>","frag":0,"ttl":64,"proto":6,"chksum":61441,"src":"34.117.65.55","dst":"192.168.76.9","options":[]},{"layertype":"Tcp","sport":443,"dport":45434,"seq":2175235866,"ack":2451051129,"dataofs":5,"reserved":0,"flags":24,"window":65535,"chksum":24678,"urgptr":0},{"layertype":"raw","data":[23,3,3,0,19,247,152,107,69,171,239,142,50,92,237,67,35,181,108,233,5,164,220,228]}]
,
[{"layertype":"ether","dst":"52:55:C0:A8:4C:02","src":"52:54:00:12:34:56","etype":2048},{"layertype":"Ip","version":4,"ihl":5,"tos":0,"len":68,"id":46601,"flags":"<auto>","frag":16384,"ttl":64,"proto":6,"chksum":5197,"src":"192.168.76.9","dst":"34.117.65.55","options":[]},{"layertype":"Tcp","sport":45434,"dport":443,"seq":2451051129,"ack":2175235890,"dataofs":5,"reserved":0,"flags":24,"window":64022,"chksum":28820,"urgptr":0},{"layertype":"raw","data":[23,3,3,0,23,108,26,140,220,166,254,44,127,234,58,190,139,209,170,56,20,50,33,1,108,25,82,161]}]
,
[{"layertype":"ether","dst":"52:54:00:12:34:56","src":"52:55:C0:A8:4C:02","etype":2048},{"layertype":"Ip","version":4,"ihl":5,"tos":0,"len":40,"id":6746,"flags":"<auto>","frag":0,"ttl":64,"proto":6,"chksum":61464,"src":"34.117.65.55","dst":"192.168.76.9","options":[]},{"layertype":"Tcp","sport":443,"dport":45434,"seq":2175235890,"ack":2451051157,"dataofs":5,"reserved":0,"flags":16,"window":65535,"chksum":61113,"urgptr":0},{"layertype":"raw","data":[0,0,0,0,0,0]}]
]
```
