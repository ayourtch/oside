use std::env;
use std::error::Error;
use std::net::UdpSocket;

use oside::protocols::dns::*;
use oside::protocols::snmp::*;
use oside::Layer;
use oside::Value;

use oside::DNS;
use oside::SNMP;
use oside::SNMPGETORRESPONSE;
use oside::SNMPGETRESPONSE;
use oside::SNMPV2C;
use oside::SNMPVARBIND;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let listener = UdpSocket::bind("127.0.0.1:53153")?;

    // Buffer for receiving data
    let mut buf = vec![0u8; 65535]; // Maximum UDP packet size

    loop {
        let (len, src_addr) = listener.recv_from(&mut buf)?;
        println!("Received {} bytes from {}", len, src_addr);
        let mut x = DNS!().ldecode(&buf[0..len]).unwrap().0;
        if let Some(dns) = x.get_layer_mut(DNS!()) {
            println!("Decoded: {:?}", &dns);

            if dns.questions.len() > 0 && dns.questions[0].qtype == DnsType::A {
                let name = dns.questions[0].qname.clone();
                let name = name.trim_end_matches('.');
                println!("Question is: {}", &name);

                let rr = DnsResourceRecord {
                    name: name.to_string(),
                    type_: DnsType::TXT,
                    class: DnsClass::IN,
                    ttl: 1,
                    rdata: DnsRData::TXT(vec!["testing123".to_string()]),
                };

                dns.answers.push(rr);
            }
            dns.flags = Value::Set(dns.flags.value() | 0x8000);
            eprintln!("X: {:#?}", &x);
            let reply = x.lencode();
            // Send response back to original requester
            listener.send_to(&reply, src_addr)?;
            println!("Sent response back to {}", src_addr);
        }
    }
}
