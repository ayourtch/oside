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
    if args.len() != 2 {
        eprintln!("Usage: {} <target_host>", args[0]);
        std::process::exit(1);
    }
    let target_host = &args[1];

    let listener = UdpSocket::bind("127.0.0.20:53")?;

    let forwarder = UdpSocket::bind("0.0.0.0:0")?;

    let target_addr = format!("{}:161", target_host);
    forwarder.connect(&target_addr)?;
    println!("Connected to {}", target_addr);

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

                let snmp_q = SNMP!()
                    / SNMPV2C!(community = "public")
                    / SnmpGet(SNMPGETORRESPONSE!(
                        request_id = 722681733,
                        var_bindings = vec![SNMPVARBIND!(name = name, value = SnmpValue::Null)]
                    ));
                println!("snmp result: {:02x?}", &snmp_q);
                let snmp_encoded = snmp_q.clone().lencode();

                forwarder.send(&snmp_encoded)?;
                println!("Forwarded to {}", target_addr);

                let resp_len = forwarder.recv(&mut buf)?;
                println!("Received {} bytes response", resp_len);

                let snmp_resp = SNMP!().ldecode(&buf[0..resp_len]).unwrap().0;
                println!("Response: {:?}", &snmp_resp);

                if let Some(SnmpGetResponse(r)) = snmp_resp.get_layer(SNMPGETRESPONSE!()) {
                    for x in &r.var_bindings {
                        println!("VAR binding: {:?}", &x);
                        let value = format!("SNMP answer: {:?}", &x.value);

                        let rr = DnsResourceRecord {
                            name: name.to_string(),
                            type_: DnsType::TXT,
                            class: DnsClass::IN,
                            ttl: 1,
                            rdata: DnsRData::TXT(vec![value]),
                        };

                        dns.answers.push(rr);
                    }
                    dns.ancount = Value::Set(dns.answers.len() as u16)
                }
            }
            dns.flags = Value::Set(dns.flags.value() | 0x8000);
            let reply = x.lencode();
            // Send response back to original requester
            listener.send_to(&reply, src_addr)?;
            println!("Sent response back to {}", src_addr);
        }
    }
}
