use oside::*;

use crate::protocols::all::*;
use oside::protocols::snmp::*;

#[test]
fn encode_snmp_1() {
    let x1 = Ether!()
        // / IP!(src = "192.0.1.2", dst="192.0.1.3")
        / IPV6!(src = "2001:db8::1", dst="2001:db8::2")
        / UDP!(sport = 1234)
        / SNMP!()
        / SNMPV2C!(community = "12345")
        / SnmpGet(SNMPGETORRESPONSE!(
            request_id = 722681733
            ,var_bindings = vec![
                SNMPVARBIND!(name = "1.0.2.3.4.5.2.3.3.2322.222",
                             value = SnmpValue::Counter64(12345))
                ,SNMPVARBIND!(name = "1.0.2.3.4.5.2.3.3.2322.333",
                             value = SnmpValue::TimeTicks(42))
            ]

        ));

    println!("x1 result: {:02x?}", &x1);
    let encoded = x1.clone().lencode();
    println!("encoded: {:?}", &encoded);
    let x = Ether!().ldecode(&encoded).unwrap().0;
    println!("decode result: {:?}", &x);
    let pcap = vec![x];
    pcap.write_pcap("test_snmp.cap");
}

#[test]
pub fn test_snmpv3_encoding() {
    let test_oid = "1.3.6.1.2.1.1.1.0";
    let x1 = Ether!()
        // / IP!(src = "192.0.1.2", dst="192.0.1.3")
        / IPV6!(src = "2001:db8::1", dst="2001:db8::2")
        / UDP!(sport = 9999)
        / Snmp::v3_get(&vec![test_oid, test_oid]);
    println!("test_snmpv3_encoding x1 result: {:#02x?}", &x1);
    let encoded = x1.clone().lencode();
    println!("encoded: {:?}", &encoded);
    let x = Ether!().ldecode(&encoded).unwrap().0;
    println!("decode result: {:#02x?}", &x);
    let pcap = vec![x];
    pcap.write_pcap("test_snmp_v3.cap");
    assert_eq!(1, 2);
}
