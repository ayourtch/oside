use criterion::{criterion_group, criterion_main, Criterion};
use oside::protocols::all::*;
use oside::*;

fn test_encode() {
    let p = Ether!().set_src(Value::Random)
        / Dot1Q!()
        / IP!().set_dst(Value::Random)
        / UDP!()
        / "asdfg".to_string();
    let out = p.fill().lencode();
}

fn test_encode_long() {
    let p = Ether!().set_src(Value::Random)
        / Dot1Q!()
        / IP!().set_dst(Value::Random)
        / UDP!()
        / "asdfgasdhkjsadhjahdsakjhdsjkhkdsahjhdsajkhdsjhasdsahhdsadsadsa".to_string();
    let out = p.fill().lencode();
}

use oside::protocols::snmp::*;

fn test_encode_snmp_ipv4() {
    let x1 = Ether!().set_src(Value::Random)
        / IP!().set_dst(Value::Random)
        / UDP!().set_sport(Value::Random)
        / SNMP!()
        / SNMPV2C!(community = "12345")
        / SnmpGet(SNMPGETORRESPONSE!(
            request_id = 722681733,
            var_bindings = vec![
                SNMPVARBIND!(
                    name = "1.0.2.3.4.5.2.3.3.2322.222",
                    value = SnmpValue::Counter64(12345)
                ) /*                ,SNMPVARBIND!(name = "1.0.2.3.4.5.2.3.3.2322.333",
                  value = SnmpValue::Timeticks(42)) */
            ]
        ));
    let out = x1.fill().lencode();
}

fn test_encode_snmp_ipv6() {
    let x1 = Ether!().set_src(Value::Random)
        / IPV6!().set_dst(Value::Random)
        / UDP!().set_sport(Value::Random)
        / SNMP!()
        / SNMPV2C!(community = "12345")
        / SnmpGet(SNMPGETORRESPONSE!(
            request_id = 722681733,
            var_bindings = vec![
                SNMPVARBIND!(
                    name = "1.0.2.3.4.5.2.3.3.2322.222",
                    value = SnmpValue::Counter64(12345)
                ),
                SNMPVARBIND!(
                    name = "1.0.2.3.4.5.2.3.3.2322.333",
                    value = SnmpValue::Timeticks(42)
                )
            ]
        ));
    let out = x1.fill().lencode();
}

fn encode_benchmark(c: &mut Criterion) {
    c.bench_function("encode ether+ip+udp", |b| b.iter(|| test_encode()));
}

fn encode_long_benchmark(c: &mut Criterion) {
    c.bench_function("encode long ether+ip+udp", |b| {
        b.iter(|| test_encode_long())
    });
}

fn snmp_encode_benchmark_ipv4(c: &mut Criterion) {
    c.bench_function("encode ether+ipv4+udp+snmp", |b| {
        b.iter(|| test_encode_snmp_ipv4())
    });
}

fn snmp_encode_benchmark_ipv6(c: &mut Criterion) {
    c.bench_function("encode ether+ipv6+udp+snmp", |b| {
        b.iter(|| test_encode_snmp_ipv6())
    });
}

criterion_group!(
    benches,
    encode_benchmark,
    encode_long_benchmark,
    snmp_encode_benchmark_ipv4,
    snmp_encode_benchmark_ipv6
);
criterion_main!(benches);
