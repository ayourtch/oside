use criterion::{criterion_group, criterion_main, Criterion};
use oside::protocols::all::*;
use oside::*;

fn test_encode() {
    let p = Ether!().set_src(Value::Random)
        / Dot1Q!()
        / IP!().set_dst(Value::Random)
        / UDP!()
        / "asdfg".to_string();
    let out = p.fill().encode();
}

fn encode_benchmark(c: &mut Criterion) {
    c.bench_function("encode ether+ip+udp", |b| b.iter(|| test_encode()));
}

criterion_group!(benches, encode_benchmark);
criterion_main!(benches);
