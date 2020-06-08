use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use criterion_cycles_per_byte::CyclesPerByte;

use pq_newhope::{cpa::Cpa, cca::Cca};
use generic_array::{GenericArray, sequence::GenericSequence, typenum::U128};

fn cpa() {
    let (pk_a, sk_a) = Cpa::<U128>::generate(&GenericArray::generate(|_| rand::random()));
    let (ct, key_b) = Cpa::<U128>::encapsulate(&pk_a, &GenericArray::generate(|_| rand::random()));
    let key_a = Cpa::<U128>::decapsulate(&sk_a, &ct);
    assert_eq!(key_a, key_b);
}

fn cca() {
    let (pk_a, sk_a) = Cca::<U128>::generate(&GenericArray::generate(|_| rand::random()));
    let (ct, key_b) = Cca::<U128>::encapsulate(&pk_a, &GenericArray::generate(|_| rand::random()));
    let key_a = Cca::<U128>::decapsulate(&sk_a, &ct);
    assert_eq!(key_a, key_b);
}

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("key_agreement");

    group.bench_function(BenchmarkId::new("cpa", 0), |b| b.iter(|| cpa()));
    group.bench_function(BenchmarkId::new("cca", 0), |b| b.iter(|| cca()));

    group.finish()
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);