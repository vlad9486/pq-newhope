use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use criterion_cycles_per_byte::CyclesPerByte;

use pq_newhope::{cpa::Cpa, cca::Cca};
use generic_array::{GenericArray, sequence::GenericSequence, typenum::{U32, U64, U128}};

fn cpa(g: &GenericArray<u8, U32>, e: &GenericArray<u8, U32>) {
    let (pk_a, sk_a) = Cpa::<U128>::generate(g);
    let (ct, key_b) = Cpa::<U128>::encapsulate(&pk_a, e);
    let key_a = Cpa::<U128>::decapsulate(&sk_a, &ct);
    black_box((key_a, key_b));
}

fn cca(g: &GenericArray<u8, U64>, e: &GenericArray<u8, U32>) {
    let (pk_a, sk_a) = Cca::<U128>::generate(g);
    let (ct, key_b) = Cca::<U128>::encapsulate(&pk_a, e);
    let key_a = Cca::<U128>::decapsulate(&sk_a, &ct);
    black_box((key_a, key_b));
}

fn bench(c: &mut Criterion<CyclesPerByte>) {
    let mut group = c.benchmark_group("key_agreement");

    let (g_cpa, g_cca, e_cpa, e_cca) = (
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
    );

    group.bench_function(BenchmarkId::new("cpa", 0), |b| b.iter(|| cpa(&g_cpa, &e_cpa)));
    group.bench_function(BenchmarkId::new("cca", 0), |b| b.iter(|| cca(&g_cca, &e_cca)));

    group.finish()
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
