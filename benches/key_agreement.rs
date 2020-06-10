use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use criterion_cycles_per_byte::CyclesPerByte;

use pq_newhope::{
    pke::{Pke, Parameter, Poly, Ntt, FromSeed},
    cpa::Cpa,
    cca::Cca,
};
use generic_array::{
    GenericArray,
    sequence::GenericSequence,
    typenum::{U32, U64, U128, B0},
};

fn gen_poly(a: &GenericArray<u8, U32>) {
    let pke = Parameter::<U128>::new(a);
    black_box(pke);
}

fn ntt(poly: Poly<U128, B0>) {
    black_box(poly.ntt());
}

fn pke(
    a: &GenericArray<u8, U32>,
    gen: &GenericArray<u8, U32>,
    enc: &GenericArray<u8, U32>,
    plain: &GenericArray<u8, U32>,
) {
    let pke = Parameter::<U128>::new(a);
    let (pk_a, sk_a) = pke.generate(gen);
    let (pk_b, ct) = pke.encrypt(enc, &pk_a, plain);
    let plain_b = Parameter::<U128>::decrypt(&pk_b, &sk_a, &ct);
    black_box(plain_b);
}

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

    let (a, gen, enc, plain) = (
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
    );

    let (g_cpa, g_cca, e_cpa, e_cca) = (
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
        GenericArray::generate(|_| rand::random()),
    );

    let p = Poly::<U128, B0>::random(&a.into());

    group.bench_function(BenchmarkId::new("gen", 0), |b| b.iter(|| gen_poly(&a)));
    group.bench_function(BenchmarkId::new("ntt", 0), |b| b.iter(|| ntt(p.clone())));
    group.bench_function(BenchmarkId::new("pke", 0), |b| {
        b.iter(|| pke(&a, &gen, &enc, &plain))
    });
    group.bench_function(BenchmarkId::new("cpa", 0), |b| {
        b.iter(|| cpa(&g_cpa, &e_cpa))
    });
    group.bench_function(BenchmarkId::new("cca", 0), |b| {
        b.iter(|| cca(&g_cca, &e_cca))
    });

    group.finish()
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = bench
);

criterion_main!(benches);
