use crate::{Cpa, Cca, Pke, Parameter};
use pq_kem::Kem;
use rac::generic_array::{GenericArray, sequence::GenericSequence, typenum::U1024};
use wasm_bindgen_test::*;

#[wasm_bindgen_test]
#[test]
fn pke() {
    let pke = Parameter::<U1024>::new(&GenericArray::generate(|_| rand::random()));
    let (pk_a, sk_a) = pke.generate(&GenericArray::generate(|_| rand::random()));
    let plain_a = GenericArray::generate(|_| rand::random());
    let (pk_b, ct) = pke.encrypt(&GenericArray::generate(|_| rand::random()), &pk_a, &plain_a);
    let plain_b = Parameter::<U1024>::decrypt(&pk_b, &sk_a, &ct);
    assert_eq!(plain_a, plain_b);
}

#[wasm_bindgen_test]
#[test]
fn cpa() {
    kem::<Cpa<U1024>>()
}

#[wasm_bindgen_test]
#[test]
fn cca() {
    kem::<Cca<U1024>>()
}

fn kem<K>()
where
    K: Kem,
{
    let (pk, sk) = K::generate_pair(&GenericArray::generate(|_| rand::random()));
    let (ct, key_b) = K::encapsulate(&GenericArray::generate(|_| rand::random()), &pk);
    let key_a = K::decapsulate(&sk, &ct);
    assert_eq!(key_a, key_b);
}
