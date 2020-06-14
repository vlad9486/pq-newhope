use crate::{
    cpa::Cpa,
    cca::Cca,
    pke::{Pke, Parameter},
};
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
    let (pk_a, sk_a) = Cpa::<U1024>::generate(&GenericArray::generate(|_| rand::random()));
    let (ct, key_b) = Cpa::<U1024>::encapsulate(&pk_a, &GenericArray::generate(|_| rand::random()));
    let key_a = Cpa::<U1024>::decapsulate(&sk_a, &ct);
    assert_eq!(key_a, key_b);
}

#[wasm_bindgen_test]
#[test]
fn cca() {
    let (pk_a, sk_a) = Cca::<U1024>::generate(&GenericArray::generate(|_| rand::random()));
    let (ct, key_b) = Cca::<U1024>::encapsulate(&pk_a, &GenericArray::generate(|_| rand::random()));
    let key_a = Cca::<U1024>::decapsulate(&sk_a, &ct);
    assert_eq!(key_a, key_b);
}
