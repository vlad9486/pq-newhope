use crate::{Kem, Cpa};
use generic_array::{GenericArray, sequence::GenericSequence, typenum::U128};

#[test]
fn cpa() {
    generic::<Cpa<U128>>()
}

fn generic<K>()
where
    K: Kem,
{
    let (pk_a, sk_a) = K::generate(GenericArray::generate(|_| rand::random()));
    let (ct, key_b) = K::encapsulate(&pk_a, GenericArray::generate(|_| rand::random()));
    let key_a = K::decapsulate(&sk_a, &ct);
    assert_eq!(key_a, key_b);
}
