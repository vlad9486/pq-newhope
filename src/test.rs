use crate::wrapper::{PublicKeyCpakem512, PublicKeyCpakem1024, PublicKeyCcakem512, PublicKeyCcakem1024};
use crate::{PublicKey, SecretKey};
use core::fmt;

fn generic_test<P>()
where
    P: PublicKey,
    P::SharedSecret: PartialEq + fmt::Debug,
{
    let (pk_a, sk_a) = P::generate();
    let (ct, key_b) = pk_a.encapsulate();
    let key_a = sk_a.decapsulate(&ct);
    assert_eq!(key_a, key_b);
}

#[test]
fn cpakem512() {
    generic_test::<PublicKeyCpakem512>()
}

#[test]
fn cpakem1024() {
    generic_test::<PublicKeyCpakem1024>()
}

#[test]
fn ccakem512() {
    generic_test::<PublicKeyCcakem512>()
}

#[test]
fn ccakem1024() {
    generic_test::<PublicKeyCcakem1024>()
}
