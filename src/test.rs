use crate::{PublicKeyCpa, Message};
use generic_array::typenum::U1024;

#[test]
fn pure() {
    let (pk_a, sk_a) = PublicKeyCpa::<U1024>::generate(Message(rand::random()));
    let (ct, key_b) = pk_a.encapsulate(Message(rand::random()));
    let key_a = sk_a.decapsulate(&ct);
    assert_eq!(key_a, key_b);
}
