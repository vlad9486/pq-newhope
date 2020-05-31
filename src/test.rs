use crate::wrapper::{PublicKeyCpakem512, PublicKeyCpakem1024, PublicKeyCcakem512, PublicKeyCcakem1024};
use crate::{PublicKey, SecretKey};

#[test]
fn cpakem512() {
    let (pk, sk) = PublicKeyCpakem512::pair();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!(
        "{}\n{}",
        hex::encode(ss.as_ref()),
        hex::encode(ss_.as_ref())
    );
    assert_eq!(ss_, ss);
}

#[test]
fn cpakem1024() {
    let (pk, sk) = PublicKeyCpakem1024::pair();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!(
        "{}\n{}",
        hex::encode(ss.as_ref()),
        hex::encode(ss_.as_ref())
    );
    assert_eq!(ss_, ss);
}

#[test]
fn ccakem512() {
    let (pk, sk) = PublicKeyCcakem512::pair();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!(
        "{}\n{}",
        hex::encode(ss.as_ref()),
        hex::encode(ss_.as_ref())
    );
    assert_eq!(ss_, ss);
}

#[test]
fn ccakem1024() {
    let (pk, sk) = PublicKeyCcakem1024::pair();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!(
        "{}\n{}",
        hex::encode(ss.as_ref()),
        hex::encode(ss_.as_ref())
    );
    assert_eq!(ss_, ss);
}
