use super::{PublicKeyCpakem512, PublicKeyCpakem1024, PublicKeyCcakem512, PublicKeyCcakem1024};

#[test]
fn cpakem512() {
    let (pk, sk) = PublicKeyCpakem512::new();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!("{}\n{}", hex::encode(ss.as_ref()), hex::encode(ss_.as_ref()));
    assert_eq!(ss_, ss);
}

#[test]
fn cpakem1024() {
    let (pk, sk) = PublicKeyCpakem1024::new();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!("{}\n{}", hex::encode(ss.as_ref()), hex::encode(ss_.as_ref()));
    assert_eq!(ss_, ss);
}

#[test]
fn ccakem512() {
    let (pk, sk) = PublicKeyCcakem512::new();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!("{}\n{}", hex::encode(ss.as_ref()), hex::encode(ss_.as_ref()));
    assert_eq!(ss_, ss);
}

#[test]
fn ccakem1024() {
    let (pk, sk) = PublicKeyCcakem1024::new();
    let (ct, ss) = pk.encrypt();
    let ss_ = sk.decrypt(&ct);
    println!("{}\n{}", hex::encode(ss.as_ref()), hex::encode(ss_.as_ref()));
    assert_eq!(ss_, ss);
}
