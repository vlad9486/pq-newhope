extern "C" {
    pub fn c512_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> u32;
    pub fn c512_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> u32;
    pub fn c512_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> u32;

    pub fn c1024_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> u32;
    pub fn c1024_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> u32;
    pub fn c1024_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> u32;

    pub fn p512_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> u32;
    pub fn p512_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> u32;
    pub fn p512_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> u32;

    pub fn p1024_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> u32;
    pub fn p1024_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> u32;
    pub fn p1024_crypto_kem_dec(ss: *mut u8, ct: *const u8, sk: *const u8) -> u32;
}

#[no_mangle]
unsafe fn randombytes(data: *mut u8, length: usize) {
    use core::slice;
    use rand::{thread_rng, Rng};

    thread_rng().fill(slice::from_raw_parts_mut(data, length))
}
