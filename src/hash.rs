use rac::generic_array::{GenericArray, typenum::U32};

pub fn shake256(data: &[u8], buffer: &mut [u8]) {
    use sha3::{
        Shake256,
        digest::{Update, ExtendableOutput, XofReader},
    };

    Shake256::default().chain(data).finalize_xof().read(buffer)
}

pub fn expand(
    seed: &GenericArray<u8, U32>,
    nonce: u8,
) -> (GenericArray<u8, U32>, GenericArray<u8, U32>) {
    let mut data = [0; 0x21];
    data[0] = nonce;
    data[0x01..0x21].clone_from_slice(seed.as_ref());
    let mut buffer = [0; 0x40];
    shake256(data.as_ref(), buffer.as_mut());
    let mut public_seed = GenericArray::default();
    public_seed.clone_from_slice(&buffer[..0x20]);
    let mut noise_seed = GenericArray::default();
    noise_seed.clone_from_slice(&buffer[0x20..]);
    (public_seed, noise_seed)
}
