pub fn shake256(data: &[u8], buffer: &mut [u8]) {
    use sha3::{
        Shake256,
        digest::{Input, ExtendableOutput, XofReader},
    };

    Shake256::default().chain(data).xof_result().read(buffer)
}

pub fn expand(seed: &[u8], nonce: u8) -> ([u8; 32], [u8; 32]) {
    let mut data = [0; 33];
    data[0] = nonce;
    data[1..33].clone_from_slice(seed);
    let mut buffer = [0; 64];
    shake256(data.as_ref(), buffer.as_mut());
    let mut public_seed = [0; 32];
    public_seed.clone_from_slice(&buffer[0..32]);
    let mut noise_seed = [0; 32];
    noise_seed[0..32].clone_from_slice(&buffer[32..]);
    (public_seed, noise_seed)
}
