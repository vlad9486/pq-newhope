use super::{
    hash,
    pke::{Packable, Codable, Pke, PublicKey, SecretKey, Parameter},
};
use core::{marker::PhantomData, ops::Add};
use generic_array::{
    GenericArray, ArrayLength,
    typenum::{Unsigned, U32, U64},
};

pub struct Cca<N>(PhantomData<N>)
where
    N: Packable;

#[derive(Clone)]
pub struct PublicKeyCca<N>
where
    N: Packable,
{
    pk: PublicKey<N>,
    parameter: Parameter<N>,
    seed: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct SecretKeyCca<N>
where
    N: Packable,
{
    sk: SecretKey<N>,
    pk: PublicKeyCca<N>,
    pk_hash: GenericArray<u8, U32>,
    reject: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct CipherTextCca<N>
where
    N: Packable,
{
    pk: PublicKey<N>,
    ct: GenericArray<u8, N::CompressedLength>,
    check: GenericArray<u8, U32>,
}

type PkLength<N> = <<N as Packable>::PackedLength as Add<U32>>::Output;
type CtLength<N> = <PkLength<N> as Add<<N as Packable>::CompressedLength>>::Output;

impl<N> Cca<N>
where
    N: Packable + Unsigned,
    N::PackedLength: Add<U32> + Unsigned,
    PkLength<N>: ArrayLength<u8> + Add<N::CompressedLength>,
    CtLength<N>: ArrayLength<u8>,
    Parameter<N>: Pke<
        Seed = U32,
        GenerationSeed = U32,
        Plain = U32,
        Cipher = N::CompressedLength,
        PublicKey = PublicKey<N>,
        SecretKey = SecretKey<N>,
    >,
{
    fn public_key_hash(pk: &PublicKeyCca<N>) -> GenericArray<u8, U32> {
        let mut pk_hash = GenericArray::default();
        let mut pk_bytes = GenericArray::<u8, PkLength<N>>::default();
        pk.encode(pk_bytes.as_mut());
        hash::shake256(pk_bytes.as_ref(), pk_hash.as_mut());
        pk_hash
    }

    fn cipher_text_hash(ct: &CipherTextCca<N>) -> GenericArray<u8, U32> {
        let mut ct_hash = GenericArray::default();
        let mut ct_bytes = GenericArray::<u8, CtLength<N>>::default();
        ct.encode(ct_bytes.as_mut());
        hash::shake256(ct_bytes.as_ref(), ct_hash.as_mut());
        ct_hash
    }

    pub fn generate(seed: &GenericArray<u8, U64>) -> (PublicKeyCca<N>, SecretKeyCca<N>) {
        let mut reject = GenericArray::default();
        reject.clone_from_slice(seed[..32].as_ref());
        let mut cpa_seed = GenericArray::default();
        cpa_seed.clone_from_slice(seed[32..].as_ref());
        let (parameter_seed, pk_seed) = hash::expand(&cpa_seed, 1);
        let parameter = Parameter::new(&parameter_seed);
        let (pk, sk) = parameter.generate(&pk_seed);
        let public_key = PublicKeyCca {
            pk: pk,
            parameter: parameter,
            seed: parameter_seed,
        };
        let pk_hash = Self::public_key_hash(&public_key);
        (
            public_key.clone(),
            SecretKeyCca {
                sk: sk,
                pk: public_key,
                pk_hash: pk_hash,
                reject: reject,
            },
        )
    }

    pub fn encapsulate(
        public_key: &PublicKeyCca<N>,
        seed: &GenericArray<u8, U32>,
    ) -> (CipherTextCca<N>, GenericArray<u8, U32>) {
        let mut ext_seed = [0; 0x21];
        ext_seed[0x00] = 0x04;
        ext_seed[0x01..0x21].clone_from_slice(seed.as_ref());

        let mut new_seed = [0; 0x41];
        new_seed[0x00] = 0x08;
        hash::shake256(ext_seed.as_ref(), &mut new_seed[0x01..0x21]);
        let public_key_hash = Self::public_key_hash(&public_key);
        new_seed[0x21..0x41].clone_from_slice(public_key_hash.as_ref());

        let mut buffer = [0; 0x60];
        hash::shake256(new_seed.as_ref(), buffer.as_mut());

        let mut encryption_seed = GenericArray::default();
        encryption_seed.clone_from_slice(buffer[0x20..0x40].as_ref());

        let mut message = GenericArray::default();
        message.clone_from_slice(new_seed[0x01..0x21].as_ref());
        let (pk_b, ct) = public_key
            .parameter
            .encrypt(&encryption_seed, &public_key.pk, &message);

        let mut hash = GenericArray::default();
        hash.clone_from_slice(buffer[0x40..].as_ref());
        let cipher_text = CipherTextCca {
            pk: pk_b,
            ct: ct,
            check: hash,
        };
        let ct_hash = Self::cipher_text_hash(&cipher_text);
        buffer[0x20..0x40].clone_from_slice(ct_hash.as_ref());

        let mut shared_secret = GenericArray::default();
        hash::shake256(buffer[0x00..0x40].as_ref(), shared_secret.as_mut());
        (cipher_text, shared_secret)
    }

    pub fn decapsulate(
        secret_key: &SecretKeyCca<N>,
        cipher_text: &CipherTextCca<N>,
    ) -> GenericArray<u8, U32> {
        #[inline(never)]
        fn c_cmp(a: &[u8], b: &[u8]) -> u8 {
            (0..a.len()).fold(0, |r, i| r | (a[i] ^ b[i]))
        }

        #[inline(never)]
        fn c_mov(r: &mut [u8], x: &[u8], c: u8) {
            for i in 0..r.len() {
                r[i] ^= c & (x[i] ^ r[i]);
            }
        }

        let message = Parameter::decrypt(&cipher_text.pk, &secret_key.sk, &cipher_text.ct);
        let mut new_seed = [0; 0x41];
        new_seed[0x00] = 0x08;
        new_seed[0x01..0x21].clone_from_slice(message.as_ref());
        new_seed[0x21..0x41].clone_from_slice(secret_key.pk_hash.as_ref());

        let mut buffer = [0; 0x60];
        hash::shake256(new_seed.as_ref(), buffer.as_mut());

        let mut encryption_seed = GenericArray::default();
        encryption_seed.clone_from_slice(buffer[0x20..0x40].as_ref());

        let (pk_b_cmp, ct_cmp) =
            secret_key
                .pk
                .parameter
                .encrypt(&encryption_seed, &secret_key.pk.pk, &message);

        let mut hash = GenericArray::default();
        hash.clone_from_slice(buffer[0x40..].as_ref());
        let cipher_text_cmp = CipherTextCca {
            pk: pk_b_cmp,
            ct: ct_cmp,
            check: hash,
        };

        let mut cipher_text_bytes = GenericArray::<u8, CtLength<N>>::default();
        cipher_text.encode(cipher_text_bytes.as_mut());
        let mut cipher_text_cmp_bytes = GenericArray::<u8, CtLength<N>>::default();
        cipher_text_cmp.encode(cipher_text_cmp_bytes.as_mut());
        let fail = c_cmp(cipher_text_bytes.as_ref(), cipher_text_cmp_bytes.as_ref());
        let fail = if fail == 0 { 0 } else { 0xff };
        hash::shake256(cipher_text_bytes.as_ref(), buffer[0x20..0x40].as_mut());
        c_mov(
            buffer[0x00..0x20].as_mut(),
            secret_key.reject.as_ref(),
            fail,
        );

        let mut shared_secret = GenericArray::default();
        hash::shake256(buffer[0x00..0x40].as_ref(), shared_secret.as_mut());
        shared_secret
    }
}

mod codable {
    #[rustfmt::skip]
    use super::{
        Codable, Packable, Parameter, Pke,
        PublicKeyCca, PublicKey,
        SecretKeyCca, SecretKey,
        CipherTextCca,
    };
    use generic_array::{
        GenericArray,
        typenum::{Unsigned, U32},
    };

    impl<N> Codable for PublicKeyCca<N>
    where
        N: Packable,
        N::PackedLength: Unsigned,
        Parameter<N>: Pke<Seed = U32>,
        PublicKey<N>: Codable,
    {
        const SIZE: usize = PublicKey::<N>::SIZE + 32;

        fn encode(&self, buffer: &mut [u8]) {
            let m = <N::PackedLength as Unsigned>::USIZE;
            self.pk.encode(buffer[..m].as_mut());
            buffer[m..].clone_from_slice(self.seed.as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let m = <N::PackedLength as Unsigned>::USIZE;
            PublicKey::decode(buffer[..m].as_ref()).map(|inner| {
                let mut seed = GenericArray::default();
                seed.clone_from_slice(buffer[m..].as_ref());
                PublicKeyCca {
                    pk: inner,
                    parameter: Parameter::new(&seed),
                    seed: seed,
                }
            })
        }
    }

    impl<N> Codable for SecretKeyCca<N>
    where
        N: Packable,
        N::PackedLength: Unsigned,
        SecretKey<N>: Codable,
        PublicKeyCca<N>: Codable,
    {
        const SIZE: usize = SecretKey::<N>::SIZE;

        fn encode(&self, buffer: &mut [u8]) {
            let m = <N::PackedLength as Unsigned>::USIZE;
            let n = m + <PublicKeyCca<N> as Codable>::SIZE;
            let o = n + 32;
            self.sk.encode(buffer[..m].as_mut());
            self.pk.encode(buffer[m..n].as_mut());
            buffer[n..o].clone_from_slice(self.pk_hash.as_ref());
            buffer[o..].clone_from_slice(self.reject.as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let m = <N::PackedLength as Unsigned>::USIZE;
            let n = m + <PublicKeyCca<N> as Codable>::SIZE;
            let o = n + 32;
            SecretKey::decode(buffer[..m].as_ref()).and_then(|sk| {
                PublicKeyCca::decode(buffer[m..n].as_ref()).map(|pk| {
                    let mut pk_hash = GenericArray::default();
                    pk_hash.clone_from_slice(buffer[n..o].as_ref());
                    let mut reject = GenericArray::default();
                    reject.clone_from_slice(buffer[o..].as_ref());
                    SecretKeyCca {
                        sk: sk,
                        pk: pk,
                        pk_hash: pk_hash,
                        reject: reject,
                    }
                })
            })
        }
    }

    impl<N> Codable for CipherTextCca<N>
    where
        N: Packable,
        N::PackedLength: Unsigned,
        N::CompressedLength: Unsigned,
        PublicKey<N>: Codable,
    {
        const SIZE: usize = PublicKey::<N>::SIZE + N::CompressedLength::USIZE + 32;

        fn encode(&self, buffer: &mut [u8]) {
            let m = <N::PackedLength as Unsigned>::USIZE;
            let n = m + <N::CompressedLength as Unsigned>::USIZE;
            self.pk.encode(buffer[..m].as_mut());
            buffer[m..n].clone_from_slice(self.ct.as_ref());
            buffer[n..].clone_from_slice(self.check.as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let m = <N::PackedLength as Unsigned>::USIZE;
            let n = m + <N::CompressedLength as Unsigned>::USIZE;
            PublicKey::decode(buffer[..m].as_ref()).map(|pk| {
                let mut inner = GenericArray::default();
                inner.clone_from_slice(buffer[m..n].as_ref());
                let mut check = GenericArray::default();
                check.clone_from_slice(buffer[n..].as_ref());
                CipherTextCca {
                    pk: pk,
                    ct: inner,
                    check: check,
                }
            })
        }
    }
}
