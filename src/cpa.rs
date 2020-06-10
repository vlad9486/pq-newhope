use super::{
    hash,
    pke::{Packable, Codable, Pke, PublicKey, SecretKey, Parameter},
};
use core::marker::PhantomData;
use generic_array::{
    GenericArray,
    typenum::U32,
};

pub struct Cpa<N>(PhantomData<N>)
where
    N: Packable;

#[derive(Clone)]
pub struct PublicKeyCpa<N>
where
    N: Packable,
{
    pk: PublicKey<N>,
    parameter: Parameter<N>,
    seed: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct SecretKeyCpa<N>
where
    N: Packable,
{
    sk: SecretKey<N>,
}

#[derive(Clone)]
pub struct CipherTextCpa<N>
where
    N: Packable,
{
    pk: PublicKey<N>,
    ct: GenericArray<u8, N::CompressedLength>,
}

impl<N> Cpa<N>
where
    N: Packable,
    Parameter<N>: Pke<
        Seed = U32,
        GenerationSeed = U32,
        Plain = U32,
        Cipher = N::CompressedLength,
        PublicKey = PublicKey<N>,
        SecretKey = SecretKey<N>,
    >,
{
    pub fn generate(seed: &GenericArray<u8, U32>) -> (PublicKeyCpa<N>, SecretKeyCpa<N>) {
        let (public_seed, noise_seed) = hash::expand(seed, 1);

        let parameter = Parameter::new(&public_seed);
        let (pk, sk) = parameter.generate(&noise_seed);
        (
            PublicKeyCpa {
                pk: pk,
                parameter: parameter,
                seed: seed.clone(),
            },
            SecretKeyCpa { sk: sk },
        )
    }

    pub fn encapsulate(
        public_key: &PublicKeyCpa<N>,
        seed: &GenericArray<u8, U32>,
    ) -> (CipherTextCpa<N>, GenericArray<u8, U32>) {
        let (message, noise_seed) = hash::expand(seed, 2);
        let (pk, cipher) = public_key
            .parameter
            .encrypt(&noise_seed, &public_key.pk, &message);
        let mut shared_secret = GenericArray::default();
        hash::shake256(message.as_ref(), shared_secret.as_mut());
        (CipherTextCpa { pk: pk, ct: cipher }, shared_secret)
    }

    pub fn decapsulate(
        secret_key: &SecretKeyCpa<N>,
        cipher_text: &CipherTextCpa<N>,
    ) -> GenericArray<u8, U32> {
        let message = Parameter::decrypt(&cipher_text.pk, &secret_key.sk, &cipher_text.ct);
        let mut shared_secret = GenericArray::default();
        hash::shake256(message.as_ref(), shared_secret.as_mut());
        shared_secret
    }
}

mod codable {
    #[rustfmt::skip]
    use super::{
        Codable, Packable, Parameter, Pke,
        PublicKeyCpa, PublicKey,
        SecretKeyCpa, SecretKey,
        CipherTextCpa,
    };
    use generic_array::{
        GenericArray,
        typenum::{Unsigned, U32},
    };

    impl<N> Codable for PublicKeyCpa<N>
    where
        N: Packable,
        Parameter<N>: Pke<Seed = U32>,
        PublicKey<N>: Codable,
    {
        const SIZE: usize = PublicKey::<N>::SIZE + 32;

        fn encode(&self, buffer: &mut [u8]) {
            let m = N::PackedLength::USIZE;
            self.pk.encode(buffer[..m].as_mut());
            buffer[m..].clone_from_slice(self.seed.as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let m = N::PackedLength::USIZE;
            PublicKey::decode(buffer[..m].as_ref()).map(|inner| {
                let mut seed = GenericArray::default();
                seed.clone_from_slice(buffer[m..].as_ref());
                PublicKeyCpa {
                    pk: inner,
                    parameter: Parameter::new(&seed),
                    seed: seed,
                }
            })
        }
    }

    impl<N> Codable for SecretKeyCpa<N>
    where
        N: Packable,
        SecretKey<N>: Codable,
    {
        const SIZE: usize = SecretKey::<N>::SIZE;

        fn encode(&self, buffer: &mut [u8]) {
            self.sk.encode(buffer.as_mut());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            SecretKey::decode(buffer.as_ref()).map(|sk| SecretKeyCpa { sk: sk })
        }
    }

    impl<N> Codable for CipherTextCpa<N>
    where
        N: Packable,
        PublicKey<N>: Codable,
    {
        const SIZE: usize = PublicKey::<N>::SIZE + N::CompressedLength::USIZE;

        fn encode(&self, buffer: &mut [u8]) {
            let m = N::PackedLength::USIZE;
            self.pk.encode(buffer[..m].as_mut());
            buffer[m..].clone_from_slice(self.ct.as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let m = N::PackedLength::USIZE;
            PublicKey::decode(buffer[..m].as_ref()).map(|pk| {
                let mut inner = GenericArray::default();
                inner.clone_from_slice(buffer[m..].as_ref());
                CipherTextCpa { pk: pk, ct: inner }
            })
        }
    }
}
