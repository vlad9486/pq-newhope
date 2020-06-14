use super::{
    hash,
    poly::PolySize,
    pke::{Pke, PublicKey, SecretKey, Parameter},
};
use core::marker::PhantomData;
use rac::{
    LineValid,
    generic_array::{GenericArray, typenum::U32},
};
use pq_kem::Kem;

pub struct Cpa<N>(PhantomData<N>)
where
    N: PolySize;

#[derive(Clone)]
pub struct PublicKeyCpa<N>
where
    N: PolySize,
{
    pk: PublicKey<N>,
    parameter: Parameter<N>,
    seed: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct SecretKeyCpa<N>
where
    N: PolySize,
{
    sk: SecretKey<N>,
}

#[derive(Clone)]
pub struct CipherTextCpa<N>
where
    N: PolySize,
{
    pk: PublicKey<N>,
    ct: GenericArray<u8, N::CompressedLength>,
}

impl<N> Kem for Cpa<N>
where
    N: PolySize,
    PublicKeyCpa<N>: LineValid,
    SecretKeyCpa<N>: LineValid,
    CipherTextCpa<N>: LineValid,
    Parameter<N>: Pke<
        Seed = U32,
        GenerationSeed = U32,
        Plain = U32,
        Cipher = N::CompressedLength,
        PublicKey = PublicKey<N>,
        SecretKey = SecretKey<N>,
    >,
{
    type PublicKey = PublicKeyCpa<N>;
    type SecretKey = SecretKeyCpa<N>;
    type CipherText = CipherTextCpa<N>;
    type PairSeedLength = U32;
    type EncapsulationSeedLength = U32;
    type SharedSecretLength = U32;

    fn generate_pair(
        seed: &GenericArray<u8, Self::PairSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey) {
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

    fn encapsulate(
        seed: &GenericArray<u8, Self::EncapsulationSeedLength>,
        public_key: &Self::PublicKey,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let (message, noise_seed) = hash::expand(seed, 2);
        let (pk, cipher) = public_key
            .parameter
            .encrypt(&noise_seed, &public_key.pk, &message);
        let mut shared_secret = GenericArray::default();
        hash::shake256(message.as_ref(), shared_secret.as_mut());
        (CipherTextCpa { pk: pk, ct: cipher }, shared_secret)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength> {
        let message = Parameter::decrypt(&cipher_text.pk, &secret_key.sk, &cipher_text.ct);
        let mut shared_secret = GenericArray::default();
        hash::shake256(message.as_ref(), shared_secret.as_mut());
        shared_secret
    }
}

mod codable {
    #[rustfmt::skip]
    use super::{
        PolySize, Parameter, Pke,
        PublicKeyCpa, PublicKey,
        SecretKeyCpa, SecretKey,
        CipherTextCpa,
    };
    use rac::{
        LineValid, Concat,
        generic_array::{GenericArray, typenum::U32},
    };

    type PkBytes<N> = Concat<PublicKey<N>, GenericArray<u8, <Parameter<N> as Pke>::Seed>>;
    type CtBytes<N> = Concat<PublicKey<N>, GenericArray<u8, <N as PolySize>::CompressedLength>>;

    impl<N> LineValid for PublicKeyCpa<N>
    where
        N: PolySize,
        Parameter<N>: Pke<Seed = U32>,
        PublicKey<N>: Clone + LineValid,
        PkBytes<N>: LineValid,
    {
        type Length = <PkBytes<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            PkBytes::try_clone_array(a).map(|Concat(pk, seed)| PublicKeyCpa {
                pk: pk,
                parameter: Parameter::new(&seed),
                seed: seed,
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(self.pk.clone(), self.seed.clone()).clone_line()
        }
    }

    impl<N> LineValid for SecretKeyCpa<N>
    where
        N: PolySize,
        SecretKey<N>: LineValid,
    {
        type Length = <SecretKey<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            SecretKey::try_clone_array(a).map(|sk| SecretKeyCpa { sk: sk })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            self.sk.clone_line()
        }
    }

    impl<N> LineValid for CipherTextCpa<N>
    where
        N: PolySize,
        PublicKey<N>: Clone + LineValid,
        CtBytes<N>: LineValid,
    {
        type Length = <CtBytes<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            CtBytes::try_clone_array(a).map(|Concat(pk, ct)| CipherTextCpa { pk: pk, ct: ct })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(self.pk.clone(), self.ct.clone()).clone_line()
        }
    }
}
