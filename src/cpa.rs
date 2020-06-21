use super::{
    hash,
    poly::PolySize,
    pke::{Pke, PublicKey, SecretKey, Parameter},
};
use core::marker::PhantomData;
use rac::{
    Concat, LineValid,
    generic_array::{GenericArray, typenum::U32},
};
use sha3::digest::{Update, ExtendableOutput};
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

impl<N, D> Kem<D> for Cpa<N>
where
    D: Default + Update + ExtendableOutput,
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
    type PublicKeyHashLength = U32;
    type EncapsulationSeedLength = U32;
    type SharedSecretLength = U32;

    fn generate_pair(
        seed: &GenericArray<u8, Self::PairSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let Concat(public_seed, noise_seed) = hash::h::<D, _, _>(&Concat(hash::B(1), seed.clone()));

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
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let _ = public_key_hash;
        let Concat(message, noise_seed) = hash::h::<D, _, _>(&Concat(hash::B(2), seed.clone()));
        let (pk, cipher) = public_key
            .parameter
            .encrypt(&noise_seed, &public_key.pk, &message);
        (CipherTextCpa { pk: pk, ct: cipher }, hash::h::<D, _, _>(&message))
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength> {
        let _ = public_key_hash;
        let message = Parameter::decrypt(&cipher_text.pk, &secret_key.sk, &cipher_text.ct);
        hash::h::<D, _, _>(&message)
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
