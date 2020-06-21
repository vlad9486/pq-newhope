use super::{
    hash,
    poly::PolySize,
    pke::{Pke, PublicKey, SecretKey, Parameter},
};
use core::marker::PhantomData;
use rac::{
    LineValid, Line, Concat,
    generic_array::{
        GenericArray,
        typenum::{U32, U64},
    },
};
use sha3::digest::{Update, ExtendableOutput};
use pq_kem::Kem;

pub struct Cca<N>(PhantomData<N>)
where
    N: PolySize;

#[derive(Clone)]
pub struct PublicKeyCca<N>
where
    N: PolySize,
{
    pk: PublicKey<N>,
    parameter: Parameter<N>,
    seed: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct SecretKeyCca<N>
where
    N: PolySize,
{
    sk: SecretKey<N>,
    reject: GenericArray<u8, U32>,
    pk: PublicKeyCca<N>,
}

#[derive(Clone)]
pub struct CipherTextCca<N>
where
    N: PolySize,
{
    pk: PublicKey<N>,
    ct: GenericArray<u8, N::CompressedLength>,
    check: GenericArray<u8, U32>,
}

type B = Concat<Concat<GenericArray<u8, U32>, GenericArray<u8, U32>>, GenericArray<u8, U32>>;

impl<N, D> Kem<D> for Cca<N>
where
    D: Default + Update + ExtendableOutput,
    N: PolySize,
    PublicKeyCca<N>: Clone + LineValid,
    SecretKeyCca<N>: LineValid,
    CipherTextCca<N>: Clone + LineValid,
    Concat<GenericArray<u8, U32>, CipherTextCca<N>>: LineValid,
    Parameter<N>: Pke<
        Seed = U32,
        GenerationSeed = U32,
        Plain = U32,
        Cipher = N::CompressedLength,
        PublicKey = PublicKey<N>,
        SecretKey = SecretKey<N>,
    >,
{
    type PublicKey = PublicKeyCca<N>;
    type SecretKey = SecretKeyCca<N>;
    type CipherText = CipherTextCca<N>;
    type PairSeedLength = U64;
    type PublicKeyHashLength = U32;
    type EncapsulationSeedLength = U32;
    type SharedSecretLength = U32;

    fn generate_pair(
        seed: &GenericArray<u8, Self::PairSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let Concat(reject, cpa_seed) = Concat::<_, GenericArray<u8, U32>>::clone_array(seed);
        let Concat(parameter_seed, pk_seed) = hash::h::<D, _, _>(&Concat(hash::B(1), cpa_seed));
        let parameter = Parameter::new(&parameter_seed);
        let (pk, sk) = parameter.generate(&pk_seed);
        let public_key = PublicKeyCca {
            pk: pk,
            parameter: parameter,
            seed: parameter_seed,
        };
        (
            public_key.clone(),
            SecretKeyCca {
                sk: sk,
                reject: reject,
                pk: public_key.clone(),
            },
        )
    }

    fn encapsulate(
        seed: &GenericArray<u8, Self::EncapsulationSeedLength>,
        public_key: &Self::PublicKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let message: GenericArray<u8, U32> = hash::h::<D, _, _>(&Concat(hash::B(0x04), seed.clone()));
        let Concat(Concat(b0, b1), b2) = hash::h::<D, Concat<_, GenericArray<u8, U32>>, B>(&Concat(
            Concat(hash::B(0x08), message.clone()),
            public_key_hash.clone(),
        ));
        let (pk_b, ct) = public_key.parameter.encrypt(&b1, &public_key.pk, &message);
        let cipher_text = CipherTextCca {
            pk: pk_b,
            ct: ct,
            check: b2,
        };
        let shared_secret = hash::h::<D, _, _>(&Concat(b0, cipher_text.clone()));
        (cipher_text, shared_secret)
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        public_key_hash: &GenericArray<u8, Self::PublicKeyHashLength>,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength> {
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

        let message: GenericArray<u8, U32> =
            Parameter::decrypt(&cipher_text.pk, &secret_key.sk, &cipher_text.ct);
        let Concat(Concat(mut b0, b1), b2) = hash::h::<D, Concat<_, GenericArray<u8, U32>>, B>(
            &Concat(Concat(hash::B(0x08), message.clone()), public_key_hash.clone()),
        );

        let (pk_b_cmp, ct_cmp) = secret_key
            .pk
            .parameter
            .encrypt(&b1, &secret_key.pk.pk, &message);
        let cipher_text_cmp = CipherTextCca {
            pk: pk_b_cmp,
            ct: ct_cmp,
            check: b2,
        };
        let cipher_text_bytes = cipher_text.clone_line();
        let cipher_text_cmp_bytes = cipher_text_cmp.clone_line();
        let fail = c_cmp(cipher_text_bytes.as_ref(), cipher_text_cmp_bytes.as_ref());
        c_mov(
            b0.as_mut(),
            secret_key.reject.as_ref(),
            if fail == 0 { 0 } else { 0xff },
        );
        hash::h::<D, _, _>(&Concat(b0, cipher_text.clone()))
    }
}

mod codable {
    #[rustfmt::skip]
    use super::{
        PolySize, Parameter, Pke,
        PublicKeyCca, PublicKey,
        SecretKeyCca, SecretKey,
        CipherTextCca,
    };
    use rac::{
        LineValid, Concat,
        generic_array::{GenericArray, typenum::U32},
    };

    type PkBytes<N> = Concat<PublicKey<N>, GenericArray<u8, <Parameter<N> as Pke>::Seed>>;
    type SkBytes<N> = Concat<SecretKey<N>, GenericArray<u8, U32>>;
    type CtTemp<N> = Concat<PublicKey<N>, GenericArray<u8, <N as PolySize>::CompressedLength>>;
    type CtBytes<N> = Concat<CtTemp<N>, GenericArray<u8, U32>>;

    impl<N> LineValid for PublicKeyCca<N>
    where
        N: PolySize,
        Parameter<N>: Pke<Seed = U32>,
        PublicKey<N>: Clone + LineValid,
        PkBytes<N>: LineValid,
    {
        type Length = <PkBytes<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            PkBytes::try_clone_array(a).map(|Concat(pk, seed)| PublicKeyCca {
                pk: pk,
                parameter: Parameter::new(&seed),
                seed: seed,
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(self.pk.clone(), self.seed.clone()).clone_line()
        }
    }

    impl<N> LineValid for SecretKeyCca<N>
    where
        N: PolySize,
        SecretKey<N>: Clone + LineValid,
        PublicKeyCca<N>: Clone + LineValid,
        Concat<SecretKey<N>, PublicKeyCca<N>>: LineValid,
        SkBytes<N>: LineValid,
        Concat<SkBytes<N>, PublicKeyCca<N>>: LineValid,
    {
        type Length = <Concat<SkBytes<N>, PublicKeyCca<N>> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            Concat::<SkBytes<N>, PublicKeyCca<N>>::try_clone_array(a)
                .map(|Concat(Concat(sk, reject), pk)| {
                    SecretKeyCca {
                        sk: sk,
                        reject: reject,
                        pk: pk,
                    }
                })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(
                Concat(self.sk.clone(), self.reject.clone()),
                self.pk.clone(),
            )
            .clone_line()
        }
    }

    impl<N> LineValid for CipherTextCca<N>
    where
        N: PolySize,
        PublicKey<N>: Clone + LineValid,
        CtTemp<N>: LineValid,
        CtBytes<N>: LineValid,
    {
        type Length = <CtBytes<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            CtBytes::try_clone_array(a).map(|Concat(Concat(pk, ct), check)| CipherTextCca {
                pk: pk,
                ct: ct,
                check: check,
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(Concat(self.pk.clone(), self.ct.clone()), self.check.clone()).clone_line()
        }
    }
}
