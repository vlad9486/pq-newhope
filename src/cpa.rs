use super::{
    traits::Kem,
    hash,
    pke::{Poly, Packable, FromSeed, Ntt},
};
use core::marker::PhantomData;
use generic_array::{
    GenericArray,
    typenum::{Unsigned, B0, B1, U32},
};
use rac::LineValid;

pub struct Cpa<N>(PhantomData<N>)
where
    N: Packable;

#[derive(Clone)]
pub struct PublicKeyCpa<N>
where
    N: Packable,
{
    b_hat: Poly<N, B0>,
    seed: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct SecretKeyCpa<N>
where
    N: Packable,
{
    s_hat: Poly<N, B0>,
}

#[derive(Clone)]
pub struct CipherTextCpa<N>
where
    N: Packable,
{
    u_hat: Poly<N, B0>,
    v_prime: GenericArray<u8, N::CompressedLength>,
}

impl<N> Kem for Cpa<N>
where
    N: Packable + Unsigned,
    PublicKeyCpa<N>: LineValid,
    SecretKeyCpa<N>: LineValid,
    CipherTextCpa<N>: LineValid,
    Poly<N, B0>: FromSeed + Ntt<Output = Poly<N, B1>>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
{
    type PublicKey = PublicKeyCpa<N>;
    type SecretKey = SecretKeyCpa<N>;
    type CipherText = CipherTextCpa<N>;
    type SharedSecretLength = U32;
    type GenerateSeedLength = U32;
    type EncapsulateSeedLength = U32;

    fn generate(
        seed: GenericArray<u8, Self::GenerateSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let (public_seed, noise_seed) = hash::expand(seed.as_ref(), 1);

        let a_hat = Poly::random(&public_seed);
        let s_hat = Poly::<_, B1>::random_small(&noise_seed, 0).ntt();
        let e_hat = Poly::<_, B1>::random_small(&noise_seed, 1).ntt();
        let b_hat = Poly::functor_3(&e_hat, &a_hat, &s_hat, |e, a, s| e + &(a * s));
        (
            PublicKeyCpa {
                b_hat: b_hat,
                seed: public_seed.into(),
            },
            SecretKeyCpa { s_hat: s_hat },
        )
    }

    fn encapsulate(
        public_key: &Self::PublicKey,
        seed: GenericArray<u8, Self::EncapsulateSeedLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let (message, noise_seed) = hash::expand(seed.as_ref(), 2);

        let v = Poly::<N, B0>::from_message(&message);
        let a_hat = Poly::random(&public_key.seed.into());
        let s_prime = Poly::<_, B1>::random_small(&noise_seed, 0).ntt();
        let e_prime = Poly::<_, B1>::random_small(&noise_seed, 1).ntt();
        let e_prime_prime = Poly::random_small(&noise_seed, 2);

        let u_hat = Poly::functor_3(&e_prime, &a_hat, &s_prime, |e, a, s| e + &(a * s));
        let temp = Poly::functor_2(&public_key.b_hat, &s_prime, |b, s| b * s);
        let temp = temp.reverse_bits().inv_ntt();
        let v_prime = Poly::functor_3(&temp, &e_prime_prime, &v, |t, e, v| t + &(e + v));
        let mut shared_secret = GenericArray::default();
        hash::shake256(message.as_ref(), shared_secret.as_mut());
        (
            CipherTextCpa {
                u_hat: u_hat,
                v_prime: v_prime.compress(),
            },
            shared_secret,
        )
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength> {
        let v_prime = Poly::decompress(&cipher_text.v_prime);
        let temp = Poly::functor_2(&cipher_text.u_hat, &secret_key.s_hat, |u, s| u * s);
        let temp = temp.reverse_bits().inv_ntt();
        let v = Poly::functor_2(&temp, &v_prime, |t, v| t - v);
        let mut shared_secret = GenericArray::default();
        hash::shake256(v.to_message_negate().as_ref(), shared_secret.as_mut());
        shared_secret
    }
}

mod proofs {
    use super::{Poly, Packable, PublicKeyCpa, SecretKeyCpa, CipherTextCpa};
    use generic_array::{
        GenericArray,
        typenum::{Unsigned, U32},
    };
    use rac::{LineValid, Line, Concat};

    type PublicKeyCpaBytes<N> =
        Concat<GenericArray<u8, <N as Packable>::PackedLength>, GenericArray<u8, U32>>;

    impl<N> LineValid for PublicKeyCpa<N>
    where
        N: Packable + Unsigned,
        PublicKeyCpaBytes<N>: Line,
    {
        type Length = <PublicKeyCpaBytes<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            let Concat(b_hat_bytes, seed) = <PublicKeyCpaBytes<N> as Line>::clone_array(a);
            Poly::unpack(&b_hat_bytes).map(|b_hat| PublicKeyCpa {
                b_hat: b_hat,
                seed: seed,
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            let b_hat_bytes = self.b_hat.pack();
            let seed = self.seed.clone();
            Concat(b_hat_bytes, seed).clone_line()
        }
    }

    impl<N> LineValid for SecretKeyCpa<N>
    where
        N: Packable + Unsigned,
    {
        type Length = <N as Packable>::PackedLength;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            Poly::unpack(&GenericArray::clone_array(a)).map(|s_hat| SecretKeyCpa { s_hat: s_hat })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            self.s_hat.pack()
        }
    }

    type CipherTextCpaBytes<N> = Concat<
        GenericArray<u8, <N as Packable>::PackedLength>,
        GenericArray<u8, <N as Packable>::CompressedLength>,
    >;

    impl<N> LineValid for CipherTextCpa<N>
    where
        N: Packable + Unsigned,
        CipherTextCpaBytes<N>: Line,
    {
        type Length = <CipherTextCpaBytes<N> as LineValid>::Length;

        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            let Concat(u_hat_bytes, v_prime) = <CipherTextCpaBytes<N> as Line>::clone_array(a);
            Poly::unpack(&u_hat_bytes).map(|u_hat| CipherTextCpa {
                u_hat: u_hat,
                v_prime: v_prime,
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            let b_hat_bytes = self.u_hat.pack();
            let v_prime = self.v_prime.clone();
            Concat(b_hat_bytes, v_prime).clone_line()
        }
    }
}
