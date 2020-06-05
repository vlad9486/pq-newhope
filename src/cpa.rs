use super::{
    kem::Kem,
    message::Message,
    poly::{Poly, PolyCompressed, Packable, Compressible, FromSeed, Ntt},
};
use core::marker::PhantomData;
use generic_array::{
    GenericArray,
    typenum::{Unsigned, B0, B1, U32},
};

pub struct Cpa<N>(PhantomData<N>)
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>;

pub struct PublicKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
{
    b_hat: Poly<N, B0>,
    seed: Message,
}

pub struct SecretKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
{
    s_hat: Poly<N, B0>,
}

pub struct CipherTextCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
{
    u_hat: Poly<N, B0>,
    v_prime: PolyCompressed<N, B0>,
}

impl<N> Kem for Cpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
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
        let mut m_seed = Message::default();
        m_seed.0.clone_from_slice(seed.as_ref());
        let (public_seed, noise_seed) = m_seed.expand(1);

        let a_hat = Poly::uniform(&public_seed);
        let s_hat = Poly::<_, B1>::sample(&noise_seed, 0).ntt();
        let e_hat = Poly::<_, B1>::sample(&noise_seed, 1).ntt();

        let b_hat = &e_hat + &(&a_hat * &s_hat);
        (
            PublicKeyCpa {
                b_hat: b_hat,
                seed: public_seed,
            },
            SecretKeyCpa { s_hat: s_hat },
        )
    }

    fn encapsulate(
        public_key: &Self::PublicKey,
        seed: GenericArray<u8, Self::EncapsulateSeedLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let mut m_seed = Message::default();
        m_seed.0.clone_from_slice(seed.as_ref());
        let (message, noise_seed) = m_seed.expand(2);

        let v = Poly::<N, B0>::from_message(&message);
        let a_hat = Poly::uniform(&public_key.seed);
        let s_prime = Poly::<_, B1>::sample(&noise_seed, 0).ntt();
        let e_prime = Poly::<_, B1>::sample(&noise_seed, 1).ntt();
        let e_prime_prime = Poly::sample(&noise_seed, 2);

        let u_hat = &e_prime + &(&a_hat * &s_prime);
        let temp = (&public_key.b_hat * &s_prime).reverse_bits().inv_ntt();
        let v_prime = &(&(&temp + &e_prime_prime) + &v);
        let mut shared_secret = GenericArray::default();
        shared_secret.clone_from_slice(message.hash().as_ref());
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
        let temp = (&secret_key.s_hat * &cipher_text.u_hat)
            .reverse_bits()
            .inv_ntt();
        let temp = &temp - &v_prime;
        let mut shared_secret = GenericArray::default();
        shared_secret.clone_from_slice(temp.to_message().hash().as_ref());
        shared_secret
    }
}
