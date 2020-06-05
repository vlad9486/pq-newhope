use super::{
    message::Message,
    poly::{Poly, PolyCompressed, Packable, Compressible, FromSeed, Ntt},
};
use core::fmt;
use generic_array::typenum::{Unsigned, B0, B1};

pub struct PublicKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
{
    b_hat: Poly<N, B0>,
    seed: Message,
}

pub struct SecretKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
{
    s_hat: Poly<N, B0>,
}

pub struct CipherTextCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
{
    u_hat: Poly<N, B0>,
    v_prime: PolyCompressed<N, B0>,
}

impl<N> PublicKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    Poly<N, B0>: FromSeed + Ntt<Output = Poly<N, B1>>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
{
    pub fn generate(seed: Message) -> (Self, SecretKeyCpa<N>) {
        let (public_seed, noise_seed) = seed.expand(1);

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

    pub fn encapsulate(&self, seed: Message) -> (CipherTextCpa<N>, Message) {
        let (message, noise_seed) = seed.expand(2);

        let v = Poly::<N, B0>::from_message(&message);
        let a_hat = Poly::uniform(&self.seed);
        let s_prime = Poly::<_, B1>::sample(&noise_seed, 0).ntt();
        let e_prime = Poly::<_, B1>::sample(&noise_seed, 1).ntt();
        let e_prime_prime = Poly::sample(&noise_seed, 2);

        let u_hat = &e_prime + &(&a_hat * &s_prime);
        let temp = (&self.b_hat * &s_prime).reverse_bits().inv_ntt();
        let v_prime = &(&(&temp + &e_prime_prime) + &v);
        (
            CipherTextCpa {
                u_hat: u_hat,
                v_prime: v_prime.compress(),
            },
            message.hash(),
        )
    }
}

impl<N> SecretKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    Poly<N, B0>: FromSeed + Ntt<Output = Poly<N, B1>>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
{
    pub fn decapsulate(&self, cipher_text: &CipherTextCpa<N>) -> Message {
        let v_prime = Poly::decompress(&cipher_text.v_prime);
        let temp = &(&self.s_hat * &cipher_text.u_hat).reverse_bits().inv_ntt() - &v_prime;
        temp.to_message().hash()
    }
}

impl<N> fmt::Debug for PublicKeyCpa<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poly = hex::encode(self.b_hat.pack());
        let seed = hex::encode(self.seed.0);

        f.debug_tuple("PublicKeyCpa")
            .field(&(poly + seed.as_str()))
            .finish()
    }
}
