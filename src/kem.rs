use super::{
    message::Message,
    coefficient::Coefficient,
    poly::{Poly, PolyCompressed, Ntt},
};
use core::{
    fmt,
    ops::Mul,
};
use generic_array::{ArrayLength, typenum::{Unsigned, B0, B1, U3, U8, U14}};

pub struct PublicKeyCpa<N>
where
    N: Mul<U8> + Mul<U3> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
{
    b_hat: Poly<N, B0>,
    seed: Message,
}

pub struct SecretKeyCpa<N>
where
    N: Mul<U8> + Mul<U3> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
{
    s_hat: Poly<N, B0>,
}

pub struct CipherTextCpa<N>
where
    N: Mul<U8> + Mul<U3> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
{
    u_hat: Poly<N, B0>,
    v_prime: PolyCompressed<N, B0>,
}

#[derive(Default, Eq, PartialEq, Debug)]
pub struct SharedSecretCpa(pub Message);

impl<N> PublicKeyCpa<N>
where
    N: Mul<U8> + Mul<U3> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
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

    pub fn encapsulate(&self, seed: Message) -> (CipherTextCpa<N>, SharedSecretCpa) {
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
            SharedSecretCpa(message.hash()),
        )
    }
}

impl<N> SecretKeyCpa<N>
where
    N: Mul<U8> + Mul<U3> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
{
    pub fn decapsulate(&self, cipher_text: &CipherTextCpa<N>) -> SharedSecretCpa {
        let v_prime = Poly::decompress(&cipher_text.v_prime);
        let temp = &(&self.s_hat * &cipher_text.u_hat).reverse_bits().inv_ntt() - &v_prime;
        SharedSecretCpa(temp.to_message().hash())
    }
}

impl<N> fmt::Debug for PublicKeyCpa<N>
where
    N: Mul<U8> + Mul<U3> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
    Poly<N, B1>: Ntt<Output = Poly<N, B0>>,
    Poly<N, B0>: Ntt<Output = Poly<N, B1>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poly = hex::encode(self.b_hat.bytes());
        let seed = hex::encode(self.seed.0);

        f.debug_tuple("PublicKeyCpa")
            .field(&(poly + seed.as_str()))
            .finish()
    }
}
