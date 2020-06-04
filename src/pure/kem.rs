use super::poly::{Params, Poly, PolyCompressed, Coefficient, Message};
use core::fmt;
use generic_array::typenum::{B0, B1, U1024};

pub struct PublicKeyCpa<P>
where
    P: Params,
{
    b_hat: Poly<P, U1024, B0>,
    seed: Message,
}

pub struct SecretKeyCpa<P>
where
    P: Params,
{
    s_hat: Poly<P, U1024, B0>,
}

pub struct CipherTextCpa<P>
where
    P: Params,
{
    u_hat: Poly<P, U1024, B0>,
    v_prime: PolyCompressed<P, U1024, B0>,
}

#[derive(Default, Eq, PartialEq, Debug)]
pub struct SharedSecretCpa(pub Message);

impl<P> PublicKeyCpa<P>
where
    P: Params,
    Coefficient<P>: Default + Clone,
{
    pub fn generate(seed: Message) -> (Self, SecretKeyCpa<P>) {
        let (public_seed, noise_seed) = seed.expand(1);

        let a_hat = Poly::uniform(&public_seed);
        let s_hat = Poly::<_, _, B1>::sample(&noise_seed, 0).ntt();
        let e_hat = Poly::<_, _, B1>::sample(&noise_seed, 1).ntt();

        let b_hat = &e_hat + &(&a_hat * &s_hat);
        (
            PublicKeyCpa {
                b_hat: b_hat,
                seed: public_seed,
            },
            SecretKeyCpa { s_hat: s_hat },
        )
    }

    pub fn encapsulate(&self, seed: Message) -> (CipherTextCpa<P>, SharedSecretCpa) {
        let (message, noise_seed) = seed.expand(2);

        let v = Poly::from_message(&message);
        let a_hat = Poly::uniform(&self.seed);
        let s_prime = Poly::<_, _, B1>::sample(&noise_seed, 0).ntt();
        let e_prime = Poly::<_, _, B1>::sample(&noise_seed, 1).ntt();
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

impl<P> SecretKeyCpa<P>
where
    P: Params,
    Coefficient<P>: Default + Clone,
{
    pub fn decapsulate(&self, cipher_text: &CipherTextCpa<P>) -> SharedSecretCpa {
        let v_prime = Poly::decompress(&cipher_text.v_prime);
        let temp = &(&self.s_hat * &cipher_text.u_hat).reverse_bits().inv_ntt() - &v_prime;
        SharedSecretCpa(temp.to_message().hash())
    }
}

impl<P> fmt::Debug for PublicKeyCpa<P>
where
    P: Params,
    Coefficient<P>: Default,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let poly = hex::encode(self.b_hat.bytes());
        let seed = hex::encode(self.seed.0);

        f.debug_tuple("PublicKeyCpa")
            .field(&(poly + seed.as_str()))
            .finish()
    }
}
