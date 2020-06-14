use super::poly::{Poly, PolySize, FromSeed, FromSeedSmall, ReverseBits, Ntt};
use generic_array::{
    GenericArray, ArrayLength,
    typenum::{U32, B0, B1},
};

#[derive(Clone)]
pub struct PublicKey<N>(Poly<N, (B0, B0, B1)>)
where
    N: PolySize;

#[derive(Clone)]
pub struct SecretKey<N>(Poly<N, (B0, B0, B1)>)
where
    N: PolySize;

#[derive(Clone)]
pub struct Parameter<N>(Poly<N, (B0, B1, B1)>)
where
    N: PolySize;

// TODO: compile-time length check
pub trait Codable
where
    Self: Sized,
{
    const SIZE: usize;

    fn encode(&self, buffer: &mut [u8]);
    fn decode(buffer: &[u8]) -> Result<Self, ()>;
}

pub trait Pke {
    type Seed: ArrayLength<u8>;
    type GenerationSeed: ArrayLength<u8>;
    type Plain: ArrayLength<u8>;
    type Cipher: ArrayLength<u8>;
    type PublicKey: Sized + Codable;
    type SecretKey: Sized + Codable;

    fn new(seed: &GenericArray<u8, Self::Seed>) -> Self;
    fn generate(
        &self,
        seed: &GenericArray<u8, Self::GenerationSeed>,
    ) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt(
        &self,
        seed: &GenericArray<u8, Self::GenerationSeed>,
        pk_a: &Self::PublicKey,
        plain: &GenericArray<u8, Self::Plain>,
    ) -> (Self::PublicKey, GenericArray<u8, Self::Cipher>);
    fn decrypt(
        pk_b: &Self::PublicKey,
        sk_a: &Self::SecretKey,
        cipher: &GenericArray<u8, Self::Cipher>,
    ) -> GenericArray<u8, Self::Plain>;
}

impl<N> Pke for Parameter<N>
where
    N: PolySize,
    Poly<N, (B0, B1, B1)>: FromSeed,
    Poly<N, (B1, B0, B0)>: FromSeedSmall + Ntt<Output = Poly<N, (B0, B0, B1)>>,
    Poly<N, (B0, B0, B1)>: Ntt + ReverseBits<Output = Poly<N, (B1, B0, B1)>>,
    Poly<N, (B1, B0, B1)>: Ntt<Output = Poly<N, (B0, B0, B0)>> + ReverseBits,
    Poly<N, (B0, B0, B0)>: FromSeed + Ntt,
{
    type Seed = U32;
    type GenerationSeed = U32;
    type Plain = U32;
    type Cipher = N::CompressedLength;
    type PublicKey = PublicKey<N>;
    type SecretKey = SecretKey<N>;

    fn new(seed: &GenericArray<u8, Self::Seed>) -> Self {
        Parameter(Poly::random(seed))
    }

    fn generate(
        &self,
        seed: &GenericArray<u8, Self::GenerationSeed>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let s = Poly::random_small(seed, 0).ntt();
        let e = Poly::random_small(seed, 1).ntt();
        let b = Poly::functor_3(&e, &self.0, &s, |e, a, s| e + a * s);
        (PublicKey(b), SecretKey(s))
    }

    fn encrypt(
        &self,
        seed: &GenericArray<u8, Self::GenerationSeed>,
        pk_a: &Self::PublicKey,
        plain: &GenericArray<u8, Self::Plain>,
    ) -> (Self::PublicKey, GenericArray<u8, Self::Cipher>) {
        let v = Poly::from_message(plain);
        let (pk_b, sk_b) = self.generate(seed);
        let e = Poly::<_, (B0, B0, B0)>::random_small(seed, 2);
        let dh = Poly::functor_2(&pk_a.0, &sk_b.0, |pk, sk| pk * sk)
            .reverse_bits()
            .inv_ntt();
        let c = Poly::functor_3(&dh, &e, &v, |dh, e, v| dh + e + v);
        (pk_b, c.compress())
    }

    fn decrypt(
        pk_b: &Self::PublicKey,
        sk_a: &Self::SecretKey,
        cipher: &GenericArray<u8, Self::Cipher>,
    ) -> GenericArray<u8, Self::Plain> {
        let dh = Poly::functor_2(&pk_b.0, &sk_a.0, |pk, sk| pk * sk)
            .reverse_bits()
            .inv_ntt();
        let c = Poly::<_, (B0, B0, B0)>::decompress(cipher);
        let v = Poly::functor_2(&dh, &c, |dh, c| dh - c);
        v.to_message_negate().into()
    }
}

mod codable {
    use super::{Codable, Poly, PolySize, PublicKey, SecretKey};
    use generic_array::{GenericArray, typenum::Unsigned};

    impl<N> Codable for PublicKey<N>
    where
        N: PolySize,
    {
        const SIZE: usize = N::PackedLength::USIZE;

        fn encode(&self, buffer: &mut [u8]) {
            buffer.clone_from_slice(self.0.pack().as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let mut v = GenericArray::default();
            v.clone_from_slice(buffer);
            Poly::unpack(&v).map(PublicKey)
        }
    }

    impl<N> Codable for SecretKey<N>
    where
        N: PolySize,
    {
        const SIZE: usize = N::PackedLength::USIZE;

        fn encode(&self, buffer: &mut [u8]) {
            buffer.clone_from_slice(self.0.pack().as_ref());
        }

        fn decode(buffer: &[u8]) -> Result<Self, ()> {
            let mut v = GenericArray::default();
            v.clone_from_slice(buffer);
            Poly::unpack(&v).map(SecretKey)
        }
    }
}
