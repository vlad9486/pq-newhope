use super::{
    hash,
    poly::PolySize,
    pke::{Pke, PublicKey, SecretKey, Parameter},
};
use core::{marker::PhantomData, ops::Add};
use rac::{
    LineValid,
    generic_array::{
        GenericArray, ArrayLength,
        typenum::{U32, U64},
    },
};

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
    pk: PublicKeyCca<N>,
    pk_hash: GenericArray<u8, U32>,
    reject: GenericArray<u8, U32>,
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

type PkLength<N> = <<N as PolySize>::PackedLength as Add<U32>>::Output;
type CtLength<N> = <PkLength<N> as Add<<N as PolySize>::CompressedLength>>::Output;

impl<N> Cca<N>
where
    N: PolySize,
    N::PackedLength: Add<U32>,
    PublicKeyCca<N>: Clone + LineValid,
    CipherTextCca<N>: LineValid,
    PkLength<N>: ArrayLength<u8> + Add<N::CompressedLength>,
    CtLength<N>: ArrayLength<u8>,
    Parameter<N>: Pke<
        Seed = U32,
        GenerationSeed = U32,
        Plain = U32,
        Cipher = N::CompressedLength,
        PublicKey = PublicKey<N>,
        SecretKey = SecretKey<N>,
    >,
{
    pub fn generate(seed: &GenericArray<u8, U64>) -> (PublicKeyCca<N>, SecretKeyCca<N>) {
        let mut reject = GenericArray::default();
        reject.clone_from_slice(seed[..32].as_ref());
        let mut cpa_seed = GenericArray::default();
        cpa_seed.clone_from_slice(seed[32..].as_ref());
        let (parameter_seed, pk_seed) = hash::expand(&cpa_seed, 1);
        let parameter = Parameter::new(&parameter_seed);
        let (pk, sk) = parameter.generate(&pk_seed);
        let public_key = PublicKeyCca {
            pk: pk,
            parameter: parameter,
            seed: parameter_seed,
        };
        let mut pk_hash = GenericArray::default();
        let pk_bytes = public_key.clone_line();
        hash::shake256(pk_bytes.as_ref(), pk_hash.as_mut());
        (
            public_key.clone(),
            SecretKeyCca {
                sk: sk,
                pk: public_key,
                pk_hash: pk_hash,
                reject: reject,
            },
        )
    }

    pub fn encapsulate(
        public_key: &PublicKeyCca<N>,
        seed: &GenericArray<u8, U32>,
    ) -> (CipherTextCca<N>, GenericArray<u8, U32>) {
        let mut ext_seed = [0; 0x21];
        ext_seed[0x00] = 0x04;
        ext_seed[0x01..0x21].clone_from_slice(seed.as_ref());

        let mut new_seed = [0; 0x41];
        new_seed[0x00] = 0x08;
        hash::shake256(ext_seed.as_ref(), &mut new_seed[0x01..0x21]);

        let public_key_bytes = public_key.clone_line();
        hash::shake256(public_key_bytes.as_ref(), new_seed[0x21..0x41].as_mut());

        let mut buffer = [0; 0x60];
        hash::shake256(new_seed.as_ref(), buffer.as_mut());

        let mut encryption_seed = GenericArray::default();
        encryption_seed.clone_from_slice(buffer[0x20..0x40].as_ref());

        let mut message = GenericArray::default();
        message.clone_from_slice(new_seed[0x01..0x21].as_ref());
        let (pk_b, ct) = public_key
            .parameter
            .encrypt(&encryption_seed, &public_key.pk, &message);

        let mut hash = GenericArray::default();
        hash.clone_from_slice(buffer[0x40..].as_ref());
        let cipher_text = CipherTextCca {
            pk: pk_b,
            ct: ct,
            check: hash,
        };
        let cipher_text_bytes = cipher_text.clone_line();
        hash::shake256(cipher_text_bytes.as_ref(), buffer[0x20..0x40].as_mut());

        let mut shared_secret = GenericArray::default();
        hash::shake256(buffer[0x00..0x40].as_ref(), shared_secret.as_mut());
        (cipher_text, shared_secret)
    }

    pub fn decapsulate(
        secret_key: &SecretKeyCca<N>,
        cipher_text: &CipherTextCca<N>,
    ) -> GenericArray<u8, U32> {
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

        let message = Parameter::decrypt(&cipher_text.pk, &secret_key.sk, &cipher_text.ct);
        let mut new_seed = [0; 0x41];
        new_seed[0x00] = 0x08;
        new_seed[0x01..0x21].clone_from_slice(message.as_ref());
        new_seed[0x21..0x41].clone_from_slice(secret_key.pk_hash.as_ref());

        let mut buffer = [0; 0x60];
        hash::shake256(new_seed.as_ref(), buffer.as_mut());

        let mut encryption_seed = GenericArray::default();
        encryption_seed.clone_from_slice(buffer[0x20..0x40].as_ref());

        let (pk_b_cmp, ct_cmp) =
            secret_key
                .pk
                .parameter
                .encrypt(&encryption_seed, &secret_key.pk.pk, &message);

        let mut hash = GenericArray::default();
        hash.clone_from_slice(buffer[0x40..].as_ref());
        let cipher_text_cmp = CipherTextCca {
            pk: pk_b_cmp,
            ct: ct_cmp,
            check: hash,
        };

        let cipher_text_bytes = cipher_text.clone_line();
        let cipher_text_cmp_bytes = cipher_text_cmp.clone_line();
        let fail = c_cmp(cipher_text_bytes.as_ref(), cipher_text_cmp_bytes.as_ref());
        let fail = if fail == 0 { 0 } else { 0xff };
        hash::shake256(cipher_text_bytes.as_ref(), buffer[0x20..0x40].as_mut());
        c_mov(
            buffer[0x00..0x20].as_mut(),
            secret_key.reject.as_ref(),
            fail,
        );

        let mut shared_secret = GenericArray::default();
        hash::shake256(buffer[0x00..0x40].as_ref(), shared_secret.as_mut());
        shared_secret
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
        LineValid,
        Concat,
        generic_array::{
            GenericArray,
            typenum::U32,
        },
    };

    type PkBytes<N> = Concat<PublicKey<N>, GenericArray<u8, <Parameter<N> as Pke>::Seed>>;
    type SkHashes = Concat<GenericArray<u8, U32>, GenericArray<u8, U32>>;
    type SkBytes<N> = Concat<Concat<SecretKey<N>, PublicKeyCca<N>>, SkHashes>;
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
            PkBytes::try_clone_array(a)
                .map(|Concat(pk, seed)| {
                    PublicKeyCca {
                        pk: pk,
                        parameter: Parameter::new(&seed),
                        seed: seed,
                    }
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
    {
        type Length = <SkBytes<N> as LineValid>::Length;
        
        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            SkBytes::try_clone_array(a).map(|Concat(Concat(sk, pk), Concat(pk_hash, reject))| {
                SecretKeyCca {
                    sk: sk,
                    pk: pk,
                    pk_hash: pk_hash,
                    reject: reject,
                }
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(
                Concat(self.sk.clone(), self.pk.clone()),
                Concat(self.pk_hash.clone(), self.reject.clone()),
            ).clone_line()
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
            CtBytes::try_clone_array(a).map(|Concat(Concat(pk, ct), check)| {
                CipherTextCca {
                    pk: pk,
                    ct: ct,
                    check: check,
                }
            })
        }

        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(Concat(self.pk.clone(), self.ct.clone()), self.check.clone()).clone_line()
        }
    }
}
