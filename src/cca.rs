use super::{
    traits::Kem,
    hash,
    poly::{Packable, Compressible},
    cpa::{Cpa, PublicKeyCpa, SecretKeyCpa, CipherTextCpa},
};
use core::marker::PhantomData;
use generic_array::{
    GenericArray,
    typenum::{Unsigned, U32},
};
use rac::{LineValid, Line, Concat};

pub struct Cca<N>(PhantomData<N>)
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>;

#[derive(Clone)]
pub struct PublicKeyCca<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
{
    pub(crate) inner: PublicKeyCpa<N>,
}

#[derive(Clone)]
pub struct SecretKeyCca<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
{
    pub(crate) inner: SecretKeyCpa<N>,
    pub(crate) public_key: PublicKeyCpa<N>,
    pub(crate) public_key_hash: GenericArray<u8, U32>,
    pub(crate) reject: GenericArray<u8, U32>,
}

#[derive(Clone)]
pub struct CipherTextCca<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
{
    pub(crate) inner: CipherTextCpa<N>,
    pub(crate) h: GenericArray<u8, U32>,
}

type GenerateSeed<N> = 
    Concat<GenericArray<u8, <Cpa<N> as Kem>::GenerateSeedLength>, GenericArray<u8, U32>>;

impl<N> Kem for Cca<N>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    Cpa<N>: Kem<PublicKey = PublicKeyCpa<N>, SecretKey = SecretKeyCpa<N>>,
    GenerateSeed<N>: Line,
    PublicKeyCpa<N>: LineValid,
    SecretKeyCpa<N>: LineValid,
    PublicKeyCca<N>: LineValid,
    SecretKeyCca<N>: LineValid,
    CipherTextCca<N>: LineValid,
{
    type PublicKey = PublicKeyCca<N>;
    type SecretKey = SecretKeyCca<N>;
    type CipherText = CipherTextCca<N>;
    type SharedSecretLength = U32;
    type GenerateSeedLength = <GenerateSeed<N> as LineValid>::Length;
    type EncapsulateSeedLength = U32;

    fn generate(
        seed: GenericArray<u8, Self::GenerateSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey) {
        let Concat(seed, reject) = Line::clone_array(&seed);
        let (public_key_cpa, secret_key_cpa) = Cpa::<N>::generate(seed);
        let mut public_key_hash = GenericArray::default();
        let public_key_bytes = public_key_cpa.clone_line();
        hash::shake256(public_key_bytes.as_ref(), public_key_hash.as_mut());
        (
            PublicKeyCca {
                inner: public_key_cpa.clone(),
            },
            SecretKeyCca {
                inner: secret_key_cpa,
                public_key: public_key_cpa,
                public_key_hash: public_key_hash,
                reject: reject,
            }
        )
    }

    fn encapsulate(
        public_key: &Self::PublicKey,
        seed: GenericArray<u8, Self::EncapsulateSeedLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>) {
        let mut data = [0; 0x21];
        data[0x01] = 0x04;
        data[0x01..0x21].clone_from_slice(seed.as_ref());

        let mut new_seed = [0; 0x41];
        new_seed[0x01] = 0x08;
        hash::shake256(data.as_ref(), &mut new_seed[0x01..0x21]);

        let mut public_key_hash = [0; 0x20];
        let public_key_bytes = public_key.inner.clone_line();
        hash::shake256(public_key_bytes.as_ref(), public_key_hash.as_mut());
        new_seed[0x21..0x41].clone_from_slice(public_key_hash.as_ref());

        let mut buffer = [0; 0x60];
        hash::shake256(new_seed.as_ref(), buffer.as_mut());

        unimplemented!()
    }

    fn decapsulate(
        secret_key: &Self::SecretKey,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength> {
        let _ = (secret_key, cipher_text);
        unimplemented!()
    }
}

mod proofs {
    use super::{
        hash,
        Packable, Compressible,
        PublicKeyCpa, SecretKeyCpa, CipherTextCpa,
        PublicKeyCca, SecretKeyCca, CipherTextCca,
    };
    use generic_array::{
        GenericArray,
        typenum::{Unsigned, U32},
    };
    use rac::{LineValid, Concat};
    
    impl<N> LineValid for PublicKeyCca<N>
    where
        N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
        PublicKeyCpa<N>: LineValid,
    {
        type Length = <PublicKeyCpa<N> as LineValid>::Length;
    
        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            PublicKeyCpa::try_clone_array(a).map(|pk_cpa| {
                PublicKeyCca {
                    inner: pk_cpa,
                }
            })
        }
    
        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            self.inner.clone_line()
        }
    }
    
    type SecretKeyCpaPublicKeyCpaBytes<N> = Concat<
        SecretKeyCpa<N>,
        GenericArray<u8, <PublicKeyCpa<N> as LineValid>::Length>,
    >;

    type SecretKeyCcaLineValid<N> = Concat<SecretKeyCpaPublicKeyCpaBytes<N>, GenericArray<u8, U32>>;
    
    impl<N> LineValid for SecretKeyCca<N>
    where
        N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
        SecretKeyCpa<N>: LineValid,
        PublicKeyCpa<N>: LineValid,
        SecretKeyCpaPublicKeyCpaBytes<N>: LineValid,
        SecretKeyCcaLineValid<N>: LineValid,
    {
        type Length = <SecretKeyCcaLineValid<N> as LineValid>::Length;
    
        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            SecretKeyCcaLineValid::<N>::try_clone_array(a)
                .and_then(|Concat(Concat(secret_key_cpa, public_key_cpa_array), reject)| {
                    let mut public_key_cpa_bytes_hash = GenericArray::default();
                    hash::shake256(
                        public_key_cpa_array.as_ref(),
                        public_key_cpa_bytes_hash.as_mut(),
                    );
                    LineValid::try_clone_array(&public_key_cpa_array)
                        .map(|public_key| {
                            SecretKeyCca {
                                inner: secret_key_cpa,
                                public_key: public_key,
                                public_key_hash: public_key_cpa_bytes_hash,
                                reject: reject,
                            }
                        })
                })
        }
    
        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            let public_key_cpa_bytes = self.public_key.clone_line();
            Concat(Concat(self.inner.clone(), public_key_cpa_bytes), self.reject.clone()).clone_line()
        }
    }
    
    type CipherTextCcaLineValid<N> = Concat<CipherTextCpa<N>, GenericArray<u8, U32>>;
    
    impl<N> LineValid for CipherTextCca<N>
    where
        N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
        CipherTextCpa<N>: LineValid,
        CipherTextCcaLineValid<N>: LineValid,
    {
        type Length = <CipherTextCcaLineValid<N> as LineValid>::Length;
    
        fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
            CipherTextCcaLineValid::<N>::try_clone_array(a)
                .map(|Concat(inner, h)| {
                    CipherTextCca {
                        inner: inner,
                        h: h,
                    }
                })
        }
    
        fn clone_line(&self) -> GenericArray<u8, Self::Length> {
            Concat(self.inner.clone(), self.h.clone()).clone_line()
        }
    }
}
