use generic_array::{ArrayLength, GenericArray};

pub trait Kem {
    type PublicKey: Sized;
    type SecretKey: Sized;
    type CipherText: Sized;
    type SharedSecretLength: ArrayLength<u8>;
    type GenerateSeedLength: ArrayLength<u8>;
    type EncapsulateSeedLength: ArrayLength<u8>;

    fn generate(
        seed: GenericArray<u8, Self::GenerateSeedLength>,
    ) -> (Self::PublicKey, Self::SecretKey);
    fn encapsulate(
        public_key: &Self::PublicKey,
        seed: GenericArray<u8, Self::EncapsulateSeedLength>,
    ) -> (Self::CipherText, GenericArray<u8, Self::SharedSecretLength>);
    fn decapsulate(
        secret_key: &Self::SecretKey,
        cipher_text: &Self::CipherText,
    ) -> GenericArray<u8, Self::SharedSecretLength>;
}
