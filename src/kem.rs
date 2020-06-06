use generic_array::{ArrayLength, GenericArray};
use rac::LineValid;

pub trait Kem {
    type PublicKey: Sized + LineValid;
    type SecretKey: Sized + LineValid;
    type CipherText: Sized + LineValid;
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
