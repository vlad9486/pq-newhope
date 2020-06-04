pub trait PublicKey
where
    Self: Sized + AsRef<[u8]>,
{
    type CipherText: Sized + AsRef<[u8]>;
    type SharedSecret: Sized + AsRef<[u8]>;
    type SecretKey: SecretKey<CipherText = Self::CipherText, SharedSecret = Self::SharedSecret>;

    fn generate() -> (Self, Self::SecretKey);
    fn encapsulate(&self) -> (Self::CipherText, Self::SharedSecret);
}

pub trait SecretKey
where
    Self: Sized + AsRef<[u8]>,
{
    type CipherText: Sized + AsRef<[u8]>;
    type SharedSecret: Sized + AsRef<[u8]>;

    fn decapsulate(&self, cipher_text: &Self::CipherText) -> Self::SharedSecret;
}
