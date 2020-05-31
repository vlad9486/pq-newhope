use core::marker::PhantomData;

pub trait NewHopeBaseSize {
    const SIZE: usize;

    const SYM: usize = 32;
    const POLY: usize = 14 * Self::SIZE / 8;
    const POLY_COMPRESSED: usize = 3 * Self::SIZE / 8;
}

pub struct Base512;

impl NewHopeBaseSize for Base512 {
    const SIZE: usize = 512;
}

pub struct Base1024;

impl NewHopeBaseSize for Base1024 {
    const SIZE: usize = 1024;
}

pub trait NewHopeSize {
    const PUBLIC_KEY: usize;
    const SECRET_KEY: usize;
    const CIPHER_TEXT: usize;
    const SHARED_SECRET: usize;
}

pub struct Cpakem<B>(PhantomData<B>)
where
    B: NewHopeBaseSize;

impl<B> NewHopeSize for Cpakem<B>
where
    B: NewHopeBaseSize,
{
    const PUBLIC_KEY: usize = B::POLY + B::SYM;
    const SECRET_KEY: usize = B::POLY;
    const CIPHER_TEXT: usize = B::POLY + B::POLY_COMPRESSED;
    const SHARED_SECRET: usize = B::SYM;
}

pub struct Ccakem<B>(PhantomData<B>)
where
    B: NewHopeBaseSize;

impl<B> NewHopeSize for Ccakem<B>
where
    B: NewHopeBaseSize,
{
    const PUBLIC_KEY: usize = <Cpakem<B> as NewHopeSize>::PUBLIC_KEY;
    const SECRET_KEY: usize = 2 * B::POLY + 3 * B::SYM;
    const CIPHER_TEXT: usize = B::POLY + B::POLY_COMPRESSED + B::SYM;
    const SHARED_SECRET: usize = B::SYM;
}

pub trait PublicKey
where
    Self: Sized + AsRef<[u8]>,
{
    type CipherText: Sized + AsRef<[u8]>;
    type SharedSecret: Sized + AsRef<[u8]>;
    type SecretKey: SecretKey<CipherText = Self::CipherText, SharedSecret = Self::SharedSecret>;

    fn pair() -> (Self, Self::SecretKey);
    fn encrypt(&self) -> (Self::CipherText, Self::SharedSecret);
}

pub trait SecretKey
where
    Self: Sized + AsRef<[u8]>,
{
    type CipherText: Sized + AsRef<[u8]>;
    type SharedSecret: Sized + AsRef<[u8]>;

    fn decrypt(&self, cipher_text: &Self::CipherText) -> Self::SharedSecret;
}
