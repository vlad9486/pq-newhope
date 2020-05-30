#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod test;

mod sys;
mod sizes;

use self::sizes::{Base512, Base1024, Cpakem, Ccakem, NewHopeSize};

use core::fmt;

macro_rules! i {
    ($s:ty, $pk:ident, $sk:ident, $keypair:path, $encrypt:path, $decrypt:path) => {
        #[derive(Clone)]
        pub struct $pk {
            raw: [u8; <$s as NewHopeSize>::PUBLIC_KEY],
        }

        impl fmt::Display for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.raw.as_ref()))
            }
        }

        #[derive(Clone)]
        pub struct $sk {
            raw: [u8; <$s as NewHopeSize>::SECRET_KEY],
        }

        impl fmt::Display for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.raw.as_ref()))
            }
        }

        impl $pk {
            pub fn new() -> (Self, $sk) {
                let mut pk = [0; <$s as NewHopeSize>::PUBLIC_KEY];
                let mut sk = [0; <$s as NewHopeSize>::SECRET_KEY];

                unsafe {
                    $keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
                }

                ($pk { raw: pk }, $sk { raw: sk })
            }

            pub fn encrypt(
                &self,
            ) -> (
                [u8; <$s as NewHopeSize>::CIPHER_TEXT],
                [u8; <$s as NewHopeSize>::SHARED_SECRET],
            ) {
                let mut ct = [0; <$s as NewHopeSize>::CIPHER_TEXT];
                let mut ss = [0; <$s as NewHopeSize>::SHARED_SECRET];

                unsafe {
                    $encrypt(ct.as_mut_ptr(), ss.as_mut_ptr(), self.raw.as_ptr());
                }

                (ct, ss)
            }
        }

        impl $sk {
            pub fn decrypt(
                &self,
                cipher_text: &[u8; <$s as NewHopeSize>::CIPHER_TEXT],
            ) -> [u8; <$s as NewHopeSize>::SHARED_SECRET] {
                let mut ss = [0; <$s as NewHopeSize>::SHARED_SECRET];

                unsafe {
                    $decrypt(ss.as_mut_ptr(), cipher_text.as_ptr(), self.raw.as_ptr());
                }

                ss
            }
        }
    };
}

i!(
    Cpakem::<Base512>,
    PublicKeyCpakem512,
    SecretKeyCpakem512,
    self::sys::p512_crypto_kem_keypair,
    self::sys::p512_crypto_kem_enc,
    self::sys::p512_crypto_kem_dec
);

i!(
    Cpakem::<Base1024>,
    PublicKeyCpakem1024,
    SecretKeyCpakem1024,
    self::sys::p1024_crypto_kem_keypair,
    self::sys::p1024_crypto_kem_enc,
    self::sys::p1024_crypto_kem_dec
);

i!(
    Ccakem::<Base512>,
    PublicKeyCcakem512,
    SecretKeyCcakem512,
    self::sys::c512_crypto_kem_keypair,
    self::sys::c512_crypto_kem_enc,
    self::sys::c512_crypto_kem_dec
);

i!(
    Ccakem::<Base1024>,
    PublicKeyCcakem1024,
    SecretKeyCcakem1024,
    self::sys::c1024_crypto_kem_keypair,
    self::sys::c1024_crypto_kem_enc,
    self::sys::c1024_crypto_kem_dec
);
