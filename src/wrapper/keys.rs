pub use crate::{PublicKey, SecretKey};
use super::sizes::{Base512, Base1024, Cpakem, Ccakem, NewHopeSize};

use core::fmt;

macro_rules! a {
    ($t:ident, $length:expr) => {
        #[derive(Clone)]
        pub struct $t {
            raw: [u8; $length],
        }

        impl AsRef<[u8]> for $t {
            fn as_ref(&self) -> &[u8] {
                &self.raw
            }
        }

        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(self.as_ref()))
            }
        }

        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($t))
                    .field(&hex::encode(self.as_ref()))
                    .finish()
            }
        }

        impl $t {
            fn zero() -> Self {
                $t { raw: [0; $length] }
            }

            #[allow(dead_code)]
            fn as_ptr(&self) -> *const u8 {
                self.raw.as_ptr()
            }

            fn as_mut_ptr(&mut self) -> *mut u8 {
                self.raw.as_mut_ptr()
            }
        }

        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.raw
                    .iter()
                    .zip(other.raw.iter())
                    .fold(true, |acc, (&l, &r)| acc && (l == r))
            }
        }
    };
}

macro_rules! i {
    ($s:ty, $pk:ident, $sk:ident, $ct:ident, $ss:ident, $keypair:path, $encrypt:path, $decrypt:path) => {
        a!($pk, <$s as NewHopeSize>::PUBLIC_KEY);
        a!($sk, <$s as NewHopeSize>::SECRET_KEY);
        a!($ct, <$s as NewHopeSize>::CIPHER_TEXT);
        a!($ss, <$s as NewHopeSize>::SHARED_SECRET);

        impl PublicKey for $pk {
            type CipherText = $ct;
            type SharedSecret = $ss;
            type SecretKey = $sk;

            fn pair() -> (Self, $sk) {
                let mut pk = $pk::zero();
                let mut sk = $sk::zero();

                unsafe {
                    $keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
                }
                (pk, sk)
            }

            fn encrypt(&self) -> (Self::CipherText, Self::SharedSecret) {
                let mut ct = $ct::zero();
                let mut ss = $ss::zero();

                unsafe {
                    $encrypt(ct.as_mut_ptr(), ss.as_mut_ptr(), self.as_ptr());
                }
                (ct, ss)
            }
        }

        impl SecretKey for $sk {
            type CipherText = $ct;
            type SharedSecret = $ss;

            fn decrypt(&self, cipher_text: &Self::CipherText) -> Self::SharedSecret {
                let mut ss = $ss::zero();

                unsafe {
                    $decrypt(ss.as_mut_ptr(), cipher_text.as_ptr(), self.as_ptr());
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
    CipherTextCpakem512,
    SharedSecretCpakem512,
    super::sys::p512_crypto_kem_keypair,
    super::sys::p512_crypto_kem_enc,
    super::sys::p512_crypto_kem_dec
);

i!(
    Cpakem::<Base1024>,
    PublicKeyCpakem1024,
    SecretKeyCpakem1024,
    CipherTextCpakem1024,
    SharedSecretCpakem1024,
    super::sys::p1024_crypto_kem_keypair,
    super::sys::p1024_crypto_kem_enc,
    super::sys::p1024_crypto_kem_dec
);

i!(
    Ccakem::<Base512>,
    PublicKeyCcakem512,
    SecretKeyCcakem512,
    CipherTextCcakem512,
    SharedSecretCcakem512,
    super::sys::c512_crypto_kem_keypair,
    super::sys::c512_crypto_kem_enc,
    super::sys::c512_crypto_kem_dec
);

i!(
    Ccakem::<Base1024>,
    PublicKeyCcakem1024,
    SecretKeyCcakem1024,
    CipherTextCcakem1024,
    SharedSecretCcakem1024,
    super::sys::c1024_crypto_kem_keypair,
    super::sys::c1024_crypto_kem_enc,
    super::sys::c1024_crypto_kem_dec
);
