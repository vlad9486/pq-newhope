#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod test;

mod wrapper;

#[rustfmt::skip]
pub use self::wrapper::{
    PublicKeyCpakem512, PublicKeyCpakem1024, PublicKeyCcakem512, PublicKeyCcakem1024,
    SecretKey, PublicKey,
};
