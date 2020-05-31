#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod test;

mod traits;
pub mod wrapper;

pub use self::traits::{PublicKey, SecretKey};
