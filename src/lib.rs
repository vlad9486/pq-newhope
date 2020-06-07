#![no_std]

pub extern crate generic_array;

#[cfg(any(test, feature = "smallest"))]
#[macro_use]
extern crate std;

mod hash;

pub mod pke;
pub mod cpa;
pub mod cca;

#[cfg(test)]
mod test;
