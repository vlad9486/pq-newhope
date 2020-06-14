#![no_std]

pub use rac::generic_array;

#[cfg(any(test, feature = "smallest"))]
extern crate std;

mod hash;

pub mod poly;
pub mod pke;
pub mod cpa;
pub mod cca;

#[cfg(test)]
mod tests;
