#![no_std]

pub use rac::generic_array;

#[cfg(any(test, feature = "smallest"))]
extern crate std;

mod hash;
pub use self::hash::h;

pub mod poly;

mod pke;
pub use self::pke::{Pke, Parameter};

mod cpa;
pub use self::cpa::Cpa;

mod cca;
pub use self::cca::Cca;

#[cfg(test)]
mod tests;
