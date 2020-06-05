use core::{
    ops::{Add, Sub, Mul},
    num::Wrapping,
};

#[derive(Clone, Default)]
pub struct Coefficient(u16);

impl Coefficient {
    pub const Q: u16 = 12289;
    const Q_INV: u16 = 12287;
    const R_LOG: u32 = 18;

    pub fn freeze(&self) -> i16 {
        let r = (self.0 % Self::Q) as i16;
        let m = r - Self::Q as i16;
        let c = m >> 15;
        m ^ ((r ^ m) & c)
    }

    pub fn new(r: u16) -> Self {
        Coefficient(r)
    }

    pub fn flip_abs(&self) -> u16 {
        let r = self.freeze() - ((Self::Q / 2) as i16);
        let m = r >> 15;
        ((r + m) ^ m) as u16
    }

    pub fn montgomery_reduce(x: u32) -> Self {
        let Wrapping(u) = Wrapping(x) * Wrapping(Self::Q_INV as u32);
        let u = (u & ((1 << Self::R_LOG) - 1)) * (Self::Q as u32);
        Coefficient::new(((x + u) >> Self::R_LOG) as u16)
    }

    pub fn data(&self) -> u32 {
        self.0 as u32
    }
}

impl<'a, 'b> Add<&'b Coefficient> for &'a Coefficient {
    type Output = Coefficient;

    fn add(self, other: &'b Coefficient) -> Self::Output {
        Coefficient::new((self.0 + other.0) % Coefficient::Q)
    }
}

impl<'a, 'b> Sub<&'b Coefficient> for &'a Coefficient {
    type Output = Coefficient;

    fn sub(self, other: &'b Coefficient) -> Self::Output {
        Coefficient::new((self.0 + 3 * Coefficient::Q - other.0) % Coefficient::Q)
    }
}

impl<'a, 'b> Mul<&'b Coefficient> for &'a Coefficient {
    type Output = Coefficient;

    fn mul(self, other: &'b Coefficient) -> Self::Output {
        let t = Coefficient::montgomery_reduce(3186 * other.data());
        Coefficient::montgomery_reduce(t.data() * self.data())
    }
}
