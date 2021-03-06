use core::{
    ops::{Add, Sub, Mul, BitOr, BitAnd},
    marker::PhantomData,
};
use super::poly::{PolyState, Involution};

#[derive(Clone, Default, Debug)]
pub struct Coefficient(u16);

impl PartialEq for Coefficient {
    fn eq(&self, other: &Coefficient) -> bool {
        self.0 % Self::Q == other.0 % Self::Q
    }
}

impl Eq for Coefficient {}

impl Coefficient {
    pub const Q: u16 = 12289;
    const Q_INV: u16 = 12287;
    const R_LOG: u32 = 18;

    pub const MIDDLE: Self = Coefficient(Self::Q / 2);

    pub const QUARTER: Self = Coefficient(Self::Q / 4);

    pub fn freeze(&self) -> i16 {
        let r = (self.0 % Self::Q) as i16;
        let m = r - Self::Q as i16;
        let c = m >> 15;
        m ^ ((r ^ m) & c)
    }

    pub fn new(r: u16) -> Self {
        Coefficient(r)
    }

    pub fn valid_new(r: u16) -> Result<Self, ()> {
        if r < Self::Q {
            Ok(Self::new(r))
        } else {
            Err(())
        }
    }

    pub fn try_new(r: u16) -> Option<Self> {
        if r < (core::u16::MAX / Self::Q) * Self::Q {
            Some(Self::new(r))
        } else {
            None
        }
    }

    pub fn small(s: i8) -> Self {
        Self::new(((Self::Q as i16) + (s as i16)) as u16)
    }

    pub fn flip_abs(&self) -> u16 {
        let r = self.freeze() - ((Self::Q / 2) as i16);
        let m = r >> 15;
        ((r + m) ^ m) as u16
    }

    pub fn montgomery_reduce(x: u32) -> Self {
        use core::num::Wrapping;

        let Wrapping(u) = Wrapping(x) * Wrapping(Self::Q_INV as u32);
        let u = (u & ((1 << Self::R_LOG) - 1)) * (Self::Q as u32);
        Self::new(((x + u) >> Self::R_LOG) as u16)
    }

    pub fn compress(&self) -> u8 {
        let x = self.freeze() as u32;
        let x = ((x << 3) + ((Self::Q / 2) as u32)) / (Self::Q as u32);
        (x & 0x07) as u8
    }

    pub fn decompress(t: u8) -> Self {
        Self::new((((t as u32) * (Self::Q as u32) + 4) >> 3) as u16)
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

pub struct CoefficientRich<S>(pub Coefficient, pub PhantomData<S>)
where
    S: PolyState;

impl<S> CoefficientRich<S>
where
    S: PolyState,
{
    pub fn new(raw: u32) -> Self {
        CoefficientRich(Coefficient::new(raw as u16), PhantomData)
    }
}

impl<O, L, R, D> Add<CoefficientRich<(O, R, D)>> for CoefficientRich<(O, L, D)>
where
    O: Involution,
    L: Involution + BitOr<R>,
    <L as BitOr<R>>::Output: Involution,
    R: Involution,
    D: Involution,
{
    type Output = CoefficientRich<(O, <L as BitOr<R>>::Output, D)>;

    fn add(self, other: CoefficientRich<(O, R, D)>) -> Self::Output {
        CoefficientRich::new((&self.0 + &other.0).data())
    }
}

impl<O, L, R, D> Sub<CoefficientRich<(O, R, D)>> for CoefficientRich<(O, L, D)>
where
    O: Involution,
    L: Involution + BitOr<R>,
    <L as BitOr<R>>::Output: Involution,
    R: Involution,
    D: Involution,
{
    type Output = CoefficientRich<(O, <L as BitOr<R>>::Output, D)>;

    fn sub(self, other: CoefficientRich<(O, R, D)>) -> Self::Output {
        CoefficientRich::new((&self.0 - &other.0).data())
    }
}

impl<O, L, R, D> Mul<CoefficientRich<(O, R, D)>> for CoefficientRich<(O, L, D)>
where
    O: Involution,
    L: Involution + BitAnd<R>,
    <L as BitAnd<R>>::Output: Involution,
    R: Involution,
    D: Involution,
{
    type Output = CoefficientRich<(O, <L as BitAnd<R>>::Output, D)>;

    fn mul(self, other: CoefficientRich<(O, R, D)>) -> Self::Output {
        CoefficientRich::new((&self.0 * &other.0).data())
    }
}
