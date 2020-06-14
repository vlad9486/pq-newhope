use super::coefficient::{Coefficient, CoefficientRich};
use crate::hash;
use core::{
    marker::PhantomData,
    ops::{Mul, Div, Not},
};
use rac::generic_array::{
    GenericArray, ArrayLength,
    typenum::{Unsigned, U8, U14, U3, U1024, U32, Bit, B0, PowerOfTwo, Logarithm2},
};

pub trait PolySize {
    type PolyLength: ArrayLength<Coefficient> + Unsigned;
    type PackedLength: ArrayLength<u8>;
    type CompressedLength: ArrayLength<u8>;
}

impl<N> PolySize for N
where
    N: Div<U8> + PowerOfTwo + ArrayLength<Coefficient> + Unsigned,
    <N as Div<U8>>::Output: Mul<U14> + Mul<U3>,
    <<N as Div<U8>>::Output as Mul<U14>>::Output: ArrayLength<u8>,
    <<N as Div<U8>>::Output as Mul<U3>>::Output: ArrayLength<u8>,
{
    type PolyLength = N;
    type PackedLength = <<N as Div<U8>>::Output as Mul<U14>>::Output;
    type CompressedLength = <<N as Div<U8>>::Output as Mul<U3>>::Output;
}

pub trait Involution
where
    Self: Sized,
{
    type Op: Involution<Op = Self>;
}

impl<T> Involution for T
where
    T: Bit + Not,
    <T as Not>::Output: Bit + Not<Output = T>,
{
    type Op = <T as Not>::Output;
}

pub trait PolyState {
    type BitOrder: Involution;
    type Size: Involution;
    type Domain: Involution;
}

impl<BitOrder, Size, Domain> PolyState for (BitOrder, Size, Domain)
where
    BitOrder: Involution,
    Size: Involution,
    Domain: Involution,
{
    type BitOrder = BitOrder;
    type Size = Size;
    type Domain = Domain;
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Poly<N, S>
where
    N: PolySize,
    S: PolyState,
{
    coefficients: GenericArray<Coefficient, N::PolyLength>,
    phantom_data: PhantomData<S>,
}

impl<N, S> Poly<N, S>
where
    N: PolySize,
    S: PolyState,
{
    const BLOCK_SIZE: usize = 1 << 6;

    pub fn new(coefficients: GenericArray<Coefficient, N::PolyLength>) -> Self {
        Poly {
            coefficients: coefficients,
            phantom_data: PhantomData,
        }
    }

    pub fn pack(&self) -> GenericArray<u8, N::PackedLength> {
        let mut r = GenericArray::default();

        for i in 0..(N::PolyLength::USIZE / 4) {
            let mut t = [0; 4];
            for j in 0..4 {
                t[j] = self.coefficients[4 * i + j].freeze() as u16;
            }

            let r = &mut r[(7 * i)..(7 * (i + 1))];
            r[0] = (t[0] & 0x00ff) as u8;
            r[1] = ((t[0] >> 0x8) | (t[1] << 0x6)) as u8;
            r[2] = (t[1] >> 0x2) as u8;
            r[3] = ((t[1] >> 0xa) | (t[2] << 0x4)) as u8;
            r[4] = (t[2] >> 0x4) as u8;
            r[5] = ((t[2] >> 0xc) | (t[3] << 0x2)) as u8;
            r[6] = (t[3] >> 0x6) as u8;
        }

        r
    }

    pub fn unpack(v: &GenericArray<u8, N::PackedLength>) -> Result<Self, ()> {
        let mut c = GenericArray::default();

        for i in 0..(N::PolyLength::USIZE / 4) {
            let a = |j| v[7 * i + j] as u16;
            let c = &mut c[(4 * i)..(4 * (i + 1))];

            c[0] = Coefficient::valid_new((0x00 >> 0x8) | (a(0) << 0x0) | ((a(1) & 0x3f) << 0x8))?;
            c[1] = Coefficient::valid_new((a(1) >> 0x6) | (a(2) << 0x2) | ((a(3) & 0x0f) << 0xa))?;
            c[2] = Coefficient::valid_new((a(3) >> 0x4) | (a(4) << 0x4) | ((a(5) & 0x03) << 0xc))?;
            c[3] = Coefficient::valid_new((a(5) >> 0x2) | (a(6) << 0x6) | ((0x00 & 0x00) << 0xe))?;
        }

        Ok(Self::new(c))
    }

    pub fn compress(&self) -> GenericArray<u8, N::CompressedLength> {
        let mut a = GenericArray::default();

        for i in 0..(N::PolyLength::USIZE / 8) {
            let mut t = [0; 8];
            for j in 0..8 {
                t[j] = self.coefficients[8 * i + j].compress()
            }

            a[3 * i + 0] = (t[0] >> 0x0) | (t[1] << 0x3) | (t[2] << 0x6);
            a[3 * i + 1] = (t[2] >> 0x2) | (t[3] << 0x1) | (t[4] << 0x4) | (t[5] << 0x7);
            a[3 * i + 2] = (t[5] >> 0x1) | (t[6] << 0x2) | (t[7] << 0x5);
        }

        a
    }

    pub fn decompress(v: &GenericArray<u8, N::CompressedLength>) -> Self {
        let mut c = GenericArray::default();

        for i in 0..(N::PolyLength::USIZE / 8) {
            let a = &v[(3 * i)..(3 * (i + 1))];
            let t = [
                a[0] & 0x07,
                (a[0] >> 0x3) & 0x07,
                (a[0] >> 0x6) | ((a[1] << 0x2) & 0x04),
                (a[1] >> 0x1) & 0x07,
                (a[1] >> 0x4) & 0x07,
                (a[1] >> 0x7) | ((a[2] << 0x1) & 0x06),
                (a[2] >> 0x2) & 0x07,
                (a[2] >> 0x5),
            ];
            for j in 0..8 {
                c[8 * i + j] = Coefficient::decompress(t[j]);
            }
        }

        Self::new(c)
    }

    pub fn functor_2<F, S0, S1>(a: &Poly<N, S0>, b: &Poly<N, S1>, f: F) -> Self
    where
        F: Fn(CoefficientRich<S0>, CoefficientRich<S1>) -> CoefficientRich<S>,
        S0: PolyState,
        S1: PolyState,
    {
        let mut r = GenericArray::default();

        for i in 0..N::PolyLength::USIZE {
            r[i] = f(
                CoefficientRich::new(a.coefficients[i].data()),
                CoefficientRich::new(b.coefficients[i].data()),
            )
            .0;
        }

        Self::new(r)
    }

    pub fn functor_3<F, S0, S1, S2>(a: &Poly<N, S0>, b: &Poly<N, S1>, c: &Poly<N, S2>, f: F) -> Self
    where
        F: Fn(CoefficientRich<S0>, CoefficientRich<S1>, CoefficientRich<S2>) -> CoefficientRich<S>,
        S0: PolyState,
        S1: PolyState,
        S2: PolyState,
    {
        let mut r = GenericArray::default();
        for i in 0..N::PolyLength::USIZE {
            r[i] = f(
                CoefficientRich::new(a.coefficients[i].data()),
                CoefficientRich::new(b.coefficients[i].data()),
                CoefficientRich::new(c.coefficients[i].data()),
            )
            .0;
        }
        Self::new(r)
    }
}

pub trait FromSeed {
    fn from_message(message: &GenericArray<u8, U32>) -> Self;
    fn to_message_negate(&self) -> GenericArray<u8, U32>;
    fn random(seed: &GenericArray<u8, U32>) -> Self;
}

pub trait FromSeedSmall {
    fn random_small(seed: &GenericArray<u8, U32>, nonce: u8) -> Self;
}

impl<N, S> FromSeed for Poly<N, S>
where
    N: PolySize,
    S: PolyState,
{
    fn from_message(message: &GenericArray<u8, U32>) -> Self {
        let mut c = GenericArray::default();

        for i in 0..N::PolyLength::USIZE {
            let l = i % 256;
            if (message[l / 8] & (1 << (l % 8))) != 0 {
                c[i] = Coefficient::MIDDLE;
            }
        }

        Self::new(c)
    }

    fn to_message_negate(&self) -> GenericArray<u8, U32> {
        const BITS: usize = 256;
        let mut t = [0; BITS];
        let mut message = GenericArray::default();

        for i in 0..N::PolyLength::USIZE {
            t[i % BITS] += self.coefficients[i].flip_abs() as u32;
        }

        for l in 0..BITS {
            let quarter = Coefficient::QUARTER.data();
            if t[l] < (quarter * (N::PolyLength::USIZE as u32) / (BITS as u32)) {
                message[l / 8] |= 1 << (l % 8);
            }
        }

        message
    }

    fn random(seed: &GenericArray<u8, U32>) -> Self {
        use core::slice;
        use keccak::f1600;

        let mut c = GenericArray::default();

        for i in 0..(N::PolyLength::USIZE / Self::BLOCK_SIZE) {
            let mut state = [0; 0x19];
            {
                let buffer =
                    unsafe { slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 0xa8) };
                buffer[0x00..0x20].clone_from_slice(seed.as_ref());
                buffer[0x20] = i as u8;
                buffer[0x21] = 0x1f;
                buffer[0xa7] = 0x80;
                f1600(&mut state);
            }
            let mut counter = 0;
            'block: loop {
                let buffer =
                    unsafe { slice::from_raw_parts_mut(state.as_mut_ptr() as *mut u8, 0xa8) };
                for chunk in buffer.chunks(2) {
                    let r = (chunk[0] as u16) | ((chunk[1] as u16) << 8);
                    match Coefficient::try_new(r) {
                        Some(t) => {
                            c[Self::BLOCK_SIZE * i + counter] = t;
                            counter += 1;
                        },
                        None => (),
                    };
                    if counter == Self::BLOCK_SIZE {
                        break 'block;
                    }
                }
                f1600(&mut state);
            }
        }

        Self::new(c)
    }
}

impl<N, S> FromSeedSmall for Poly<N, S>
where
    N: PolySize,
    S: PolyState<Size = B0>,
{
    fn random_small(seed: &GenericArray<u8, U32>, nonce: u8) -> Self {
        let mut c = GenericArray::default();

        let mut ext_seed = [0; 34];
        ext_seed[0..32].clone_from_slice(seed.as_ref());
        ext_seed[32] = nonce;

        for i in 0..(N::PolyLength::USIZE / Self::BLOCK_SIZE) {
            ext_seed[33] = i as u8;

            // Compute the Hamming weight of a byte
            let hw = |b: u8| -> i8 { (0..8).map(|i| ((b >> i) & 1) as i8).sum() };

            let mut buffer = [0; Self::BLOCK_SIZE * 2];
            hash::shake256(ext_seed.as_ref(), buffer.as_mut());
            for j in 0..Self::BLOCK_SIZE {
                c[Self::BLOCK_SIZE * i + j] =
                    Coefficient::small(hw(buffer[2 * j]) - hw(buffer[2 * j + 1]));
            }
        }

        Self::new(c)
    }
}

pub trait ReverseBits {
    type Output: ReverseBits;

    fn reverse_bits(self) -> Self::Output;
}

impl<N, S> ReverseBits for Poly<N, S>
where
    N: PolySize,
    N::PolyLength: Logarithm2,
    <N::PolyLength as Logarithm2>::Output: Unsigned,
    S: PolyState,
{
    type Output = Poly<N, (<S::BitOrder as Involution>::Op, S::Size, S::Domain)>;

    fn reverse_bits(self) -> Self::Output {
        let mut s = Poly::new(self.coefficients);

        for i in 0..1024 {
            let (j, _) = (0..<N::PolyLength as Logarithm2>::Output::USIZE)
                .fold((0, i), |(y, x), _| (y * 2 + x % 2, x / 2));
            if i < j {
                let temp = s.coefficients[i].clone();
                s.coefficients[i] = s.coefficients[j].clone();
                s.coefficients[j] = temp;
            }
        }

        s
    }
}

pub trait Ntt {
    type Output: Ntt;

    fn ntt(self) -> Self::Output;
    fn inv_ntt(self) -> Self::Output;
}

fn multiply<N, S>(s: Poly<N, S>, gammas: &[u16]) -> Poly<N, S>
where
    N: PolySize,
    S: PolyState,
{
    let mut s = s;

    for i in 0..N::PolyLength::USIZE {
        s.coefficients[i] =
            Coefficient::montgomery_reduce((gammas[i] as u32) * s.coefficients[i].data());
    }

    s
}

fn transform<BitOrder, Size, Domain>(
    s: Poly<U1024, (BitOrder, Size, Domain)>,
    omegas: &[u16],
) -> Poly<U1024, (BitOrder::Op, Size, Domain::Op)>
where
    BitOrder: Involution,
    Size: Involution,
    Domain: Involution,
{
    let mut s = Poly::new(s.coefficients);

    for i in 0..10 {
        let distance = 1 << i;
        for start in 0..distance {
            let mut jt_widdle = 0;
            let mut j = start;
            loop {
                let w = omegas[jt_widdle] as u32;
                jt_widdle += 1;
                let temp = s.coefficients[j].clone();
                s.coefficients[j] = &temp + &s.coefficients[j + distance];
                s.coefficients[j + distance] = Coefficient::montgomery_reduce(
                    w * (&temp - &s.coefficients[j + distance]).data(),
                );
                j += 2 * distance;
                if j >= 1023 {
                    break;
                }
            }
        }
    }

    s
}

impl<BitOrder, Size, Domain> Ntt for Poly<U1024, (BitOrder, Size, Domain)>
where
    BitOrder: Involution,
    Size: Involution,
    Domain: Involution,
{
    type Output = Poly<U1024, (BitOrder::Op, Size, Domain::Op)>;

    fn ntt(self) -> Self::Output {
        let s = multiply(self, super::tables::GAMMAS_BITREV_MONTGOMERY.as_ref());
        transform(s, super::tables::GAMMAS_BITREV_MONTGOMERY.as_ref())
    }

    fn inv_ntt(self) -> Self::Output {
        let s = transform(self, super::tables::OMEGAS_INV_BITREV_MONTGOMERY.as_ref());
        multiply(s, super::tables::GAMMAS_INV_MONTGOMERY.as_ref())
    }
}

impl<S> Poly<U1024, S>
where
    S: PolyState,
{
    #[cfg(feature = "smallest")]
    pub fn smallest(&self) -> std::vec::Vec<u8> {
        use num_bigint::ToBigUint;

        let mut q = 0u8.to_biguint().unwrap();
        for i in 0..1024 {
            q *= Coefficient::Q;
            q += self.coefficients[i].freeze() as u16
        }

        q.to_bytes_le()
    }

    #[cfg(feature = "smallest")]
    pub fn from_smallest(v: &[u8]) -> Self {
        use num_bigint::BigUint;
        use num_traits::ToPrimitive;

        let mut q = BigUint::from_bytes_le(v);
        let mut c = GenericArray::default();
        for i in 0..1024 {
            c[1023 - i] = Coefficient::new((&q % Coefficient::Q).to_u16().unwrap());
            q /= Coefficient::Q;
        }

        Self::new(c)
    }
}

#[cfg(test)]
mod tests {
    use super::{Poly, FromSeed, ReverseBits, Ntt};
    use rac::generic_array::{
        GenericArray,
        sequence::GenericSequence,
        typenum::{U1024, B0, B1},
    };

    #[cfg(feature = "smallest")]
    #[test]
    fn smallest() {
        let poly = Poly::<U1024, (B0, B1, B0)>::random(&GenericArray::generate(|_| rand::random()));
        let dump = poly.smallest();
        let poly_new = Poly::<U1024, (B0, B1, B0)>::from_smallest(dump.as_ref());
        assert_eq!(poly, poly_new);
        assert!(dump.len() <= 1739);
    }

    #[test]
    fn ntt() {
        let poly = Poly::<U1024, (B0, B1, B0)>::random(&GenericArray::generate(|_| rand::random()));
        let poly_new = poly.clone().ntt().reverse_bits().inv_ntt().reverse_bits();

        assert_eq!(poly.coefficients, poly_new.coefficients);
    }
}
