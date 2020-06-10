use super::coefficient::Coefficient;
use crate::hash;
use core::{
    marker::PhantomData,
    ops::{Mul, Div, BitXor},
};
use generic_array::{
    GenericArray, ArrayLength,
    typenum::{Unsigned, U8, U14, U3, U1024, Bit, B1, PowerOfTwo},
};

pub trait Packable {
    type PolyLength: ArrayLength<Coefficient>;
    type PackedLength: ArrayLength<u8>;
    type CompressedLength: ArrayLength<u8>;

    fn pack(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::PackedLength>;

    fn unpack(
        v: &GenericArray<u8, Self::PackedLength>,
    ) -> Result<GenericArray<Coefficient, Self::PolyLength>, ()>;

    fn compress(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::CompressedLength>;

    fn decompress(
        v: &GenericArray<u8, Self::CompressedLength>,
    ) -> GenericArray<Coefficient, Self::PolyLength>;
}

impl<N> Packable for N
where
    N: Div<U8> + PowerOfTwo + ArrayLength<Coefficient> + Unsigned,
    <N as Div<U8>>::Output: Mul<U14> + Mul<U3>,
    <<N as Div<U8>>::Output as Mul<U14>>::Output: ArrayLength<u8> + Unsigned,
    <<N as Div<U8>>::Output as Mul<U3>>::Output: ArrayLength<u8> + Unsigned,
{
    type PolyLength = N;
    type PackedLength = <<N as Div<U8>>::Output as Mul<U14>>::Output;
    type CompressedLength = <<N as Div<U8>>::Output as Mul<U3>>::Output;

    fn pack(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::PackedLength> {
        let mut r = GenericArray::default();

        for i in 0..(N::USIZE / 4) {
            let mut t = [0; 4];
            for j in 0..4 {
                t[j] = v[4 * i + j].freeze() as u16;
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

    fn unpack(
        v: &GenericArray<u8, Self::PackedLength>,
    ) -> Result<GenericArray<Coefficient, Self::PolyLength>, ()> {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE / 4) {
            let a = |j| v[7 * i + j] as u16;
            let c = &mut c[(4 * i)..(4 * (i + 1))];

            c[0] = Coefficient::valid_new((0x00 >> 0x8) | (a(0) << 0x0) | ((a(1) & 0x3f) << 0x8))?;
            c[1] = Coefficient::valid_new((a(1) >> 0x6) | (a(2) << 0x2) | ((a(3) & 0x0f) << 0xa))?;
            c[2] = Coefficient::valid_new((a(3) >> 0x4) | (a(4) << 0x4) | ((a(5) & 0x03) << 0xc))?;
            c[3] = Coefficient::valid_new((a(5) >> 0x2) | (a(6) << 0x6) | ((0x00 & 0x00) << 0xe))?;
        }

        Ok(c)
    }

    fn compress(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::CompressedLength> {
        let mut a = GenericArray::default();

        for i in 0..(N::USIZE / 8) {
            let mut t = [0; 8];
            for j in 0..8 {
                t[j] = v[8 * i + j].compress()
            }

            a[3 * i + 0] = (t[0] >> 0x0) | (t[1] << 0x3) | (t[2] << 0x6);
            a[3 * i + 1] = (t[2] >> 0x2) | (t[3] << 0x1) | (t[4] << 0x4) | (t[5] << 0x7);
            a[3 * i + 2] = (t[5] >> 0x1) | (t[6] << 0x2) | (t[7] << 0x5);
        }

        a
    }

    fn decompress(
        v: &GenericArray<u8, Self::CompressedLength>,
    ) -> GenericArray<Coefficient, Self::PolyLength> {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE / 8) {
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

        c
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Poly<N, R>
where
    N: Packable,
    R: Bit,
{
    coefficients: GenericArray<Coefficient, N::PolyLength>,
    phantom_data: PhantomData<R>,
}

impl<N, R> Poly<N, R>
where
    N: Packable,
    R: Bit,
{
    const BLOCK_SIZE: usize = 1 << 6;

    pub fn new(coefficients: GenericArray<Coefficient, N::PolyLength>) -> Self {
        Poly {
            coefficients: coefficients,
            phantom_data: PhantomData,
        }
    }

    pub fn pack(&self) -> GenericArray<u8, N::PackedLength> {
        N::pack(&self.coefficients)
    }

    pub fn unpack(v: &GenericArray<u8, N::PackedLength>) -> Result<Self, ()> {
        N::unpack(v).map(Self::new)
    }

    pub fn compress(&self) -> GenericArray<u8, N::CompressedLength> {
        N::compress(&self.coefficients)
    }

    pub fn decompress(v: &GenericArray<u8, N::CompressedLength>) -> Self {
        Self::new(N::decompress(v))
    }

    pub fn functor_2<F>(a: &Self, b: &Self, f: F) -> Self
    where
        F: Fn(&Coefficient, &Coefficient) -> Coefficient,
    {
        let mut r = GenericArray::default();

        for i in 0..N::PolyLength::USIZE {
            r[i] = f(&a.coefficients[i], &b.coefficients[i]);
        }

        Self::new(r)
    }

    pub fn functor_3<F>(a: &Self, b: &Self, c: &Self, f: F) -> Self
    where
        F: Fn(&Coefficient, &Coefficient, &Coefficient) -> Coefficient,
    {
        let mut r = GenericArray::default();
        for i in 0..N::PolyLength::USIZE {
            r[i] = f(&a.coefficients[i], &b.coefficients[i], &c.coefficients[i]);
        }
        Self::new(r)
    }
}

pub trait FromSeed {
    fn from_message(message: &[u8; 32]) -> Self;
    fn to_message_negate(&self) -> [u8; 32];
    fn random(seed: &[u8; 32]) -> Self;
    fn random_small(seed: &[u8; 32], nonce: u8) -> Self;
}

impl<N, R> FromSeed for Poly<N, R>
where
    N: Packable,
    R: Bit,
{
    fn from_message(message: &[u8; 32]) -> Self {
        let mut c = GenericArray::default();

        for i in 0..N::PolyLength::USIZE {
            let l = i % 256;
            if (message[l / 8] & (1 << (l % 8))) != 0 {
                c[i] = Coefficient::MIDDLE;
            }
        }

        Self::new(c)
    }

    fn to_message_negate(&self) -> [u8; 32] {
        const BITS: usize = 256;
        let mut t = [0; BITS];
        let mut message = [0; 32];

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

    fn random(seed: &[u8; 32]) -> Self {
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

    fn random_small(seed: &[u8; 32], nonce: u8) -> Self {
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

pub trait Ntt {
    type Output: Ntt;

    fn reverse_bits(self) -> Self::Output;
    fn ntt(self) -> Self::Output;
    fn inv_ntt(self) -> Self::Output;
}

impl<R> Poly<U1024, R>
where
    R: Bit + BitXor<B1>,
    <R as BitXor<B1>>::Output: Bit + BitXor<B1, Output = R>,
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

    fn multiply(self, gammas: &[u16]) -> Self {
        let mut s = self;

        for i in 0..1024 {
            s.coefficients[i] = Coefficient::montgomery_reduce(
                (gammas[i] as u32) * (s.coefficients[i].data() as u32),
            );
        }

        s
    }

    fn transform(self, omegas: &[u16]) -> Poly<U1024, <R as BitXor<B1>>::Output> {
        let mut s = Poly::new(self.coefficients);

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
}

impl<R> Ntt for Poly<U1024, R>
where
    R: Bit + BitXor<B1>,
    <R as BitXor<B1>>::Output: Bit + BitXor<B1, Output = R>,
{
    type Output = Poly<U1024, <R as BitXor<B1>>::Output>;

    fn reverse_bits(self) -> Self::Output {
        let mut s = Poly::new(self.coefficients);

        for i in 0..1024 {
            let j = super::tables::BITREV[i] as usize;
            if i < j {
                let temp = s.coefficients[i].clone();
                s.coefficients[i] = s.coefficients[j].clone();
                s.coefficients[j] = temp;
            }
        }

        s
    }

    fn ntt(self) -> Self::Output {
        self.multiply(super::tables::GAMMAS_BITREV_MONTGOMERY.as_ref())
            .transform(super::tables::GAMMAS_BITREV_MONTGOMERY.as_ref())
    }

    fn inv_ntt(self) -> Self::Output {
        self.transform(super::tables::OMEGAS_INV_BITREV_MONTGOMERY.as_ref())
            .multiply(super::tables::GAMMAS_INV_MONTGOMERY.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::{Poly, FromSeed, Ntt};
    use generic_array::typenum::{U1024, B0};

    #[cfg(feature = "smallest")]
    #[test]
    fn smallest() {
        let poly = Poly::<U1024, B0>::random(&rand::random());
        let dump = poly.smallest();
        let poly_new = Poly::<U1024, B0>::from_smallest(dump.as_ref());
        assert_eq!(poly, poly_new);
        assert!(dump.len() <= 1739);
    }

    #[test]
    fn ntt() {
        let poly = Poly::<U1024, B0>::random(&rand::random());
        let poly_new = poly.clone().ntt().reverse_bits().inv_ntt().reverse_bits();

        assert_eq!(poly.coefficients, poly_new.coefficients);
    }
}
