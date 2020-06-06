use super::coefficient::Coefficient;
use crate::hash;
use core::{
    marker::PhantomData,
    ops::{Mul, Add, Sub, BitXor},
};
use generic_array::{
    GenericArray, ArrayLength,
    typenum::{Unsigned, U8, U14, U3, Bit, B1, U128},
};

pub trait Packable {
    type PolyLength: ArrayLength<Coefficient>;

    type PackedLength: ArrayLength<u8>;

    fn pack(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::PackedLength>;

    fn unpack(
        v: &GenericArray<u8, Self::PackedLength>,
    ) -> Result<GenericArray<Coefficient, Self::PolyLength>, ()>;
}

pub trait Compressible {
    type PolyLength: ArrayLength<Coefficient>;

    type CompressedLength: ArrayLength<u8>;

    fn compress(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::CompressedLength>;

    fn decompress(
        v: &GenericArray<u8, Self::CompressedLength>,
    ) -> GenericArray<Coefficient, Self::PolyLength>;
}

pub trait FromSeed {
    fn from_message(message: &[u8; 32]) -> Self;
    fn to_message_negate(&self) -> [u8; 32];
    fn random(seed: &[u8; 32]) -> Self;
    fn random_small(seed: &[u8; 32], nonce: u8) -> Self;
}

#[derive(Clone)]
pub struct Poly<N, R>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength>,
    R: Bit,
{
    coefficients: GenericArray<Coefficient, <N as Compressible>::PolyLength>,
    phantom_data: PhantomData<R>,
}

impl<N> Packable for N
where
    N: Mul<U8> + Mul<U14> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U14>>::Output: ArrayLength<u8>,
{
    type PolyLength = <N as Mul<U8>>::Output;
    type PackedLength = <N as Mul<U14>>::Output;

    fn pack(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::PackedLength> {
        let mut r = GenericArray::default();

        for i in 0..(N::USIZE * 2) {
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

        for i in 0..(N::USIZE * 2) {
            let a = |j| v[7 * i + j] as u16;
            let c = &mut c[(4 * i)..(4 * (i + 1))];

            c[0] = Coefficient::valid_new((0x00 >> 0x8) | (a(0) << 0x0) | ((a(1) & 0x3f) << 0x8))?;
            c[1] = Coefficient::valid_new((a(1) >> 0x6) | (a(2) << 0x2) | ((a(3) & 0x0f) << 0xa))?;
            c[2] = Coefficient::valid_new((a(3) >> 0x4) | (a(4) << 0x4) | ((a(5) & 0x03) << 0xc))?;
            c[3] = Coefficient::valid_new((a(5) >> 0x2) | (a(6) << 0x6) | ((0x00 & 0x00) << 0xe))?;
        }

        Ok(c)
    }
}

impl<N> Compressible for N
where
    N: Mul<U8> + Mul<U3> + Unsigned,
    <N as Mul<U8>>::Output: ArrayLength<Coefficient>,
    <N as Mul<U3>>::Output: ArrayLength<u8>,
{
    type PolyLength = <N as Mul<U8>>::Output;
    type CompressedLength = <N as Mul<U3>>::Output;

    fn compress(
        v: &GenericArray<Coefficient, Self::PolyLength>,
    ) -> GenericArray<u8, Self::CompressedLength> {
        let mut a = GenericArray::default();

        for i in 0..N::USIZE {
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

        for i in 0..N::USIZE {
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

impl<N, R> FromSeed for Poly<N, R>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    R: Bit,
{
    fn from_message(message: &[u8; 32]) -> Self {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE * 8) {
            let l = i % 256;
            if (message[l / 8] & (1 << (l % 8))) != 0 {
                c[i] = Coefficient::MIDDLE;
            }
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }

    fn to_message_negate(&self) -> [u8; 32] {
        const BITS: usize = 256;
        let coefficients = N::USIZE * 8;
        let mut t = [0; BITS];
        let mut message = [0; 32];

        for i in 0..coefficients {
            t[i % BITS] += self.coefficients[i].flip_abs() as u32;
        }

        for l in 0..BITS {
            if t[l] < (Coefficient::QUARTER.data() * (coefficients as u32) / (BITS as u32)) {
                message[l / 8] |= 1 << (l % 8);
            }
        }

        message
    }

    fn random(seed: &[u8; 32]) -> Self {
        use sha3::{
            Shake128,
            digest::{Input, ExtendableOutput, XofReader},
        };

        let mut c = GenericArray::default();

        let mut ext_seed = [0; 33];
        ext_seed[0..32].clone_from_slice(seed.as_ref());
        for i in 0..((N::USIZE * 8) / Self::BLOCK_SIZE) {
            ext_seed[32] = i as u8;
            let mut h = Shake128::default().chain(ext_seed.as_ref()).xof_result();
            let mut counter = 0;
            'block: loop {
                let mut buffer = [0; 168];
                h.read(buffer.as_mut());
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
            }
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }

    fn random_small(seed: &[u8; 32], nonce: u8) -> Self {
        let mut c = GenericArray::default();

        let mut ext_seed = [0; 34];
        ext_seed[0..32].clone_from_slice(seed.as_ref());
        ext_seed[32] = nonce;

        for i in 0..((N::USIZE * 8) / Self::BLOCK_SIZE) {
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

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }
}

impl<N, R> Poly<N, R>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    R: Bit,
{
    const BLOCK_SIZE: usize = 1 << 6;

    pub fn rt_check() {
        assert!((N::USIZE & (N::USIZE - 1)) == 0, "should be power of two");
        assert!(
            N::USIZE * 8 < Self::BLOCK_SIZE * 256,
            "block has {} coefficients, index of the block should fit in byte",
            Self::BLOCK_SIZE,
        );
    }

    pub fn pack(&self) -> GenericArray<u8, N::PackedLength> {
        N::pack(&self.coefficients)
    }

    pub fn unpack(v: &GenericArray<u8, N::PackedLength>) -> Result<Self, ()> {
        N::unpack(v)
            .map(|v| {
                Poly {
                    coefficients: v,
                    phantom_data: PhantomData,
                }
            })
    }

    pub fn compress(&self) -> GenericArray<u8, <N as Compressible>::CompressedLength> {
        N::compress(&self.coefficients)
    }

    pub fn decompress(v: &GenericArray<u8, <N as Compressible>::CompressedLength>) -> Self {
        Poly {
            coefficients: N::decompress(v),
            phantom_data: PhantomData,
        }
    }
}

impl<'a, 'b, N, R> Add<&'b Poly<N, R>> for &'a Poly<N, R>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    R: Bit,
{
    type Output = Poly<N, R>;

    fn add(self, other: &'b Poly<N, R>) -> Self::Output {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE * 8) {
            c[i] = &self.coefficients[i] + &other.coefficients[i];
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }
}

impl<'a, 'b, N, R> Sub<&'b Poly<N, R>> for &'a Poly<N, R>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    R: Bit,
{
    type Output = Poly<N, R>;

    fn sub(self, other: &'b Poly<N, R>) -> Self::Output {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE * 8) {
            c[i] = &self.coefficients[i] - &other.coefficients[i];
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }
}

impl<'a, 'b, N, R> Mul<&'b Poly<N, R>> for &'a Poly<N, R>
where
    N: Packable + Compressible<PolyLength = <N as Packable>::PolyLength> + Unsigned,
    R: Bit,
{
    type Output = Poly<N, R>;

    fn mul(self, other: &'b Poly<N, R>) -> Self::Output {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE * 8) {
            c[i] = &self.coefficients[i] * &other.coefficients[i];
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }
}

pub trait Ntt {
    type Output: Ntt;

    fn reverse_bits(self) -> Self::Output;
    fn ntt(self) -> Self::Output;
    fn inv_ntt(self) -> Self::Output;
}

impl<R> Poly<U128, R>
where
    R: Bit + BitXor<B1>,
    <R as BitXor<B1>>::Output: Bit + BitXor<B1, Output = R>,
{
    fn multiply(self, gammas: &[u16]) -> Self {
        let mut s = self;

        for i in 0..1024 {
            let a = (s.coefficients[i].data() as u32) * (gammas[i] as u32);
            s.coefficients[i] = Coefficient::montgomery_reduce(a);
        }

        s
    }

    fn transform(self, omegas: &[u16]) -> Poly<U128, <R as BitXor<B1>>::Output> {
        let mut s = Poly {
            coefficients: self.coefficients,
            phantom_data: PhantomData,
        };

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

impl<R> Ntt for Poly<U128, R>
where
    Coefficient: Default + Clone,
    R: Bit + BitXor<B1>,
    <R as BitXor<B1>>::Output: Bit + BitXor<B1, Output = R>,
{
    type Output = Poly<U128, <R as BitXor<B1>>::Output>;

    fn reverse_bits(self) -> Self::Output {
        let mut s = Poly {
            coefficients: self.coefficients,
            phantom_data: PhantomData,
        };

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
