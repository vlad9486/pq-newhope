use super::{
    message::Message,
    coefficient::Coefficient,
};
use core::{
    marker::PhantomData,
    ops::{Mul, Div, Add, Sub, BitXor},
};
use generic_array::{
    GenericArray, ArrayLength,
    typenum::{U8, U14, U3, Bit, B1, U1024},
};

pub struct Poly<N, R>
where
    N: ArrayLength<Coefficient>,
    R: Bit,
{
    coefficients: GenericArray<Coefficient, N>,
    phantom_data: PhantomData<R>,
}

pub struct PolyCompressed<N, R>
where
    N: Div<U8>,
    <N as Div<U8>>::Output: Mul<U3>,
    <<N as Div<U8>>::Output as Mul<U3>>::Output: ArrayLength<u8>,
    R: Bit,
{
    coefficients: GenericArray<u8, <<N as Div<U8>>::Output as Mul<U3>>::Output>,
    phantom_data: PhantomData<R>,
}

impl<N, R> Poly<N, R>
where
    Coefficient: Default,
    N: ArrayLength<Coefficient> + Div<U8>,
    <N as Div<U8>>::Output: Mul<U14> + Mul<U3>,
    <<N as Div<U8>>::Output as Mul<U14>>::Output: ArrayLength<u8>,
    <<N as Div<U8>>::Output as Mul<U3>>::Output: ArrayLength<u8>,
    R: Bit,
{
    const BLOCK_SIZE: usize = 1 << 6;

    pub fn from_bytes(bytes: &GenericArray<u8, <<N as Div<U8>>::Output as Mul<U14>>::Output>) -> Self {
        assert!((N::USIZE & (N::USIZE - 1)) == 0, "should be power of two");

        assert!(
            N::USIZE < Self::BLOCK_SIZE * 256,
            "block has {} coefficients, index of the block should fit in byte",
            Self::BLOCK_SIZE,
        );

        let mut c = GenericArray::default();
        for i in 0..(N::USIZE / 4) {
            let a = |j| bytes[7 * i + j] as u16;
            let c = &mut c[(4 * i)..(4 * (i + 1))];

            c[0] = Coefficient::new((0x00 >> 0x8) | (a(0) << 0x0) | ((a(1) & 0x3f) << 0x8));
            c[1] = Coefficient::new((a(1) >> 0x6) | (a(2) << 0x2) | ((a(3) & 0x0f) << 0xa));
            c[2] = Coefficient::new((a(3) >> 0x4) | (a(4) << 0x4) | ((a(5) & 0x03) << 0xc));
            c[3] = Coefficient::new((a(5) >> 0x2) | (a(6) << 0x6) | ((0x00 & 0x00) << 0xe));
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }

    pub fn bytes(&self) -> GenericArray<u8, <<N as Div<U8>>::Output as Mul<U14>>::Output> {
        let mut a = GenericArray::default();

        for i in 0..(N::USIZE / 4) {
            // memorize?
            let t = |j: usize| -> u16 {
                let c: &Coefficient = &self.coefficients[4 * i + j];
                c.freeze() as u16
            };
            let r = &mut a[(7 * i)..(7 * (i + 1))];
            r[0] = (t(0) & 0x00ff) as u8;
            r[1] = ((t(0) >> 0x8) | (t(1) << 0x6)) as u8;
            r[2] = (t(1) >> 0x2) as u8;
            r[3] = ((t(1) >> 0xa) | (t(2) << 0x4)) as u8;
            r[4] = (t(2) >> 0x4) as u8;
            r[5] = ((t(2) >> 0xc) | (t(3) << 0x2)) as u8;
            r[6] = (t(3) >> 0x6) as u8;
        }

        a
    }

    pub fn compress(&self) -> PolyCompressed<N, R> {
        let mut a = GenericArray::default();

        for i in 0..(N::USIZE / 8) {
            // memorize?
            let t = |j: usize| -> u8 {
                let c: &Coefficient = &self.coefficients[8 * i + j];
                let x = c.freeze() as u32;
                let x = ((x << 3) + ((Coefficient::Q / 2) as u32)) / (Coefficient::Q as u32);
                (x & 0x07) as u8
            };

            a[3 * i + 0] = (t(0) >> 0x0) | (t(1) << 0x3) | (t(2) << 0x6);
            a[3 * i + 1] = (t(2) >> 0x2) | (t(3) << 0x1) | (t(4) << 0x4) | (t(5) << 0x7);
            a[3 * i + 2] = (t(5) >> 0x1) | (t(6) << 0x2) | (t(7) << 0x5);
        }

        PolyCompressed {
            coefficients: a,
            phantom_data: PhantomData,
        }
    }

    pub fn decompress(p: &PolyCompressed<N, R>) -> Self {
        let mut c = GenericArray::default();

        for i in 0..(N::USIZE / 8) {
            let a = &p.coefficients[(3 * i)..(3 * (i + 1))];
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
                c[8 * i + j] = Coefficient::new((((t[j] as u32) * (Coefficient::Q as u32) + 4) >> 3) as u16);
            }
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }

    pub fn from_message(message: &Message) -> Self {
        let mut c = GenericArray::default();

        for i in 0..N::USIZE {
            let l = i % 256;
            if (message.0[l / 8] & (1 << (l % 8))) != 0 {
                c[i] = Coefficient::new(Coefficient::Q / 2);
            }
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }

    pub fn to_message(&self) -> Message {
        let mut t = [0; 256];
        let mut message = Message::default();

        for i in 0..N::USIZE {
            t[i % 256] += self.coefficients[i].flip_abs() as u32;
        }

        for l in 0..256 {
            if t[l] < (((Coefficient::Q as usize) * N::USIZE / 1024) as u32) {
                message.0[l / 8] |= 1 << (l % 8);
            }
        }

        message
    }

    pub fn uniform(seed: &Message) -> Self {
        use sha3::{
            Shake128,
            digest::{Input, ExtendableOutput, XofReader},
        };

        let mut c = GenericArray::default();

        let mut ext_seed = [0; 33];
        ext_seed[0..32].clone_from_slice(seed.0.as_ref());
        for i in 0..(N::USIZE / Self::BLOCK_SIZE) {
            ext_seed[32] = i as u8;
            let mut h = Shake128::default().chain(ext_seed.as_ref()).xof_result();
            let mut counter = 0;
            'block: loop {
                let mut buffer = [0; 168];
                h.read(buffer.as_mut());
                for chunk in buffer.chunks(2) {
                    let coefficient = (chunk[0] as u16) | ((chunk[1] as u16) << 8);
                    if coefficient < (core::u16::MAX / Coefficient::Q) * Coefficient::Q {
                        c[Self::BLOCK_SIZE * i + counter] = Coefficient::new(coefficient);
                        counter += 1;
                    }
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

    pub fn sample(seed: &Message, nonce: u8) -> Self {
        use sha3::{
            Shake256,
            digest::{Input, ExtendableOutput, XofReader},
        };

        let mut c = GenericArray::default();

        let mut ext_seed = [0; 34];
        ext_seed[0..32].clone_from_slice(seed.0.as_ref());
        ext_seed[32] = nonce;

        for i in 0..(N::USIZE / Self::BLOCK_SIZE) {
            ext_seed[33] = i as u8;

            // Compute the Hamming weight of a byte
            let hw = |b: u8| -> u16 { (0..8).map(|i| ((b >> i) & 1) as u16).sum() };

            let mut h = Shake256::default().chain(ext_seed.as_ref()).xof_result();
            let mut buffer = [0; Self::BLOCK_SIZE * 2];
            h.read(buffer.as_mut());
            for j in 0..Self::BLOCK_SIZE {
                let r = hw(buffer[2 * j]) + Coefficient::Q - hw(buffer[2 * j + 1]);
                c[Self::BLOCK_SIZE * i + j] = Coefficient::new(r);
            }
        }

        Poly {
            coefficients: c,
            phantom_data: PhantomData,
        }
    }
}

impl<'a, 'b, N, R> Add<&'b Poly<N, R>> for &'a Poly<N, R>
where
    Coefficient: Default,
    N: ArrayLength<Coefficient>,
    R: Bit,
{
    type Output = Poly<N, R>;

    fn add(self, other: &'b Poly<N, R>) -> Self::Output {
        let mut c = GenericArray::default();

        for i in 0..N::USIZE {
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
    Coefficient: Default,
    N: ArrayLength<Coefficient>,
    R: Bit,
{
    type Output = Poly<N, R>;

    fn sub(self, other: &'b Poly<N, R>) -> Self::Output {
        let mut c = GenericArray::default();

        for i in 0..N::USIZE {
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
    Coefficient: Default,
    N: ArrayLength<Coefficient>,
    R: Bit,
{
    type Output = Poly<N, R>;

    fn mul(self, other: &'b Poly<N, R>) -> Self::Output {
        let mut c = GenericArray::default();

        for i in 0..N::USIZE {
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

impl<R> Poly<U1024, R>
where
    Coefficient: Default + Clone,
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

    fn transform(self, omegas: &[u16]) -> Poly<U1024, <R as BitXor<B1>>::Output> {
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

impl<R> Ntt for Poly<U1024, R>
where
    Coefficient: Default + Clone,
    R: Bit + BitXor<B1>,
    <R as BitXor<B1>>::Output: Bit + BitXor<B1, Output = R>,
{
    type Output = Poly<U1024, <R as BitXor<B1>>::Output>;

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
