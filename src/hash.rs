use rac::{
    Line, LineValid,
    generic_array::{GenericArray, typenum::U1},
};

pub struct B(pub u8);

impl LineValid for B {
    type Length = U1;

    fn try_clone_array(a: &GenericArray<u8, Self::Length>) -> Result<Self, ()> {
        Ok(B(a[0]))
    }

    fn clone_line(&self) -> GenericArray<u8, Self::Length> {
        GenericArray::from([self.0])
    }
}

pub fn h<I, O>(input: &I) -> O
where
    I: LineValid,
    O: Line,
{
    use sha3::{
        Shake256,
        digest::{Update, ExtendableOutput, XofReader},
    };

    let mut buffer = GenericArray::default();
    Shake256::default()
        .chain(input.clone_line())
        .finalize_xof()
        .read(buffer.as_mut());

    Line::clone_array(&buffer)
}
