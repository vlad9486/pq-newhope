use rac::{
    Line, LineValid,
    generic_array::{GenericArray, typenum::U1},
};
use sha3::digest::{Update, ExtendableOutput};

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

pub fn h<D, I, O>(input: &I) -> O
where
    D: Default + Update + ExtendableOutput,
    I: LineValid,
    O: Line,
{
    use sha3::digest::XofReader;

    let mut buffer = GenericArray::default();
    D::default()
        .chain(input.clone_line())
        .finalize_xof()
        .read(buffer.as_mut());

    Line::clone_array(&buffer)
}
