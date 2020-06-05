use core::fmt;
use sha3::{
    Shake256,
    digest::{Input, ExtendableOutput, XofReader},
};

#[derive(Default, Eq, PartialEq)]
pub struct Message(pub [u8; Self::SIZE]);

impl Message {
    pub const SIZE: usize = 32;

    pub fn expand(self, nonce: u8) -> (Message, Message) {
        let mut ext_seed = [0; 33];
        ext_seed[0] = nonce;
        ext_seed[1..33].clone_from_slice(self.as_ref());
        let mut h = Shake256::default().chain(ext_seed.as_ref()).xof_result();
        let mut buffer = [0; 64];
        h.read(&mut buffer);
        let mut public_seed = Message::default();
        public_seed.0.as_mut().clone_from_slice(&buffer[0..32]);
        let mut noise_seed = Message::default();
        noise_seed.0.as_mut().clone_from_slice(&buffer[32..]);
        (public_seed, noise_seed)
    }

    pub fn hash(self) -> Message {
        let mut h = Shake256::default().chain(self.as_ref()).xof_result();
        let mut buffer = [0; 32];
        h.read(&mut buffer);
        Message(buffer)
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Message")
            .field(&hex::encode(self.as_ref()))
            .finish()
    }
}
