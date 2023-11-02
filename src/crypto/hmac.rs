use super::Secret;
use borsh::{BorshDeserialize, BorshSerialize};

pub trait Hmac {
    type Sign: AsRef<[u8]> + Clone + core::fmt::Debug + BorshSerialize + BorshDeserialize;
    fn sign(value: &[u8], secret: &Secret) -> Self::Sign;
    fn verify(value: &[u8], sign: &Self::Sign, secret: &Secret) -> bool;
    fn xor(a: Self::Sign, b: Self::Sign) -> Self::Sign;
}

#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl Hmac for Blake3Hasher {
    type Sign = [u8; 32];
    fn sign(value: &[u8], secret: &Secret) -> Self::Sign {
        let mut hasher = blake3::Hasher::new();
        hasher.update(value);
        hasher.update(secret);
        *hasher.finalize().as_bytes()
    }
    fn verify(value: &[u8], sign: &Self::Sign, secret: &Secret) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(value);
        hasher.update(secret);
        hasher.finalize().as_bytes() == sign
    }
    fn xor(mut a: Self::Sign, b: Self::Sign) -> Self::Sign {
        a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a ^= *b);
        a
    }
}
