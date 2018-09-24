//! Implementation of I2P's ElGamal public-key encryption scheme over the
//! 2048-bit MODP DH group.
//!
//! This implementation is not constant-time (yet).

#[macro_use]
extern crate lazy_static;

extern crate num_bigint;
extern crate num_traits;
extern crate rand;
extern crate sha2;

#[cfg(test)]
extern crate data_encoding;

use std::fmt;

mod constants;
mod elgamal;
mod utils;

pub use elgamal::{Decryptor, Encryptor, KeyPairGenerator};

/// The public component of an ElGamal encryption keypair. Represents only the
/// exponent, not the primes (which are constants).
pub struct PublicKey(pub [u8; 256]);

impl PublicKey {
    fn from_bytes(buf: &[u8; 256]) -> Self {
        let mut x = [0u8; 256];
        x.copy_from_slice(buf);
        PublicKey(x)
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(true, |acc, (a, b)| acc && (a == b))
    }
}

/// The private component of an ElGamal encryption keypair.
pub struct PrivateKey(pub [u8; 256]);

impl PrivateKey {
    fn from_bytes(buf: &[u8; 256]) -> Self {
        let mut x = [0u8; 256];
        x.copy_from_slice(buf);
        PrivateKey(x)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey::from_bytes(&self.0)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.0[..].fmt(formatter)
    }
}
