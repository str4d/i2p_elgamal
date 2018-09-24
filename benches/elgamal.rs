#![feature(test)]

extern crate i2p_elgamal;
extern crate rand;
extern crate test;

use i2p_elgamal::{Decryptor, Encryptor, KeyPairGenerator};
use rand::{thread_rng, Rng};

#[bench]
fn elgamal_keygen(b: &mut test::Bencher) {
    b.iter(|| KeyPairGenerator::generate());
}

#[bench]
fn elgamal_encryption(b: &mut test::Bencher) {
    let (_, pub_key) = KeyPairGenerator::generate();
    let enc = Encryptor::from(&pub_key);

    let rng = &mut thread_rng();
    let mut msg = [0u8; 222];
    rng.fill(&mut msg[..]);

    b.iter(|| enc.encrypt(&msg));
}

#[bench]
fn elgamal_decryption(b: &mut test::Bencher) {
    let (priv_key, pub_key) = KeyPairGenerator::generate();
    let enc = Encryptor::from(&pub_key);
    let dec = Decryptor::from(&priv_key);

    let rng = &mut thread_rng();
    let mut msg = [0u8; 222];
    rng.fill(&mut msg[..]);
    let ct = enc.encrypt(&msg).unwrap();

    b.iter(|| dec.decrypt(&ct));
}
