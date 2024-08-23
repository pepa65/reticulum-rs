use core::cmp;
use core::fmt;

use crypto_common::typenum::Unsigned;
use crypto_common::OutputSizeUser;
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = <<Sha256 as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
pub const ADDRESS_HASH_SIZE: usize = 16;

pub fn create_hash(data: &[u8], out: &mut [u8]) {
    out.copy_from_slice(
        &Sha256::new().chain_update(data).finalize().as_slice()[..cmp::min(out.len(), HASH_SIZE)],
    );
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Hash([u8; HASH_SIZE]);

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct AddressHash([u8; ADDRESS_HASH_SIZE]);

impl Hash {
    pub fn generator() -> Sha256 {
        Sha256::new()
    }

    pub fn new(hash: [u8; HASH_SIZE]) -> Self {
        Self { 0: hash }
    }

    pub fn new_empty() -> Self {
        Self {
            0: [0u8; HASH_SIZE],
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }

    pub fn new_from_rand<R: CryptoRngCore>(mut rng: R) -> Self {
        let mut hash = [0u8; HASH_SIZE];
        let mut data = [0u8; HASH_SIZE];

        rng.fill_bytes(&mut data[..]);

        create_hash(&data, &mut hash);
        Self { 0: hash }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AddressHash {
    pub fn new(hash: [u8; ADDRESS_HASH_SIZE]) -> Self {
        Self { 0: hash }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; ADDRESS_HASH_SIZE];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }

    pub fn new_from_hash(hash: &Hash) -> Self {
        let mut address_hash = [0u8; ADDRESS_HASH_SIZE];
        address_hash.copy_from_slice(&hash.0[0..ADDRESS_HASH_SIZE]);
        Self { 0: address_hash }
    }

    pub fn new_from_rand<R: CryptoRngCore>(rng: R) -> Self {
        Self::new_from_hash(&Hash::new_from_rand(rng))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for data in self.0.iter() {
            write!(f, "{:0>2x}", data)?;
        }

        Ok(())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for data in self.0.iter() {
            write!(f, "{:0>2x}", data)?;
        }

        Ok(())
    }
}
