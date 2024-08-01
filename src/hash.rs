use core::fmt;

use sha2::{Digest, Sha256};

pub fn create_hash(data: &[u8], hash: &mut [u8]) {
    hash.copy_from_slice(Sha256::new().chain_update(data).finalize().as_slice());
}

pub struct AddressHash([u8; 16]);

impl AddressHash {
    pub fn new(hash: [u8; 16]) -> Self {
        Self { 0: hash }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut hash = [0u8; 16];
        create_hash(data, &mut hash);
        Self { 0: hash }
    }
}

impl fmt::Display for AddressHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = &self.0;
        write!(f, "{:x}{:x}{:x}{:x}", hash[0], hash[1], hash[2], hash[3])
    }
}
