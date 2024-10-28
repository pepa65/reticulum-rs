use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
use rand_core::CryptoRngCore;
use x25519_dalek::PublicKey;

use crate::{crypt::fernet::Fernet, hash::AddressHash, packet::Packet};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum LinkStatus {
    Pending = 0x00,
    Handshake = 0x01,
    Active = 0x02,
    Stale = 0x03,
    Closed = 0x04,
}

pub type LinkId = AddressHash;

impl From<Packet<'_>> for LinkId {
    fn from(packet: Packet) -> Self {
        packet.hash().into()
    }
}

pub struct PublicLink {
    pub public_key: PublicKey,
    pub verifying_key: VerifyingKey,
}

pub type PublicLinkData = [u8; 32 + 32];

impl PublicLink {

    pub fn new(public_key: PublicKey, verifying_key: VerifyingKey) -> Self {
        Self {
            public_key,
            verifying_key,
        }
    }

    pub fn from_data(data: PublicLinkData) -> Self {
        let mut key_bytes = [0u8; PUBLIC_KEY_LENGTH];

        key_bytes[..].copy_from_slice(&data[..PUBLIC_KEY_LENGTH]);
        let public_key = PublicKey::from(key_bytes);

        key_bytes[..].copy_from_slice(&data[PUBLIC_KEY_LENGTH..]);
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).unwrap_or(VerifyingKey::default());

        Self {
            public_key,
            verifying_key,
        }
    }

    pub fn to_data(&self) -> PublicLinkData {
        let mut data = [0u8; 32 + 32];

        data[..32].copy_from_slice(self.public_key.as_bytes());
        data[32..].copy_from_slice(self.verifying_key.as_bytes());

        data
    }
}

pub struct Link<R: CryptoRngCore> {
    fernet: Fernet<R>,
    status: LinkStatus,
}

impl<R: CryptoRngCore> Link<R> {

    pub fn status(&self) -> LinkStatus {
        self.status
    }
}


