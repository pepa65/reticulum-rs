use rand_core::CryptoRngCore;

use crate::{
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{
        DecryptIdentity, EmptyIdentity, EncryptIdentity, HashIdentity, Identity, PrivateIdentity,
    },
    packet::{DestinationType, Packet},
};

use sha2::{digest::Update, Digest, Sha256};

use core::marker::PhantomData;

//***************************************************************************//

pub trait Direction {}

pub struct Input;
pub struct Output;

impl Direction for Input {}
impl Direction for Output {}

//***************************************************************************//

pub trait Type {
    fn destination_type(&self) -> DestinationType;
}

pub struct Single;
pub struct Plain;
pub struct Group;
pub struct Link;

impl Type for Single {
    fn destination_type(&self) -> DestinationType {
        DestinationType::Single
    }
}

impl Type for Plain {
    fn destination_type(&self) -> DestinationType {
        DestinationType::Plain
    }
}

impl Type for Group {
    fn destination_type(&self) -> DestinationType {
        DestinationType::Group
    }
}

impl Type for Link {
    fn destination_type(&self) -> DestinationType {
        DestinationType::Link
    }
}

pub const NAME_HASH_LENGTH: usize = 10;

pub struct DestinationName<'a> {
    app_name: &'a str,
    aspects: &'a str,
    hash: Hash,
}

impl<'a> DestinationName<'a> {
    pub fn new(app_name: &'a str, aspects: &'a str) -> Self {
        let hash = Hash::new(
            Hash::generator()
                .chain_update(app_name.as_bytes())
                .chain_update(".".as_bytes())
                .chain_update(aspects.as_bytes())
                .finalize()
                .into(),
        );

        Self {
            app_name,
            aspects,
            hash,
        }
    }

    pub fn as_name_hash_slice(&self) -> &[u8] {
        &self.hash.as_slice()[..NAME_HASH_LENGTH]
    }
}

pub struct Destination<'a, I: HashIdentity, D: Direction, T: Type> {
    direction: PhantomData<D>,
    r#type: PhantomData<T>,
    identity: &'a I,
    name: DestinationName<'a>,
    hash: AddressHash,
}

impl<'a, I: DecryptIdentity + HashIdentity, T: Type> Destination<'a, I, Input, T> {
    pub fn decrypt<'b, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        data: &[u8],
        out_buf: &'b mut [u8],
    ) -> Result<&'b [u8], RnsError> {
        self.identity.decrypt(rng, data, out_buf)
    }
}

impl<'a, I: EncryptIdentity + HashIdentity, D: Direction, T: Type> Destination<'a, I, D, T> {
    pub fn encrypt<'b, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        text: &[u8],
        out_buf: &'b mut [u8],
    ) -> Result<&'b [u8], RnsError> {
        self.identity.encrypt(rng, text, out_buf)
    }
}

impl<'a> Destination<'a, PrivateIdentity, Input, Single> {
    pub fn new(identity: &'a PrivateIdentity, name: DestinationName<'a>) -> Self {
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            name,
        }
    }

    pub fn announce<'b>(&self, buf: &'b mut [u8]) -> Result<Packet<'b>, RnsError> {}
}

impl<'a> Destination<'a, Identity, Output, Single> {
    pub fn new(identity: &'a Identity, name: DestinationName<'a>) -> Self {
        let hash = create_hash(identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            name,
            hash,
        }
    }
}

impl<'a, D: Direction> Destination<'a, EmptyIdentity, D, Plain> {
    pub fn new(identity: &'a EmptyIdentity, name: DestinationName<'a>) -> Self {
        let hash = create_hash(identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            name,
            hash,
        }
    }
}

fn create_hash<'a, I: HashIdentity>(identity: &I, name: &DestinationName<'a>) -> AddressHash {
    AddressHash::new_from_hash(&Hash::new(
        Hash::generator()
            .chain_update(name.as_name_hash_slice())
            .chain_update(identity.as_address_hash_slice())
            .finalize()
            .into(),
    ))
}

pub type SingleInputDesination<'a> = Destination<'a, PrivateIdentity, Input, Single>;
pub type SingleOutputDesination<'a> = Destination<'a, Identity, Output, Single>;
pub type PlainInputDesination<'a> = Destination<'a, EmptyIdentity, Input, Plain>;
pub type PlainOutputDesination<'a> = Destination<'a, EmptyIdentity, Output, Plain>;

#[cfg(test)]
mod tests {
    use core::str;
    use rand_core::OsRng;

    use crate::identity::PrivateIdentity;

    use super::DestinationName;
    use super::SingleInputDesination;
    use super::SingleOutputDesination;

    #[test]
    fn create_destinations() {
        let mut identity = PrivateIdentity::new_from_rand(OsRng);

        let mut single_in_destination =
            SingleOutputDesination::new(identity.as_identity(), DestinationName::new("test", "in"));
    }
}
