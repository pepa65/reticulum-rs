use rand_core::{CryptoRngCore, OsRng};

use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::{
        DecryptIdentity, EmptyIdentity, EncryptIdentity, HashIdentity, Identity, PrivateIdentity,
    },
    packet::{
        DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType,
        PropagationType,
    },
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
    pub app_name: &'a str,
    pub aspects: &'a str,
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
    pub name: DestinationName<'a>,
    pub address_hash: AddressHash,
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
        let address_hash = create_address_hash(identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            name,
            address_hash,
        }
    }

    pub fn announce<'b, R: CryptoRngCore + Copy>(
        &self,
        rng: R,
        app_data: Option<&[u8]>,
        buffer: &'b mut OutputBuffer<'b>,
    ) -> Result<Packet<'b>, RnsError> {
        let rand_hash = AddressHash::new_from_hash(&Hash::new_from_rand(rng));

        let address_hash_slice = self.address_hash.as_slice();
        buffer.write(address_hash_slice)?;
        buffer.write(self.identity.as_identity().public_key_bytes())?;
        buffer.write(self.name.as_name_hash_slice())?;
        buffer.write(rand_hash.as_slice())?;

        if let Some(data) = app_data {
            buffer.write(data)?;
        }

        let signature = self.identity.sign(buffer.as_slice())?;

        buffer.write(&signature.to_bytes())?;

        let announce_data = &buffer.as_slice()[address_hash_slice.len()..];

        Ok(Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: &[],
            destination: self.address_hash,
            transport: None,
            context: PacketContext::None,
            data: announce_data,
        })
    }
}

impl<'a> Destination<'a, Identity, Output, Single> {
    pub fn new(identity: &'a Identity, name: DestinationName<'a>) -> Self {
        let address_hash = create_address_hash(identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            name,
            address_hash,
        }
    }
}

impl<'a, D: Direction> Destination<'a, EmptyIdentity, D, Plain> {
    pub fn new(identity: &'a EmptyIdentity, name: DestinationName<'a>) -> Self {
        let address_hash = create_address_hash(identity, &name);
        Self {
            direction: PhantomData,
            r#type: PhantomData,
            identity,
            name,
            address_hash,
        }
    }
}

fn create_address_hash<'a, I: HashIdentity>(
    identity: &I,
    name: &DestinationName<'a>,
) -> AddressHash {
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
    use rand_core::OsRng;

    use crate::buffer::OutputBuffer;
    use crate::identity::PrivateIdentity;
    use crate::serde::Serialize;

    use super::DestinationName;
    use super::SingleInputDesination;

    #[test]
    fn create_announce() {
        let mut identity = PrivateIdentity::new_from_rand(OsRng);

        let mut single_in_destination =
            SingleInputDesination::new(&identity, DestinationName::new("test", "in"));

        let mut announce_packet_data = [0u8; 1024];
        let mut buffer = OutputBuffer::new(&mut announce_packet_data);

        let announce_packet = single_in_destination
            .announce(OsRng, None, &mut buffer)
            .expect("valid announce packet");

        println!("Announce packet {}", announce_packet);
    }

    #[test]
    fn compare_announce() {
        let priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let sign_priv_key: [u8; 32] = [
            0xf0, 0xec, 0xbb, 0xa4, 0x9e, 0x78, 0x3d, 0xee, 0x14, 0xff, 0xc6, 0xc9, 0xf1, 0xe1,
            0x25, 0x1e, 0xfa, 0x7d, 0x76, 0x29, 0xe0, 0xfa, 0x32, 0x41, 0x3c, 0x5c, 0x59, 0xec,
            0x2e, 0x0f, 0x6d, 0x6c,
        ];

        let priv_identity = PrivateIdentity::new(priv_key.into(), sign_priv_key.into());

        let destination = SingleInputDesination::new(
            &priv_identity,
            DestinationName::new("example_utilities", "announcesample.fruits"),
        );

        println!("identity hash {}", priv_identity.as_identity().address_hash);
        println!("destination name hash {}", destination.name.hash);
        println!("destination hash {}", destination.address_hash);

        let mut announce_packet_data = [0u8; 1024];
        let mut buffer = OutputBuffer::new(&mut announce_packet_data);

        let announce = destination
            .announce(OsRng, None, &mut buffer)
            .expect("valid announce packet");

        let mut output_data = [0u8; 4096];
        let mut buffer = OutputBuffer::new(&mut output_data);

        let _ = announce.serialize(&mut buffer).expect("correct data");

        println!("ANNOUNCE {}", buffer);
    }
}
