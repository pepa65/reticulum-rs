use crate::{
    buffer::OutputBuffer,
    error::RnsError,
    hash::AddressHash,
    packet::{Header, Packet, PacketContext},
};

pub trait Serialize {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError>;
}

pub trait Deserialize {
    fn deserialize(&self, buf: &[u8]) -> Result<usize, RnsError>;
}

impl Serialize for AddressHash {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(self.as_slice())
    }
}

impl Serialize for Header {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[self.to_meta(), self.hops])
    }
}
impl Serialize for PacketContext {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        buffer.write(&[*self as u8])
    }
}

impl<'a> Serialize for Packet<'a> {
    fn serialize(&self, buffer: &mut OutputBuffer) -> Result<usize, RnsError> {
        self.header.serialize(buffer)?;

        self.destination.serialize(buffer)?;

        if let Some(transport) = &self.transport {
            transport.serialize(buffer)?;
        }

        self.context.serialize(buffer)?;

        buffer.write(self.data)
    }
}

#[cfg(test)]
mod tests {
    use core::str;
    use rand_core::OsRng;

    use crate::{
        buffer::{OutputBuffer, StaticBuffer},
        hash::{AddressHash, Hash},
        packet::{
            DestinationType, Header, HeaderType, IfacFlag, Packet, PacketContext, PacketType,
            PropagationType,
        },
    };

    use super::Serialize;

    #[test]
    fn serialize_packet() {
        let mut output_data = [0u8; 4096];

        let mut buffer = OutputBuffer::new(&mut output_data);

        let packet = Packet {
            header: Header {
                ifac_flag: IfacFlag::Open,
                header_type: HeaderType::Type1,
                propagation_type: PropagationType::Broadcast,
                destination_type: DestinationType::Single,
                packet_type: PacketType::Announce,
                hops: 0,
            },
            ifac: None,
            destination: AddressHash::new_from_rand(OsRng),
            transport: None,
            context: PacketContext::None,
            data: StaticBuffer::new(),
        };

        packet.serialize(&mut buffer).expect("serialized packet");

        println!("{}", buffer);
    }
}
