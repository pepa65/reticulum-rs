use crate::{
    error::RnsError,
    hash::AddressHash,
    packet::{Header, Packet, PacketContext},
};

trait Serialize {
    fn serialize(&self, buf: &mut [u8]) -> Result<usize, RnsError>;
}

trait Deserialize {
    fn deserialize(&self, buf: &[u8]) -> Result<(), RnsError>;
}

impl Serialize for AddressHash {
    fn serialize(&self, buf: &mut [u8]) -> Result<usize, RnsError> {
        if buf.len() >= self.len() {
            buf[..self.len()].copy_from_slice(self.as_slice());
            Ok(self.len())
        } else {
            Err(RnsError::InvalidArgument)
        }
    }
}

impl Serialize for Header {
    fn serialize(&self, buf: &mut [u8]) -> Result<usize, RnsError> {
        let meta = (self.ifac_flag as u8) << 7
            | (self.header_type as u8) << 6
            | (self.propagation_type as u8) << 4
            | (self.destination_type as u8) << 2
            | (self.packet_type as u8) << 0;

        if buf.len() >= 2 {
            buf[0] = meta;
            buf[1] = self.hops;
            Ok(2)
        } else {
            Err(RnsError::InvalidArgument)
        }
    }
}
impl Serialize for PacketContext {
    fn serialize(&self, buf: &mut [u8]) -> Result<usize, RnsError> {
        if buf.len() >= 1 {
            buf[0] = *self as u8;
            Ok(1)
        } else {
            Err(RnsError::InvalidArgument)
        }
    }
}

impl<'a> Serialize for Packet<'a> {
    fn serialize(&self, buf: &mut [u8]) -> Result<usize, RnsError> {
        let mut buf_offset = 0;

        buf_offset += self.header.serialize(&mut buf[buf_offset..])?;
        buf_offset += self.destination.serialize(&mut buf[buf_offset..])?;

        if let Some(transport) = &self.transport {
            buf_offset += transport.serialize(&mut buf[buf_offset..])?;
        }

        buf_offset += self.context.serialize(&mut buf[buf_offset..])?;

        Ok(buf_offset)
    }
}
