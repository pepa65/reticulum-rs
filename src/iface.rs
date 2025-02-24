pub mod hdlc;
pub mod kaonic;

use crate::error::RnsError;
use crate::packet::Packet;

pub trait Interface {
    fn send(&mut self, packet: &Packet) -> Result<(), RnsError>;
    fn recv(&mut self) -> Result<Packet, RnsError>;
}
