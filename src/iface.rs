use tokio::sync::broadcast;

use crate::packet::Packet;

pub mod hdlc;
pub mod kaonic;
pub mod tcp;


pub struct PacketChannel {
    pub in_tx: broadcast::Sender<Packet>,
    pub out_rx: broadcast::Receiver<Packet>,
}

