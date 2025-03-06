use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::MutexGuard;

use tokio::sync::broadcast;

use crate::destination::DestinationDesc;
use crate::destination::DestinationHandleStatus;
use crate::destination::DestinationName;
use crate::destination::SingleInputDestination;
use crate::hash::AddressHash;
use crate::identity::PrivateIdentity;
use crate::link::LinkHandleResult;
use crate::packet::DestinationType;
use crate::packet::PacketContext;
use crate::{
    destination::SingleOutputDestination,
    error::RnsError,
    iface::PacketChannel,
    link::Link,
    packet::{Packet, PacketType},
};

/// Precalculated desitnation name for the path request destination
// pub const PATH_REQUEST_DESTINATION_NAME: DestinationName = DestinationName {
//     hash: Hash::new([
//         0x79, 0x26, 0xbb, 0xe7, 0xdd, 0x7f, 0x9a, 0xba, 0x88, 0xb0, 0x61, 0x55, 0x16, 0x00, 0xa2,
//         0x5d, 0x06, 0xef, 0x0f, 0x75, 0x78, 0x20, 0x27, 0x30, 0xbd, 0x2f, 0x22, 0x42, 0x00, 0x71,
//         0x5e, 0xfe,
//     ]),
// };
//
// /// Precalculated desitnation for the path request
// pub const PATH_REQUEST_DESTINATION: PlainOutputDestination = PlainOutputDestination {
//     direction: PhantomData,
//     r#type: PhantomData,
//     identity: EmptyIdentity {},
//     desc: DestinationDesc {
//         name: PATH_REQUEST_DESTINATION_NAME,
//         address_hash: AddressHash::new([
//             0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0,
//             0x27, 0x61,
//         ]),
//         identity: Identity::default(),
//     },
// };

struct TransportHandler {
    in_packet_rx: broadcast::Receiver<Packet>,
    out_packet_tx: broadcast::Sender<Packet>,
    single_in_destinations: HashMap<AddressHash, Arc<Mutex<SingleInputDestination>>>,
    out_links: Vec<Arc<Mutex<Link>>>,
    in_links: HashMap<AddressHash, Arc<Mutex<Link>>>,
}

pub struct Transport {
    in_packet_tx: broadcast::Sender<Packet>,
    in_packet_rx: broadcast::Receiver<Packet>,
    out_packet_tx: broadcast::Sender<Packet>,
    out_packet_rx: broadcast::Receiver<Packet>,
    handler: Arc<Mutex<TransportHandler>>,
}

impl Transport {
    pub fn new() -> Self {
        let (out_packet_tx, out_packet_rx) = tokio::sync::broadcast::channel(32);
        let (in_packet_tx, in_packet_rx) = tokio::sync::broadcast::channel(32);

        let handler = Arc::new(Mutex::new(TransportHandler {
            single_in_destinations: HashMap::new(),
            out_links: Vec::new(),
            in_links: HashMap::new(),
            in_packet_rx: in_packet_tx.subscribe(),
            out_packet_tx: out_packet_tx.clone(),
        }));

        let handler_task = {
            let handler = handler.clone();
            tokio::spawn(manage_transport(handler))
        };

        Self {
            out_packet_tx,
            out_packet_rx,
            in_packet_tx,
            in_packet_rx,
            handler,
        }
    }

    pub fn packet_channel(&self) -> PacketChannel {
        PacketChannel {
            in_tx: self.in_packet_tx.clone(),
            out_rx: self.out_packet_tx.subscribe(),
        }
    }

    pub fn recv(&self) -> broadcast::Receiver<Packet> {
        self.in_packet_tx.subscribe()
    }

    pub fn send(&self, packet: Packet) -> Result<(), RnsError> {
        self.out_packet_tx
            .send(packet)
            .map_err(|_| RnsError::ConnectionError)
            .map(|_| ())
    }

    pub fn link(&self, destination: DestinationDesc) -> Arc<Mutex<Link>> {
        let mut link = Link::new(destination);

        let packet = link.request();

        log::debug!(
            "tp: create new link {} for destination {}",
            link.id(),
            destination
        );

        let link = Arc::new(Mutex::new(link));

        self.send(packet).expect("link request was sent");

        self.handler.lock().unwrap().out_links.push(link.clone());

        link
    }

    pub fn add_destination(
        &mut self,
        identity: PrivateIdentity,
        name: DestinationName,
    ) -> Arc<Mutex<SingleInputDestination>> {
        let destination = SingleInputDestination::new(identity, name);
        let address_hash = destination.desc.address_hash;

        log::debug!("tp: add destination {}", address_hash);

        let destination = Arc::new(Mutex::new(destination));

        self.handler
            .lock()
            .unwrap()
            .single_in_destinations
            .insert(address_hash, destination.clone());

        destination
    }

    // pub fn create_path_request(
    //     destination_hash: &AddressHash,
    //     tag: Option<&[u8]>,
    // ) -> Result<Packet, RnsError> {
    //     let mut data = PacketDataBuffer::new();
    //
    //     data.chain_write(destination_hash.as_slice())?
    //         .chain_write(tag.unwrap_or(&[]))?;
    //
    //     Ok(Packet {
    //         header: Header {
    //             ifac_flag: packet::IfacFlag::Open,
    //             header_type: packet::HeaderType::Type1,
    //             propagation_type: packet::PropagationType::Broadcast,
    //             destination_type: PATH_REQUEST_DESTINATION.destination_type(),
    //             packet_type: packet::PacketType::Data,
    //             hops: 0,
    //         },
    //         ifac: None,
    //         destination: PATH_REQUEST_DESTINATION.desc.address_hash,
    //         transport: None,
    //         context: PacketContext::None,
    //         data,
    //     })
    // }
}

fn handle_proof<'a>(packet: &Packet, handler: &MutexGuard<'a, TransportHandler>) {
    log::trace!("tp: handle proof for {}", packet.destination);

    for link in &handler.out_links {
        let mut link = link.lock().unwrap();
        match link.handle_packet(packet) {
            LinkHandleResult::Activated => {
                let rtt_packet = link.create_rtt();
                handler.out_packet_tx.send(rtt_packet).unwrap();
            }
            _ => {}
        }
    }
}

fn handle_data<'a>(packet: &Packet, handler: &mut MutexGuard<'a, TransportHandler>) {
    log::trace!(
        "tp: handle data request for {} dst={:2x} ctx={:2x}",
        packet.destination,
        packet.header.destination_type as u8,
        packet.context as u8,
    );

    if packet.header.destination_type == DestinationType::Link {
        if let Some(link) = handler.in_links.get(&packet.destination).cloned() {
            let mut link = link.lock().unwrap();
            let _ = link.handle_packet(packet);
        }
    }

    if packet.header.destination_type == DestinationType::Single {
        if let Some(destination) = handler
            .single_in_destinations
            .get(&packet.destination)
            .cloned()
        {

            // todo
        }
    }
}

fn handle_link_request<'a>(packet: &Packet, handler: &mut MutexGuard<'a, TransportHandler>) {
    log::trace!("tp: handle link request for {}", packet.destination);

    if let Some(destination) = handler
        .single_in_destinations
        .get(&packet.destination)
        .cloned()
    {
        let mut destination = destination.lock().unwrap();
        match destination.handle_packet(packet) {
            DestinationHandleStatus::LinkProof(link, packet) => {
                log::trace!("tp: send proof to {}", packet.destination);

                handler.out_packet_tx.send(packet).unwrap();

                handler
                    .in_links
                    .insert(*link.id(), Arc::new(Mutex::new(link)));
            }
            DestinationHandleStatus::None => {}
        }
    }
}

async fn manage_transport(handler: Arc<Mutex<TransportHandler>>) {
    let mut in_packet_rx = {
        let handler = handler.lock().unwrap();
        handler.in_packet_rx.resubscribe()
    };

    loop {
        tokio::select! {
            recv = in_packet_rx.recv() => {
                if let Ok(packet) = recv {

                let handler = &mut handler.lock().unwrap();
                    match packet.header.packet_type {
                        PacketType::Announce => { }
                        PacketType::LinkRequest => handle_link_request(&packet, handler),
                        PacketType::Proof => handle_proof(&packet, handler),
                        PacketType::Data => handle_data(&packet, handler),
                        _ => {}
                    }
                }
            }
        }
    }
}
