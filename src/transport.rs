use alloc::sync::Arc;
use core::marker::PhantomData;
use rand_core::CryptoRngCore;

use crate::{
    async_io::{self, AsyncMytex},
    destination::{DestinationName, PlainOutputDesination},
    error::RnsError,
    hash::{AddressHash, Hash},
    identity::EmptyIdentity,
    link::{Link, LinkStatus},
    packet::{self, Header, Packet, PacketContext, PacketDataBuffer},
};

/// Precalculated desitnation name for the path request destination
pub const PATH_REQUEST_DESTINATION_NAME: DestinationName = DestinationName {
    app_name: "rnstransport",
    aspects: "path.request",
    hash: Hash::new([
        0x79, 0x26, 0xbb, 0xe7, 0xdd, 0x7f, 0x9a, 0xba, 0x88, 0xb0, 0x61, 0x55, 0x16, 0x00, 0xa2,
        0x5d, 0x06, 0xef, 0x0f, 0x75, 0x78, 0x20, 0x27, 0x30, 0xbd, 0x2f, 0x22, 0x42, 0x00, 0x71,
        0x5e, 0xfe,
    ]),
};

/// Precalculated desitnation for the path request
pub const PATH_REQUEST_DESTINATION: PlainOutputDesination = PlainOutputDesination {
    direction: PhantomData,
    r#type: PhantomData,
    identity: &EmptyIdentity {},
    name: PATH_REQUEST_DESTINATION_NAME,
    address_hash: AddressHash::new([
        0x6b, 0x9f, 0x66, 0x01, 0x4d, 0x98, 0x53, 0xfa, 0xab, 0x22, 0x0f, 0xba, 0x47, 0xd0, 0x27,
        0x61,
    ]),
};

pub struct Transport<R: CryptoRngCore> {
    pending_links: AsyncMytex<Vec<Arc<Link<R>>>>,
}

impl<R: CryptoRngCore> Transport<R> {
    pub fn new() -> Self {
        Self {
            pending_links: AsyncMytex::new(Vec::new()),
        }
    }

    pub fn create_path_request<'a>(
        destination_hash: &AddressHash,
        tag: Option<&[u8]>,
    ) -> Result<Packet<'a>, RnsError> {
        let mut data = PacketDataBuffer::new();

        data.chain_write(destination_hash.as_slice())?
            .chain_write(tag.unwrap_or(&[]))?;

        Ok(Packet {
            header: Header {
                ifac_flag: packet::IfacFlag::Open,
                header_type: packet::HeaderType::Type1,
                propagation_type: packet::PropagationType::Broadcast,
                destination_type: PATH_REQUEST_DESTINATION.destination_type(),
                packet_type: packet::PacketType::Data,
                hops: 0,
            },
            ifac: None,
            destination: PATH_REQUEST_DESTINATION.address_hash,
            transport: None,
            context: PacketContext::None,
            data,
        })
    }
}

async fn update_pending_links<R: CryptoRngCore>(transport: Arc<Transport<R>>) {
    loop {
        {
            let mut pending_links = transport.pending_links.lock().await;
            pending_links.retain(|link| link.status() != LinkStatus::Closed);
        }

        async_io::async_sleep(core::time::Duration::from_secs(5)).await;
    }
}
