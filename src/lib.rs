#[cfg(feature = "alloc")]
extern crate alloc;

pub mod async_io;
pub mod buffer;
pub mod crypt;
pub mod destination;
pub mod error;
pub mod hash;
pub mod identity;
pub mod link;
pub mod packet;
pub mod time;
pub mod transport;

mod serde;
