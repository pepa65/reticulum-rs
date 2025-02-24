pub mod kaonic_grpc;

pub const RADIO_FRAME_MAX_SIZE: usize = 2048usize;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum RadioModule {
    RadioA = 0x00,
    RadioB = 0x01,
}
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct RadioConfig {
    pub freq: u32, // kHz
    pub channel: u32,
    pub channel_spacing: u32, // kHz
}
