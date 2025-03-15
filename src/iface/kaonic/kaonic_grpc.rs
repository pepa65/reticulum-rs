pub mod proto {
    tonic::include_proto!("kaonic");
}

use std::time::Duration;

use proto::device_client::DeviceClient;
use proto::radio_client::RadioClient;
use proto::RadioFrame;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::{Interface, PacketChannel};
use crate::packet::Packet;
use crate::serde::Serialize;

use alloc::string::String;

use super::RadioModule;

#[derive(Clone)]
pub struct KaonicGrpcConfig {
    pub addr: String,
    pub module: RadioModule,
}

pub struct KaonicGrpc {
    config: KaonicGrpcConfig,
}

pub type KaonicGrpcInterface = Interface<KaonicGrpc>;

impl KaonicGrpcInterface {
    pub fn start(config: KaonicGrpcConfig, channel: PacketChannel) -> Self {
        log::debug!("kaonic_grpc: start new iface <{}>", config.addr);

        let handler = KaonicGrpc { config };

        Interface::<KaonicGrpc>::new(
            handler,
            channel,
            |mut channel, handler, cancel| async move {
                let config = { handler.lock().unwrap().config.clone() };
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }

                    let grpc_channel = Channel::from_shared(config.addr.to_string())
                        .unwrap()
                        .connect_timeout(Duration::from_secs(30))
                        .connect()
                        .await;

                    if let Err(err) = grpc_channel {
                        log::warn!(
                            "kaonic_grpc: couldn't connect to <{}> = '{}'",
                            config.addr,
                            err
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }

                    let grpc_channel = grpc_channel.unwrap();

                    let mut radio_client = RadioClient::new(grpc_channel.clone());
                    let mut _device_client = DeviceClient::new(grpc_channel.clone());

                    let mut recv_stream = radio_client
                        .receive_stream(proto::ReceiveRequest {
                            module: config.module as u32,
                            timeout: 0,
                        })
                        .await
                        .unwrap()
                        .into_inner();

                    log::info!("kaonic_grpc: connected to <{}>", config.addr);

                    loop {
                        const BUFFER_SIZE: usize = std::mem::size_of::<Packet>() * 3;

                        let mut tx_buffer = [0u8; BUFFER_SIZE];
                        let mut rx_buffer = [0u8; BUFFER_SIZE];

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            Some(result) = recv_stream.next() => {
                                if let Ok(response) = result {
                                    if let Some(frame) = response.frame {
                                        if frame.length > 0 {
                                            if let Ok(buf) = decode_frame_to_buffer(&frame, &mut rx_buffer[..]) {
                                                if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(buf)) {
                                                        let _ = channel.send_rx(packet).await;
                                                } else {
                                                    log::warn!("kaonic_grpc: couldn't decode packet");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(packet) = channel.wait_for_tx() => {
                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if let Ok(_) = packet.serialize(&mut output) {

                                    let frame = encode_buffer_to_frame(output.as_mut_slice());

                                    let result = radio_client.transmit(proto::TransmitRequest{
                                        module: config.module as u32,
                                        frame: Some(frame),
                                    }).await;

                                    if let Err(err) = result {
                                        log::warn!("kaonic_grpc: tx err = '{}'", err);
                                        if err.code() == tonic::Code::Unknown || err.code() == tonic::Code::Unavailable {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    log::info!("kaonic_grpc: disconnected from <{}>", config.addr);
                }
            },
        )
    }
}

fn encode_buffer_to_frame(buffer: &mut [u8]) -> RadioFrame {
    // Convert the packet bytes to a list of words
    // TODO: Optimize dynamic allocation
    let words = buffer
        .chunks(4)
        .map(|chunk| {
            let mut work = 0u32;
            let chunk = chunk.iter().as_slice();

            for i in 0..chunk.len() {
                work |= (chunk[i] as u32) << (i * 8);
            }

            work
        })
        .collect::<Vec<_>>();

    proto::RadioFrame {
        data: words,
        length: buffer.len() as u32,
    }
}

fn decode_frame_to_buffer<'a>(
    frame: &RadioFrame,
    buffer: &'a mut [u8],
) -> Result<&'a [u8], RnsError> {
    if buffer.len() < (frame.length as usize) {
        return Err(RnsError::OutOfMemory);
    }

    let length = frame.length as usize;
    let mut index = 0usize;
    for word in &frame.data {
        for i in 0..4 {
            buffer[index] = ((word >> i * 8) & 0xFF) as u8;

            index += 1;

            if index >= length {
                break;
            }
        }

        if index >= length {
            break;
        }
    }

    Ok(&buffer[..length])
}
