pub mod proto {
    tonic::include_proto!("kaonic");
}

use std::sync::Arc;
use std::time::Duration;

use proto::device_client::DeviceClient;
use proto::radio_client::RadioClient;
use proto::RadioFrame;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::iface::{Interface, InterfaceContext, RxMessage};
use crate::packet::Packet;
use crate::serde::Serialize;

use alloc::string::String;

use super::RadioModule;

pub struct KaonicGrpc {
    pub addr: String,
    pub module: RadioModule,
}

impl KaonicGrpc {
    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };
        let module = { context.inner.lock().unwrap().module };

        let iface_address = context.channel.address;

        let (rx_channel, tx_channel) = context.channel.split();

        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let grpc_channel = Channel::from_shared(addr.to_string())
                .unwrap()
                .connect_timeout(Duration::from_secs(30))
                .connect()
                .await;

            if let Err(err) = grpc_channel {
                log::warn!("kaonic_grpc: couldn't connect to <{}> = '{}'", addr, err);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            let grpc_channel = grpc_channel.unwrap();

            let mut radio_client = RadioClient::new(grpc_channel.clone());
            let mut _device_client = DeviceClient::new(grpc_channel.clone());

            let mut recv_stream = radio_client
                .receive_stream(proto::ReceiveRequest {
                    module: module as u32,
                    timeout: 0,
                })
                .await
                .unwrap()
                .into_inner();

            log::info!("kaonic_grpc: connected to <{}>", addr);

            const BUFFER_SIZE: usize = std::mem::size_of::<Packet>() * 2;

            let cancel = context.cancel.clone();
            let stop = CancellationToken::new();

            let rx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let rx_channel = rx_channel.clone();

                tokio::spawn(async move {
                    let mut rx_buffer = [0u8; BUFFER_SIZE];

                    log::trace!("kaonic_grpc: start rx task");

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            }
                            _ = stop.cancelled() => {
                                    break;
                            }
                            Some(result) = recv_stream.next() => {
                                if let Ok(response) = result {
                                    if let Some(frame) = response.frame {
                                        if frame.length > 0 {
                                            if let Ok(buf) = decode_frame_to_buffer(&frame, &mut rx_buffer[..]) {
                                                if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(buf)) {
                                                        let _ = rx_channel.send(RxMessage { address: iface_address, packet }).await;
                                                } else {
                                                    log::warn!("kaonic_grpc: couldn't decode packet");
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    stop.cancel();
                })
            };

            let tx_task = {
                let cancel = cancel.clone();
                let stop = stop.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    let mut tx_buffer = [0u8; BUFFER_SIZE];
                    log::trace!("kaonic_grpc: start tx task");
                    loop {
                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                    break;
                            },
                            _ = stop.cancelled() => {
                                    break;
                            },
                            Some(message) = tx_channel.recv() => {
                                let packet = message.packet;
                                let mut output = OutputBuffer::new(&mut tx_buffer);
                                if let Ok(_) = packet.serialize(&mut output) {

                                    let frame = encode_buffer_to_frame(output.as_mut_slice());

                                    let result = radio_client.transmit(proto::TransmitRequest{
                                        module: module as u32,
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
                        };
                    }

                    stop.cancel();
                })
            };

            tx_task.await.unwrap();
            rx_task.await.unwrap();

            log::info!("kaonic_grpc: disconnected from <{}>", addr);
        }
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

impl Interface for KaonicGrpc {
    fn mtu() -> usize {
        2048
    }
}
