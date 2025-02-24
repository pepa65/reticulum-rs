pub mod proto {
    tonic::include_proto!("kaonic");
}

use proto::device_client::DeviceClient;
use proto::radio_client::RadioClient;

use tokio::sync::broadcast;
use tokio::sync::mpsc;

use tokio_stream::StreamExt;
use tonic::transport::Channel;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::packet::Packet;
use crate::serde::Serialize;

use crate::iface::kaonic::RadioConfig;
use crate::iface::kaonic::RadioModule;
use crate::iface::Interface;

const TX_BUFFER_SIZE: usize = 4096;

pub struct KaonicGrpc {
    radio_client: RadioClient<Channel>,
    device_client: DeviceClient<Channel>,
    tx_buffer: [u8; TX_BUFFER_SIZE],
    rx_task: tokio::task::JoinHandle<Result<(), RnsError>>,
    packet_rx: tokio::sync::mpsc::Receiver<Packet>,
    module: RadioModule,
}

fn convert_frame_to_packet(frame: &proto::RadioFrame) -> Result<Packet, RnsError> {
    let mut buffer = [0u8; crate::iface::kaonic::RADIO_FRAME_MAX_SIZE];
    let mut convert_buffer = OutputBuffer::new(&mut buffer);

    let mut buffer = InputBuffer::new(convert_buffer.as_slice());
    Packet::deserialize(&mut buffer)
}

impl KaonicGrpc {
    pub async fn new(address: &str, module: RadioModule) -> Result<Self, RnsError> {
        let channel = Channel::from_shared(address.to_string())
            .unwrap()
            .connect()
            .await
            .map_err(|_| RnsError::ConnectionError)?;

        let radio_client = RadioClient::new(channel.clone());

        let (mut packet_tx, packet_rx) = mpsc::channel(32);

        let mut rx_radio_client = radio_client.clone();
        let rx_task = tokio::spawn(async move {
            let mut stream = rx_radio_client
                .receive_stream(proto::ReceiveRequest {
                    module: module as u32,
                    timeout: 0, // unused
                })
                .await
                .map_err(|_| RnsError::ConnectionError)?
                .into_inner();

            while let Some(item) = stream.next().await {
                if let Some(response) = item.ok() {
                    if let Some(frame) = response.frame {
                        let packet = convert_frame_to_packet(&frame);
                        if let Ok(packet) = packet {
                            let _ = packet_tx.send(packet).await;
                        }
                    }
                }
            }

            Ok(())
        });

        Ok(Self {
            radio_client,
            device_client: DeviceClient::new(channel.clone()),
            tx_buffer: [0u8; TX_BUFFER_SIZE],
            packet_rx,
            rx_task,
            module,
        })
    }

    pub async fn configure(&mut self, config: RadioConfig) -> Result<(), RnsError> {
        let _ = self
            .radio_client
            .configure(proto::ConfigurationRequest {
                module: self.module as u32,
                freq: config.freq,
                channel: config.channel,
                channel_spacing: config.channel_spacing,
            })
            .await
            .map_err(|_| RnsError::ConnectionError)?;
        Ok(())
    }

    /// Transmit a packet over the radio
    pub async fn transmit(&mut self, packet: &Packet) -> Result<(), RnsError> {
        let mut output_buffer = OutputBuffer::new(&mut self.tx_buffer);

        packet.serialize(&mut output_buffer)?;

        let bytes = output_buffer.as_mut_slice();

        // Convert the packet bytes to a list of words
        // NOTE: Dynamic allocation
        let words = bytes
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

        let frame = proto::RadioFrame {
            data: words,
            length: bytes.len() as u32,
        };

        let request = proto::TransmitRequest {
            module: self.module as u32,
            frame: Some(frame),
        };

        let _ = self
            .radio_client
            .transmit(request)
            .await
            .map_err(|_| RnsError::ConnectionError)?;

        Ok(())
    }
}

impl Interface for KaonicGrpc {
    fn send(&mut self, packet: &Packet) -> Result<(), RnsError> {
        tokio::runtime::Handle::current().block_on(self.transmit(packet))
    }

    fn recv(&mut self) -> Result<Packet, RnsError> {
        tokio::runtime::Handle::current()
            .block_on(self.packet_rx.recv())
            .ok_or(RnsError::ConnectionError)
    }
}
