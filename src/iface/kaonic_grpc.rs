pub mod proto {
    tonic::include_proto!("kaonic");
}

use proto::device_client::DeviceClient;
use proto::radio_client::RadioClient;

use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::packet::Packet;
use crate::serde::Serialize;

const TX_BUFFER_SIZE: usize = 4096;

pub struct KaonicGrpc {
    radio_client: RadioClient<Channel>,
    device_client: DeviceClient<Channel>,
    tx_buffer: [u8; TX_BUFFER_SIZE],
    rx_task: Option<tokio::task::JoinHandle<()>>,
}

impl KaonicGrpc {
    pub async fn new(address: &str) -> Result<Self, RnsError> {
        let channel = Channel::from_shared(address.to_string())
            .unwrap()
            .connect()
            .await
            .map_err(|_| RnsError::ConnectionError)?;

        Ok(Self {
            radio_client: RadioClient::new(channel.clone()),
            device_client: DeviceClient::new(channel.clone()),
            tx_buffer: [0u8; TX_BUFFER_SIZE],
            rx_task: None,
        })
    }

    pub async fn configure(&mut self, config: proto::ConfigurationRequest) -> Result<(), RnsError> {
        let _ = self
            .radio_client
            .configure(config)
            .await
            .map_err(|_| RnsError::ConnectionError)?;
        Ok(())
    }

    pub async fn transmit<'a>(&mut self, module: u32, packet: &Packet<'a>) -> Result<(), RnsError> {
        let mut output_buffer = OutputBuffer::new(&mut self.tx_buffer);

        packet.serialize(&mut output_buffer)?;
        let bytes = output_buffer.as_mut_slice();

        let words = bytes
            .chunks(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
            .collect::<Vec<_>>();

        let words_len = words.len();

        let frame = proto::RadioFrame {
            data: words,
            length: words_len as u32,
        };

        let request = proto::TransmitRequest {
            module,
            frame: Some(frame),
        };

        let _ = self
            .radio_client
            .transmit(request)
            .await
            .map_err(|_| RnsError::ConnectionError)?;

        Ok(())
    }

    pub fn start_receive(&mut self, module: u32) -> Result<(), RnsError> {
        let mut client = self.radio_client.clone();
     
        self.rx_task = Some(tokio::spawn(async move {
            let timeout = std::time::Duration::from_secs(1);

            let mut stream = client
                .receive_stream(proto::ReceiveRequest {
                    module,
                    timeout: timeout.as_millis() as u32,
                })
                .await
                .unwrap()
                .into_inner();

            while let Some(frame) = stream.next().await {
                match frame {
                    Ok(response) => {
                        if let Some(frame) = response.frame {
                            let bytes = frame
                                .data
                                .iter()
                                .flat_map(|word| word.to_le_bytes())
                                .collect::<Vec<_>>();

                            let mut buffer = InputBuffer::new(bytes.as_slice());
                            let _packet = Packet::deserialize(&mut buffer);
                        }
                    }
                    Err(_) => (),
                }
            }
        }));

        Ok(())
    }

    pub async fn stop_receive(&mut self) {
        if let Some(task) = self.rx_task.take() {
            task.abort();
        }
    }
}
