use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::packet::Packet;
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;
use super::{Interface, PacketChannel};

#[derive(Clone)]
pub struct TcpClientConfig {
    pub addr: String,
}

pub struct TcpClient {
    config: TcpClientConfig,
}

pub type TcpClientInterface = Interface<TcpClient>;

impl TcpClientInterface {
    pub fn start(config: TcpClientConfig, channel: PacketChannel) -> Self {
        log::debug!("tcp_client: start new iface <{}>", config.addr);

        let handler = TcpClient { config };

        Interface::<TcpClient>::new(
            handler,
            channel,
            |channel, handler, cancel| async move {
                let config = { handler.lock().unwrap().config.clone() };
                loop {
                    if cancel.is_cancelled() {
                        break;
                    }

                    let stream = TcpStream::connect(config.addr.clone())
                        .await
                        .map_err(|_| RnsError::ConnectionError);

                    if let Err(_) = stream {
                        log::info!("tcp_client: couldn't connect to <{}>", config.addr);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        continue;
                    }

                    let stream = stream.unwrap();
                    let (read_stream, write_stream) = stream.into_split();

                    log::info!("tcp_client connected to <{}>", config.addr);

                    const BUFFER_SIZE: usize = std::mem::size_of::<Packet>() * 3;

                    let rx_task = {
                        let cancel = cancel.clone();
                        let mut channel = channel.clone();
                        let mut stream = read_stream;

                        tokio::spawn(async move {
                            loop {
                                let mut hdlc_rx_buffer = [0u8; BUFFER_SIZE];

                                let mut rx_buffer = [0u8; BUFFER_SIZE];

                                tokio::select! {
                                    _ = cancel.cancelled() => {
                                            break;
                                    }
                                    result = stream.read(&mut rx_buffer) => {
                                            match result {
                                                Ok(0) => {
                                                    log::warn!("tcp_client: connection closed");
                                                    break;
                                                }
                                                Ok(n) => {
                                                    let mut output = OutputBuffer::new(&mut hdlc_rx_buffer[..]);
                                                    if let Ok(_) = Hdlc::decode(&rx_buffer[..n], &mut output) {
                                                        if let Ok(packet) = Packet::deserialize(&mut InputBuffer::new(output.as_slice())) {
                                                            let _ = channel.send_rx(packet).await;
                                                        } else {
                                                            log::warn!("tcp_client: couldn't decode packet");
                                                        }
                                                    } else {
                                                        log::warn!("tcp_client: couldn't decode hdlc frame");
                                                    }
                                                }
                                                Err(e) => {
                                                    log::warn!("tcp_client: connection error {}", e);
                                                    break;
                                                }
                                            }
                                        },
                                };
                            }
                        })
                    };

                    let tx_task = {
                        let cancel = cancel.clone();
                        let mut channel = channel.clone();
                        let mut stream = write_stream;

                        tokio::spawn(async move {
                            loop {
                                let mut hdlc_tx_buffer = [0u8; BUFFER_SIZE];

                                let mut tx_buffer = [0u8; BUFFER_SIZE];

                                tokio::select! {
                                    _ = cancel.cancelled() => {
                                            break;
                                    }
                                    Ok(packet) = channel.wait_for_tx() => {
                                        let mut output = OutputBuffer::new(&mut tx_buffer);
                                        if let Ok(_) = packet.serialize(&mut output) {

                                            let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);

                                            if let Ok(_) = Hdlc::encode(output.as_slice(), &mut hdlc_output) {
                                                let _ = stream.write_all(hdlc_output.as_slice()).await;
                                                let _ = stream.flush().await;
                                            }
                                        }
                                    }
                                };
                            }
                        })
                    };

                    tx_task.await.unwrap();
                    rx_task.await.unwrap();

                    log::info!("tcp_client: disconnected from <{}>", config.addr);
                }
            },
        )
    }
}
