use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::buffer::{InputBuffer, OutputBuffer};
use crate::error::RnsError;
use crate::packet::Packet;
use crate::serde::Serialize;

use tokio::io::AsyncReadExt;

use alloc::string::String;

use super::hdlc::Hdlc;
use super::PacketChannel;

struct TcpClientHandler {}

#[derive(Clone)]
pub struct TcpClientConfig {
    pub addr: String,
}

enum ClientCommand {
    Send(Packet),
    Close,
}

pub struct TcpClient {
    client_task: tokio::task::JoinHandle<()>,
    cmd_tx: tokio::sync::mpsc::Sender<ClientCommand>,
    cancel_token: CancellationToken,
}

impl TcpClient {
    pub async fn new(
        config: TcpClientConfig,
        packet_channel: PacketChannel,
    ) -> Result<Self, RnsError> {
        let cancel_token = CancellationToken::new();

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientCommand>(4);

        let mut packet_channel = packet_channel;

        // Spawn task with reconnection mechanism
        let client_task = {
            let task_cancel_token = cancel_token.clone();

            let mut handler = TcpClientHandler {};
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = task_cancel_token.cancelled() => {
                                break;
                        }
                        _ = handler.handle(&config.addr, &mut cmd_rx, &mut packet_channel) => {
                            log::warn!("tcp_client: retry connection");
                            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                        }
                    }
                }
            })
        };

        Ok(Self {
            client_task,
            cmd_tx,
            cancel_token,
        })
    }
}

impl TcpClientHandler {
    async fn handle(
        &mut self,
        addr: &str,
        cmd_rx: &mut tokio::sync::mpsc::Receiver<ClientCommand>,
        packet_channel: &mut PacketChannel,
    ) -> Result<(), RnsError> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|_| RnsError::ConnectionError)?;

        log::info!("tcp_client connected to <{}>", addr);

        let mut hdlc_tx_buffer = [0u8; 2048];
        let mut hdlc_rx_buffer = [0u8; 2048];

        let mut tx_buffer = [0u8; 2048];
        let mut rx_buffer = [0u8; 2048];

        loop {
            tokio::select! {
                // Read stream
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
                                                    // log::trace!("tcp_client: << rx /{}/", packet.destination);
                                                    let _ = packet_channel.in_tx.send(packet);
                                                } else {
                                                    log::warn!("tcp_client: couldn't decode hdlc frame");
                                                }
                                            } else {
                                                log::warn!("tcp_client: couldn't decode packet");
                                            }
                                        }
                                        Err(e) => {
                                            log::warn!("tcp_client: connection error {}", e);
                                            break;
                                        }
                                    }
                                },

                Ok(packet) = packet_channel.out_rx.recv() => {
                    let mut output = OutputBuffer::new(&mut tx_buffer);
                    // log::trace!("tcp_client: >> tx {}", packet.destination);
                    if let Ok(_) = packet.serialize(&mut output) {

                        let mut hdlc_output = OutputBuffer::new(&mut hdlc_tx_buffer[..]);

                        if let Ok(_) = Hdlc::encode(output.as_slice(), &mut hdlc_output) {
                            let _ = stream.write_all(hdlc_output.as_slice()).await;
                            let _ = stream.flush().await;
                        }
                    }
                }

                // Handle commands
                Some(cmd) = cmd_rx.recv() => {
                    match cmd {
                        ClientCommand::Send(_) => {
                        },
                        ClientCommand::Close => {
                            break;
                        },
                    }
                }
            };
        }

        log::debug!("tcp_client handler closed");

        Ok(())
    }
}
