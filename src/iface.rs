pub mod hdlc;
pub mod kaonic;
pub mod tcp;

use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::broadcast;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::error::RnsError;
use crate::packet::Packet;

const PACKET_TRACE_ENABLED: bool = true;

pub struct PacketChannel {
    in_tx: broadcast::Sender<Packet>,
    out_rx: broadcast::Receiver<Packet>,
}

impl PacketChannel {
    pub fn new(in_tx: broadcast::Sender<Packet>, out_rx: broadcast::Receiver<Packet>) -> Self {
        Self { in_tx, out_rx }
    }

    pub async fn wait_for_tx(&mut self) -> Result<Packet, RnsError> {
        let packet = self.out_rx.recv().await.map_err(|_| RnsError::PacketError);

        if let Ok(packet) = packet {
            if PACKET_TRACE_ENABLED {
                log::debug!("packet: >> tx {}", packet.destination);
            }
        }

        packet
    }

    pub async fn send_rx(&mut self, packet: Packet) -> Result<usize, RnsError> {
        if PACKET_TRACE_ENABLED {
            log::debug!("packet: << rx {}", packet.destination);
        }
        self.in_tx.send(packet).map_err(|_| RnsError::PacketError)
    }
}

impl Clone for PacketChannel {
    fn clone(&self) -> Self {
        Self {
            in_tx: self.in_tx.clone(),
            out_rx: self.out_rx.resubscribe(),
        }
    }
}

pub struct Interface<T> {
    _handler: Arc<Mutex<T>>,
    _join: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

impl<T> Interface<T> {
    pub fn new<F, R>(handler: T, channel: PacketChannel, worker: F) -> Self
    where
        F: FnOnce(PacketChannel, Arc<Mutex<T>>, CancellationToken) -> R,
        R: std::future::Future<Output = ()> + Send + 'static,
        R::Output: Send + 'static,
    {
        let handler = Arc::new(Mutex::new(handler));

        let cancel = CancellationToken::new();

        let join = task::spawn(worker(channel, handler.clone(), cancel.clone()));

        Self {
            _handler: handler,
            _join: join,
            cancel,
        }
    }

    pub fn handler(&self) -> Arc<Mutex<T>> {
        self._handler.clone()
    }
}

impl<T> Drop for Interface<T> {
    fn drop(&mut self) {
        let cancel = self.cancel.clone();
        cancel.cancel();
    }
}
