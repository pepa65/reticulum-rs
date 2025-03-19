pub mod hdlc;
pub mod kaonic;
pub mod tcp;

use std::sync::Arc;
use std::sync::Mutex;

use tokio::sync::mpsc;
use tokio::task;
use tokio_util::sync::CancellationToken;

use crate::packet::Packet;

pub type InterfaceTxSender = mpsc::Sender<Packet>;
pub type InterfaceTxReceiver = mpsc::Receiver<Packet>;
pub type InterfaceRxSender = mpsc::Sender<Packet>;
pub type InterfaceRxReceiver = mpsc::Receiver<Packet>;

pub struct InterfaceChannel {
    pub rx_channel: InterfaceRxSender,
    pub tx_channel: InterfaceTxReceiver,
}

impl InterfaceChannel {
    pub fn make_rx_channel(cap: usize) -> (InterfaceRxSender, InterfaceRxReceiver) {
        mpsc::channel(cap)
    }

    pub fn make_tx_channel(cap: usize) -> (InterfaceTxSender, InterfaceTxReceiver) {
        mpsc::channel(cap)
    }

    pub fn new(rx_channel: InterfaceRxSender, tx_channel: InterfaceTxReceiver) -> Self {
        Self {
            rx_channel,
            tx_channel,
        }
    }

    pub fn split(self) -> (InterfaceRxSender, InterfaceTxReceiver) {
        (self.rx_channel, self.tx_channel)
    }
}

pub struct Interface<T> {
    _handler: Arc<Mutex<T>>,
    _join: tokio::task::JoinHandle<()>,
    cancel: CancellationToken,
}

impl<T> Interface<T> {
    pub fn new<F, R>(handler: T, channel: InterfaceChannel, worker: F) -> Self
    where
        F: FnOnce(InterfaceChannel, Arc<Mutex<T>>, CancellationToken) -> R,
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
