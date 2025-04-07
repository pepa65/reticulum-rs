use alloc::string::String;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::error::RnsError;

use super::tcp_client::TcpClient;
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct TcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
}

impl TcpServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
        }
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = TcpListener::bind(addr.clone())
                .await
                .map_err(|_| RnsError::ConnectionError);

            if let Err(_) = listener {
                log::warn!("tcp_server: couldn't bind to <{}>", addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            log::info!("tcp_server: listen on <{}>", addr);

            let listener = listener.unwrap();
            loop {
                let client = listener.accept().await;
                if let Ok(client) = client {
                    log::info!("tcp_server: new client <{}> connected", client.1);

                    let mut iface_manager = iface_manager.lock().await;

                    iface_manager.spawn(
                        TcpClient::new_from_stream(client.1.to_string(), client.0),
                        TcpClient::spawn,
                    );
                }
            }
        }
    }
}

impl Interface for TcpServer {
    fn mtu() -> usize {
        2048
    }
}
