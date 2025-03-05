use rand_core::OsRng;

use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp::{TcpClient, TcpClientConfig};
use reticulum::link::Link;
use reticulum::transport::Transport;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let transport = Transport::new();

    log::info!("start tcp app");

    let _tcp_client = TcpClient::new(
        TcpClientConfig {
            addr: "127.0.0.1:4242".into(),
        },
        transport.packet_channel(),
    )
    .await
    .expect("tcp client");

    let id = PrivateIdentity::new_from_rand(OsRng);

    let mut recv = transport.recv();
    loop {
        if let Ok(packet) = recv.recv().await {
            if let Ok(dest) = DestinationAnnounce::validate(&packet) {
                log::debug!("destination announce {}", packet);
                let link = transport.link(dest.desc);
            }
        }
    }
}
