use rand_core::OsRng;

use reticulum::destination::{DestinationAnnounce, DestinationName};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp::{TcpClientConfig, TcpClientInterface};
use reticulum::transport::Transport;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let mut transport = Transport::new();

    log::info!("start tcp app");

    let _tcp_client = TcpClientInterface::start(
        TcpClientConfig {
            addr: "127.0.0.1:4242".into(),
        },
        transport.packet_channel(),
    );

    let identity = PrivateIdentity::new_from_name("link-example");

    let in_destination = transport.add_destination(
        identity,
        DestinationName::new("example_utilities", "linkexample"),
    );

    transport
        .send(
            in_destination
                .lock()
                .unwrap()
                .announce(OsRng, None)
                .unwrap(),
        )
        .unwrap();

    let mut recv = transport.recv();
    loop {
        if let Ok(packet) = recv.recv().await {
            if let Ok(dest) = DestinationAnnounce::validate(&packet) {
                log::debug!("destination announce {}", dest.desc);
                // let link = transport.link(dest.desc);
            }
        }
    }
}
