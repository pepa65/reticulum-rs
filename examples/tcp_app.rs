use rand_core::OsRng;
use reticulum::destination::{DestinationAnnounce, DestinationName, SingleInputDestination};
use reticulum::identity::PrivateIdentity;
use reticulum::iface::tcp::{TcpClientConfig, TcpClientInterface};
use reticulum::transport::Transport;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let transport = Transport::new();

    log::info!("start tcp app");

    let _tcp_client = TcpClientInterface::start(
        TcpClientConfig {
            addr: "127.0.0.1:4242".into(),
        },
        transport.packet_channel(),
    );

    let id = PrivateIdentity::new_from_rand(OsRng);

    let destination = SingleInputDestination::new(id, DestinationName::new("example", "app"));

    transport
        .send(destination.announce(OsRng, None).expect("announce packet"))
        .expect("send announce");

    let mut recv = transport.recv();
    loop {
        if let Ok(packet) = recv.recv().await {
            log::debug!("packet {}", packet);
            match DestinationAnnounce::validate(&packet) {
                Ok(_) => {
                    log::info!("announce {}", packet.destination);
                }
                Err(_) => {
                    log::error!("announce not valid");
                }
            }
        }
    }
}
