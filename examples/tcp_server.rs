use reticulum::iface::tcp_server::TcpServer;
use reticulum::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> TCP SERVER APP <<<");

    let transport = Transport::new(TransportConfig::default());

    let _ = transport.iface_manager().lock().await.spawn(
        TcpServer::new("127.0.0.1:4242", transport.iface_manager()),
        TcpServer::spawn,
    );

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
