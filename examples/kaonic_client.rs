use std::env;
use std::sync::Arc;
use std::time::Duration;

use rand_core::OsRng;
use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::kaonic::kaonic_grpc::{KaonicGrpcConfig, KaonicGrpcInterface};
use reticulum::iface::kaonic::RadioModule;
use reticulum::transport::Transport;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <grpc-addr>", args[0]);
        return;
    }

    let grpc_addr = &args[1];

    let transport = Arc::new(Mutex::new(Transport::new()));

    log::info!("start kaonic client");

    let _kaonic_client = KaonicGrpcInterface::start(
        KaonicGrpcConfig {
            addr: format!("http://{}", grpc_addr).into(),
            module: RadioModule::RadioA,
        },
        transport.lock().await.channel().await,
    );

    let identity = PrivateIdentity::new_from_name("kaonic-example");

    let in_destination = transport
        .lock()
        .await
        .add_destination(
            identity,
            DestinationName::new("example_utilities", "linkexample"),
        )
        .await;

    // Announce task
    {
        let transport = transport.clone();
        tokio::spawn(async move {
            loop {
                log::trace!("announce");

                transport
                    .lock()
                    .await
                    .send(in_destination.lock().await.announce(OsRng, None).unwrap())
                    .await;

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
