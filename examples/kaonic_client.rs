use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reticulum::destination::DestinationName;
use reticulum::identity::PrivateIdentity;
use reticulum::iface::kaonic::kaonic_grpc::{KaonicGrpcConfig, KaonicGrpcInterface};
use reticulum::iface::kaonic::RadioModule;
use reticulum::transport::Transport;

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
        transport.lock().unwrap().packet_channel(),
    );

    let identity = PrivateIdentity::new_from_name("kaonic-example");

    let in_destination = transport.lock().unwrap().add_destination(
        identity,
        DestinationName::new("example_utilities", "linkexample"),
    );

    // Announce task
    {
        let transport = transport.clone();
        tokio::spawn(async move {
            loop {
                log::trace!("announce");

                transport
                    .lock()
                    .unwrap()
                    .announce(&in_destination.lock().unwrap(), None)
                    .expect("announce");

                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    let mut recv = transport.lock().unwrap().recv();
    loop {
        tokio::select! {
            Ok(packet) = recv.recv() => {
                log::debug!("packet {}", packet);
            },
        }
    }
}
