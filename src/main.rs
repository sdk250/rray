#![allow(dead_code, unused_variables, unused_imports)]


mod error;
mod ext;
mod driver;


use tracing::{ error, info };
use tokio::{
    net::{ TcpListener, TcpStream },
    time::{ sleep, Duration }
};

use error::{ Result, RError };
use ext::logger_service;
use driver::handle_connection;


const HOST: &'static str = "0.0.0.0";
const PORT: u16 = 20880;


async fn _main() -> Result<()> {
    let listener = TcpListener::bind((HOST, PORT)).await?;
    info!("Server listening on {}:{}", HOST, PORT);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                info!("New connection from {}", peer_addr);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection().await {
                        error!("Error handling connection from {}: {}", peer_addr, e);
                    }
                });
            },
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                sleep(Duration::from_secs(10)).await;
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[tokio::main]
async fn main() {
    let _log_guard = logger_service(true, true, true);

    if let Err(e) = _main().await {
        error!("Error: {}", e);
    }
}
