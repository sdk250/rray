use std::sync::Arc;

use tracing::{ error, info, warn };
use tokio::{
    net::TcpListener,
    time::{ sleep, Duration }
};

use rray::config::{ self, Config };
use rray::error::Result;
use rray::ext::{ logger_service, parse_level };
use rray::driver::handle_connection;


const CONFIG_PATH: &str = "config.toml";


async fn serve(cfg: Arc<Config>) -> Result<()> {
    let listener = TcpListener::bind((cfg.inbound.listen, cfg.inbound.port)).await?;
    info!("SOCKS5 listening on {}:{}", cfg.inbound.listen, cfg.inbound.port);
    info!("outbound {}:{} (sni {})", cfg.outbound.server, cfg.outbound.port, cfg.outbound.reality.server_name);

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let cfg = cfg.clone();
                // 每条连接独立 spawn：单连接的错误不影响其它连接。
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, cfg).await {
                        warn!("connection from {} failed: {}", peer_addr, e);
                    }
                });
            },
            Err(e) => {
                error!("failed to accept connection: {}", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cfg = match config::load(CONFIG_PATH) {
        Ok(cfg) => cfg,
        Err(e) => {
            // 日志还没起来，只能直接打到 stderr。
            eprintln!("failed to load {CONFIG_PATH}: {e}");
            std::process::exit(1);
        },
    };

    let level = match parse_level(&cfg.log.level) {
        Ok(level) => level,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        },
    };
    let _log_guard = logger_service(level, true, true, true);

    if let Err(e) = serve(Arc::new(cfg)).await {
        error!("fatal: {}", e);
        std::process::exit(1);
    }
}
