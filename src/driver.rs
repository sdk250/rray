use std::sync::Arc;

use tokio::net::TcpStream;
use tracing::info;

use crate::config::Config;
use crate::error::Result;
use crate::{ inbound::socks5, outbound, relay };

/// 编排单条连接：SOCKS5 握手 → 开出站 → 回复客户端 → 双向转发。
/// 每条连接独立 spawn，错误不传染其它连接。
pub(crate) async fn handle_connection(mut client: TcpStream, cfg: Arc<Config>) -> Result<()> {
    client.set_nodelay(true)?;

    let target = socks5::handshake(&mut client).await?;
    info!("CONNECT -> {:?}:{}", target.addr, target.port);

    match outbound::open(&cfg.outbound, &cfg.timeout, &target).await {
        Ok(upstream) => {
            socks5::reply(&mut client, true).await?;
            relay::relay(client, upstream).await?;
            Ok(())
        },
        Err(e) => {
            // 出站失败也要给客户端一个明确的失败回复，别让它干等。
            let _ = socks5::reply(&mut client, false).await;
            Err(e)
        },
    }
}
