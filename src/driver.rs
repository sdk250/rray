use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::time::Duration;
use tracing::info;

use crate::config::Config;
use crate::error::Result;
use crate::{ inbound::socks5, outbound, relay };

/// 编排单条连接：SOCKS5 握手 → 回复客户端 → 开出站 → 双向转发。
/// 每条连接独立 spawn，错误不传染其它连接。
pub async fn handle_connection(mut client: TcpStream, cfg: Arc<Config>) -> Result<()> {
    client.set_nodelay(true)?;

    let target = socks5::handshake(&mut client).await?;
    info!("CONNECT -> {:?}:{}", target.addr, target.port);

    // 与 xray 一致，先回成功：客户端随即发首包，出站握手期间它就在 socket 缓冲里，
    // 握手完成后与 VLESS 头一并写出，省掉一个 RTT。
    // 代价：出站失败时客户端只会看到连接被关闭，拿不到 SOCKS5 失败码。
    socks5::reply(&mut client, true).await?;
    let upstream = outbound::open(&cfg.outbound, &cfg.timeout, &target, &mut client).await?;
    let timeouts = relay::Timeouts {
        idle: Duration::from_millis(cfg.timeout.idle_ms),
        half_close: Duration::from_millis(cfg.timeout.half_close_ms),
    };
    relay::relay(client, upstream, timeouts).await
}
