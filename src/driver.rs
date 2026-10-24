use std::sync::Arc;

use tokio::net::{ TcpListener, TcpStream };
use tokio::sync::Semaphore;
use tokio::time::{ Duration, sleep };
use tracing::{ error, info, warn };

use crate::config::Config;
use crate::error::Result;
use crate::{ inbound::socks5, outbound, relay };

/// accept 循环。每条连接独立 spawn：单连接的错误不影响其它连接。
///
/// 达到 `max_connections` 时先不 accept：新连接在内核 backlog 里排队，有连接结束就接上，
/// 客户端看到的是变慢而不是被拒。
pub async fn serve(listener: TcpListener, cfg: Arc<Config>) {
    let limit = cfg.inbound.max_connections;
    let slots = (limit > 0).then(|| Arc::new(Semaphore::new(limit)));
    let mut saturated = false;

    loop {
        let permit = match &slots {
            Some(slots) => {
                let full = slots.available_permits() == 0;
                if full && !saturated {
                    warn!("max_connections ({limit}) reached, pausing accept");
                }
                saturated = full;
                Some(slots.clone().acquire_owned().await.expect("semaphore is never closed"))
            },
            None => None,
        };

        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_connection(stream, cfg).await {
                        warn!("connection from {} failed: {}", peer_addr, e);
                    }
                });
            },
            Err(e) => {
                error!("failed to accept connection: {}", e);
                sleep(Duration::from_secs(1)).await;
            },
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncReadExt, AsyncWriteExt };

    const CONFIG: &str = r#"
[log]
level = "info"
[inbound]
listen = "127.0.0.1"
port = 1080
max_connections = 1
[outbound]
server = "127.0.0.1"
port = 9
[outbound.vless]
uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
flow = "xtls-rprx-vision"
[outbound.reality]
public_key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
short_id = "0123abcd"
server_name = "www.microsoft.com"
"#;

    /// SOCKS5 no-auth greeting，返回服务端是否在 `wait` 内回了方法选择。
    async fn greeted(c: &mut TcpStream, wait: Duration) -> bool {
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut reply = [0u8; 2];
        matches!(tokio::time::timeout(wait, c.read_exact(&mut reply)).await, Ok(Ok(_)))
    }

    /// 达到 max_connections 时暂停 accept：新连接在 backlog 里排队，不被拒绝；
    /// 占位的连接一结束，排队的立刻被处理。
    #[tokio::test]
    async fn max_connections_pauses_accept_until_a_slot_frees() {
        let cfg = Arc::new(crate::config::parse(CONFIG).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, cfg));

        let mut first = TcpStream::connect(addr).await.unwrap();
        assert!(greeted(&mut first, Duration::from_secs(1)).await);

        // 第二条：TCP 能连上（进 backlog），但没人处理它的 greeting。
        let mut second = TcpStream::connect(addr).await.unwrap();
        assert!(!greeted(&mut second, Duration::from_millis(200)).await, "超过上限还在接新连接");

        drop(first); // 占位连接结束 → 释放名额
        let mut reply = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(1), second.read_exact(&mut reply))
            .await
            .expect("名额释放后排队连接没被处理")
            .unwrap();
        assert_eq!(reply, [0x05, 0x00]);
    }
}
