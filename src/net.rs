use std::net::IpAddr;

use tokio::{
    net::TcpStream,
    time::{ timeout, sleep, Duration }
};

use crate::error::{ Result, RError };

#[derive(Debug, Clone)]
pub enum Address {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Debug, Clone)]
pub struct Target {
    pub addr: Address,
    pub port: u16,
}

/// 带超时的拨号，失败后按 `retries` 次线性退避重试；成功即开 TCP_NODELAY。
pub async fn dial(server: &str, port: u16, connect_ms: u64, retries: u32) -> Result<TcpStream> {
    let mut last = RError::Protocol("no dial attempt");

    for attempt in 0..=retries {
        match timeout(Duration::from_millis(connect_ms), TcpStream::connect((server, port))).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true)?;
                return Ok(s);
            },
            Ok(Err(e)) => last = RError::from(e),
            Err(_) => last = RError::Protocol("connect timeout"),
        }
        if attempt < retries {
            sleep(Duration::from_millis(200 * (attempt as u64 + 1))).await;
        }
    }

    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拿一个刚释放、确定无人监听的回环端口。
    /// （不用 TEST-NET 保留地址：某些沙箱/透明代理会无差别接受外部连接。）
    async fn closed_port() -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn dial_unreachable_errors_after_retries() {
        let port = closed_port().await;
        let r = dial("127.0.0.1", port, 200, 1).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn dial_backs_off_between_retries() {
        let port = closed_port().await;
        let start = std::time::Instant::now();
        // 连接被拒是瞬时的，耗时即两次退避 200ms + 400ms
        assert!(dial("127.0.0.1", port, 200, 2).await.is_err());
        assert!(start.elapsed() >= Duration::from_millis(600));
    }

    #[tokio::test]
    async fn dial_localhost_succeeds() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = l.accept().await;
        });
        let s = dial("127.0.0.1", addr.port(), 1000, 1).await;
        assert!(s.is_ok());
    }
}
