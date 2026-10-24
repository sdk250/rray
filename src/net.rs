use std::collections::{ HashMap, VecDeque };
use std::future::Future;
use std::io;
use std::net::{ IpAddr, SocketAddr };
use std::sync::{ LazyLock, Mutex };

use tokio::{
    net::{ TcpStream, lookup_host },
    task::JoinSet,
    time::{ timeout, sleep, Duration, Instant }
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

/// 对齐 Go `net.Dialer` 默认：空闲 15s 后开始探测，每 15s 一次。
/// NAT/中间设备静默丢弃连接时，内核能发现并让读写报错，而不是一直挂着。
const KEEPALIVE: Duration = Duration::from_secs(15);

/// 域名解析结果的复用时长。getaddrinfo 不给 TTL，只能取固定值；连接失败会提前失效。
const DNS_TTL: Duration = Duration::from_secs(60);
/// Happy Eyeballs 的错开延迟（RFC 8305 推荐 250ms）。
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

static DNS: LazyLock<DnsCache> = LazyLock::new(DnsCache::default);

/// 带超时的拨号，失败后按 `retries` 次线性退避重试；成功即开 TCP_NODELAY 与 keepalive。
/// 域名走缓存解析，多个地址按 Happy Eyeballs 并发尝试；超时覆盖解析 + 连接。
pub async fn dial(server: &str, port: u16, connect_ms: u64, retries: u32) -> Result<TcpStream> {
    let mut last = RError::Protocol("no dial attempt".into());

    for attempt in 0..=retries {
        let connect = async {
            let addrs = resolve(server, port).await?;
            connect_any(&interleave(addrs), HAPPY_EYEBALLS_DELAY, TcpStream::connect).await
        };
        match timeout(Duration::from_millis(connect_ms), connect).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true)?;
                let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE).with_interval(KEEPALIVE);
                socket2::SockRef::from(&s).set_tcp_keepalive(&keepalive)?;
                return Ok(s);
            },
            // 连不上可能是服务器换了 IP：丢掉缓存，下次重新解析。
            Ok(Err(e)) => {
                DNS.invalidate(server, port);
                last = RError::from(e);
            },
            Err(_) => {
                DNS.invalidate(server, port);
                last = RError::Protocol("connect timeout".into());
            },
        }
        if attempt < retries {
            sleep(Duration::from_millis(200 * (attempt as u64 + 1))).await;
        }
    }

    Err(last)
}

/// 解析出站地址。IP 字面量直接返回，域名走缓存。
async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    DNS.resolve_with(host, port, DNS_TTL, || async { Ok(lookup_host((host, port)).await?.collect()) }).await
}

/// (host, port) → (解析时刻, 地址)。
type DnsEntries = HashMap<(String, u16), (Instant, Vec<SocketAddr>)>;

#[derive(Default)]
struct DnsCache {
    entries: Mutex<DnsEntries>,
}

impl DnsCache {
    async fn resolve_with<F, Fut>(&self, host: &str, port: u16, ttl: Duration, lookup: F) -> io::Result<Vec<SocketAddr>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = io::Result<Vec<SocketAddr>>>,
    {
        let key = (host.to_owned(), port);
        if let Some((at, addrs)) = self.lock().get(&key)
            && at.elapsed() < ttl
        {
            return Ok(addrs.clone());
        }
        let addrs = lookup().await?;
        if addrs.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("dns: no address for {host}")));
        }
        self.lock().insert(key, (Instant::now(), addrs.clone()));
        Ok(addrs)
    }

    fn invalidate(&self, host: &str, port: u16) {
        self.lock().remove(&(host.to_owned(), port));
    }

    /// 锁内只做 HashMap 操作、不会 panic，中毒也照用。
    fn lock(&self) -> std::sync::MutexGuard<'_, DnsEntries> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// RFC 8305：保留解析器给的顺序（已按 RFC 6724 排好），从首个地址的地址族开始两族交替。
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first_v6) = addrs.first().map(SocketAddr::is_ipv6) else {
        return addrs;
    };
    let (mut primary, mut secondary): (VecDeque<_>, VecDeque<_>) =
        addrs.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(primary.len() + secondary.len());
    while !primary.is_empty() || !secondary.is_empty() {
        out.extend(primary.pop_front());
        out.extend(secondary.pop_front());
    }
    out
}

/// 简化版 Happy Eyeballs：按顺序发起连接，前一个 `delay` 内没结果就并行发起下一个，
/// 前一个明确失败则立刻发起下一个；先成功的胜出，其余随 JoinSet 释放被取消。
async fn connect_any<T, F, Fut>(addrs: &[SocketAddr], delay: Duration, connect: F) -> io::Result<T>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let mut pending = addrs.iter().copied().peekable();
    let mut attempts = JoinSet::new();
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address to connect");

    loop {
        if let Some(addr) = pending.next() {
            attempts.spawn(connect(addr));
        }
        if attempts.is_empty() {
            return Err(last);
        }
        let joined = if pending.peek().is_some() {
            tokio::select! {
                r = attempts.join_next() => r,
                _ = sleep(delay) => continue,
            }
        } else {
            attempts.join_next().await
        };
        match joined {
            Some(Ok(Ok(conn))) => return Ok(conn),
            Some(Ok(Err(e))) => last = e,
            Some(Err(e)) => last = io::Error::other(e),
            None => {},
        }
    }
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
        let s = dial("127.0.0.1", addr.port(), 1000, 1).await.unwrap();
        assert!(s.nodelay().unwrap());
        // NAT/中间设备静默丢连接时要能发现
        assert!(socket2::SockRef::from(&s).keepalive().unwrap());
    }

    fn v4(last: u8, port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([10, 0, 0, last], port))
    }

    fn v6(last: u16, port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], port))
    }

    /// RFC 8305：保留解析器给的顺序，按首个地址的地址族开始交替排列。
    #[test]
    fn interleaves_address_families() {
        assert_eq!(interleave(vec![v6(1, 1), v6(2, 1), v4(1, 1), v4(2, 1)]), vec![v6(1, 1), v4(1, 1), v6(2, 1), v4(2, 1)]);
        assert_eq!(interleave(vec![v4(1, 1), v4(2, 1), v6(1, 1)]), vec![v4(1, 1), v6(1, 1), v4(2, 1)]);
        assert_eq!(interleave(vec![v4(1, 1), v4(2, 1)]), vec![v4(1, 1), v4(2, 1)]);
    }

    /// 前一个地址很慢（黑洞）时，过了错开延迟就并行试下一个，先成功的胜出。
    #[tokio::test]
    async fn slow_address_does_not_block_the_next() {
        let addrs = [v4(1, 1), v4(2, 1)];
        let start = std::time::Instant::now();
        let won = connect_any(&addrs, Duration::from_millis(50), |a| async move {
            if a == v4(1, 1) {
                sleep(Duration::from_secs(5)).await;
            }
            Ok::<_, std::io::Error>(a)
        })
        .await
        .unwrap();
        assert_eq!(won, v4(2, 1));
        assert!(start.elapsed() >= Duration::from_millis(50));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    /// 前一个地址明确失败（被拒）就立刻试下一个，不等错开延迟。
    #[tokio::test]
    async fn refused_address_falls_through_immediately() {
        let refused = std::net::SocketAddr::from(([127, 0, 0, 1], closed_port().await));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = l.local_addr().unwrap();
        tokio::spawn(async move { let _ = l.accept().await; });

        let start = std::time::Instant::now();
        let s = connect_any(&[refused, open], Duration::from_secs(5), TcpStream::connect).await.unwrap();
        assert_eq!(s.peer_addr().unwrap(), open);
        assert!(start.elapsed() < Duration::from_secs(1), "失败后还在等错开延迟");
    }

    #[tokio::test]
    async fn all_addresses_failing_is_an_error() {
        let a = std::net::SocketAddr::from(([127, 0, 0, 1], closed_port().await));
        let b = std::net::SocketAddr::from(([127, 0, 0, 1], closed_port().await));
        assert!(connect_any(&[a, b], Duration::from_millis(50), TcpStream::connect).await.is_err());
        assert!(connect_any(&[], Duration::from_millis(50), TcpStream::connect).await.is_err());
    }

    /// 解析结果在 TTL 内复用；失效或过期后重新解析。
    #[tokio::test]
    async fn dns_cache_reuses_until_invalidated_or_expired() {
        use std::sync::atomic::{ AtomicUsize, Ordering };

        let cache = DnsCache::default();
        let lookups = AtomicUsize::new(0);
        let lookup = || async {
            lookups.fetch_add(1, Ordering::SeqCst);
            Ok(vec![v4(1, 443)])
        };
        let ttl = Duration::from_millis(100);

        assert_eq!(cache.resolve_with("ex.com", 443, ttl, lookup).await.unwrap(), vec![v4(1, 443)]);
        cache.resolve_with("ex.com", 443, ttl, lookup).await.unwrap();
        assert_eq!(lookups.load(Ordering::SeqCst), 1, "TTL 内应命中缓存");

        cache.invalidate("ex.com", 443);
        cache.resolve_with("ex.com", 443, ttl, lookup).await.unwrap();
        assert_eq!(lookups.load(Ordering::SeqCst), 2, "失效后应重新解析");

        sleep(ttl + Duration::from_millis(20)).await;
        cache.resolve_with("ex.com", 443, ttl, lookup).await.unwrap();
        assert_eq!(lookups.load(Ordering::SeqCst), 3, "过期后应重新解析");
    }

    /// IP 字面量不经 DNS。
    #[tokio::test]
    async fn ip_literal_skips_dns() {
        assert_eq!(resolve("127.0.0.1", 8444).await.unwrap(), vec![std::net::SocketAddr::from(([127, 0, 0, 1], 8444))]);
        assert_eq!(resolve("::1", 8444).await.unwrap(), vec!["[::1]:8444".parse().unwrap()]);
    }
}
