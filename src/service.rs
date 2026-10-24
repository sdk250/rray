use std::sync::Arc;
use std::sync::Mutex;

use tokio::runtime::Runtime;
use tokio::sync::oneshot;

use crate::{
    config, driver,
    error::{ RError, Result }
};

struct Running {
    runtime: Runtime,
    shutdown: oneshot::Sender<()>,
}

// 中毒态（持锁线程 panic）处理：两处都清掉中毒标记继续用锁
// （`unwrap_or_else(|e| e.into_inner())`），不 `.unwrap()`。这个 Mutex 保护的
// 只是一个 `Option<Running>`，中毒不代表数据结构被撕裂——要么是 None 要么是
// 完整的 Running，没有半成品状态可能因 panic 变得不一致。照旧 `.unwrap()`
// 会让一次瞬时 panic 使 start/stop 永久失败且没有自愈路径，只能重启整个
// 进程——这违背「停止后必须能再次启动」的要求。
static STATE: Mutex<Option<Running>> = Mutex::new(None);
const MODULE: &str = "Service";

/// 启动本地 SOCKS5 并返回实际监听端口。已在运行时返回错误。
pub fn start(text: &str) -> Result<u16> {
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Err(RError::Custom(MODULE, "已经在运行".into()));
    }

    let cfg = config::parse(text)?;
    let cfg = Arc::new(cfg);

    let runtime = Runtime::new()?;

    let bind = async | cfg: &config::Config | {
        use tokio::net::TcpListener;
        Ok::<_, RError>(TcpListener::bind((
            cfg.inbound.listen, cfg.inbound.port
        )).await?)
    };
    // 同步等到 bind 成功：这是「已就绪」的唯一可靠信号，也是把实际端口
    // 交给调用方的唯一途径。失败在这里就能明确报出，而不是让上层去猜。
    let listener = runtime
        .block_on(bind(&cfg))?;
    let port = listener.local_addr()?.port();

    let (tx, rx) = oneshot::channel();
    let serve_cfg = cfg.clone();
    runtime.spawn(async move {
        tokio::select! {
            _ = driver::serve(listener, serve_cfg) => {}
            _ = rx => {}
        }
    });

    *guard = Some(Running { runtime, shutdown: tx });
    Ok(port)
}

/// 停止并释放端口。幂等：未在运行时也返回 true。
pub fn stop() -> bool {
    // 只在锁内 take() 出 Running，锁立刻释放；下面最多 2 秒的
    // shutdown_timeout 在锁外做。之前 guard 一直活到 shutdown 返回，
    // 期间全局锁被占住，任何并发的 start/stop 调用都要陪等 2 秒。
    // 锁外做是安全的：并发的 start 走 bind 0，由内核另分配一个空闲
    // 端口，不会跟这里正在关闭、即将释放的监听冲突，所以它不需要
    // 等这个 Running 彻底退出。
    let running = {
        let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
        guard.take()
    };
    if let Some(running) = running {
        let _ = running.shutdown.send(());
        // 必须等：shutdown_background 立刻返回，listener 可能还没被
        // drop，端口就还占着——下一次 start 会 bind 失败，表现为
        // 「断开后再连就连不上」。给一个有界的等待。
        running.runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    }
    true
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;

    // start/stop 操作的是进程级全局状态，测试必须串行
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    const CFG: &str = r#"
[log]
level = "warn"
[inbound]
listen = "127.0.0.1"
port = 0
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
[timeout]
connect_ms = 5000
handshake_ms = 10000
dial_retries = 2
"#;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn start_returns_bound_port() {
        let _g = lock();
        let port = start(CFG).expect("start");
        assert!(port > 0);
        assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
        assert!(stop());
    }

    #[test]
    fn start_twice_fails_until_stopped() {
        let _g = lock();
        start(CFG).expect("first start");
        assert!(start(CFG).is_err());
        assert!(stop());
        start(CFG).expect("start after stop");
        assert!(stop());
    }

    #[test]
    fn stop_is_idempotent() {
        let _g = lock();
        assert!(stop());
        assert!(stop());
    }

    #[test]
    fn start_rejects_bad_config() {
        let _g = lock();
        assert!(start("not toml").is_err());
        start(CFG).expect("valid start after a failed one");
        assert!(stop());
    }
}
