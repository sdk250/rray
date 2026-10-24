//! 双向转发：每个方向一个读写循环，共用一个空闲计时（对齐 xray 的
//! ConnectionIdle / UplinkOnly / DownlinkOnly）。零拷贝（splice）留待第二阶段，接在 `pump` 里。

use std::sync::atomic::{ AtomicBool, AtomicU64, Ordering };

use tokio::io::{ AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt };
use tokio::sync::Notify;
use tokio::time::{ Duration, Instant, sleep_until };

use crate::error::Result;

/// 每个方向的转发缓冲。tokio 默认 8KB，大流量时 syscall 太多；
/// 上行写进 Vision 时超出单帧的部分由 `vision::reshape` 拆帧。
const RELAY_BUF: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// 两个方向都没有数据超过这么久就关掉（xray ConnectionIdle）。
    pub idle: Duration,
    /// 一个方向已结束后，另一方向空闲这么久就关掉（xray UplinkOnly / DownlinkOnly）。
    pub half_close: Duration,
}

/// 两个方向共享的活动记录。原子量让 relay 的 future 保持 Send。
struct Activity {
    start: Instant,
    last_ms: AtomicU64,
    half_closed: AtomicBool,
    /// 半关闭时叫醒 watchdog：它可能正按 idle 算出的更晚截止时间睡着。
    changed: Notify,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
            half_closed: AtomicBool::new(false),
            changed: Notify::new(),
        }
    }

    fn half_close(&self) {
        self.half_closed.store(true, Ordering::Relaxed);
        self.touch();
        self.changed.notify_one();
    }

    fn touch(&self) {
        self.last_ms.store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn deadline(&self, t: &Timeouts) -> Instant {
        let limit = if self.half_closed.load(Ordering::Relaxed) { t.half_close } else { t.idle };
        self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed)) + limit
    }
}

/// 在两条流之间双向搬数据。两个方向都 EOF 后正常结束；任一方向出错即结束；
/// 空闲超时也正常结束（丢掉两端即关闭连接）。
pub async fn relay<A, B>(a: A, b: B, timeouts: Timeouts) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_read, a_write) = tokio::io::split(a);
    let (b_read, b_write) = tokio::io::split(b);
    let activity = Activity::new();

    let both = async {
        tokio::try_join!(pump(a_read, b_write, &activity), pump(b_read, a_write, &activity))
    };
    tokio::select! {
        r = both => {
            r?;
        },
        _ = watchdog(&activity, &timeouts) => {
            tracing::debug!("relay closed on idle timeout");
        },
    }
    Ok(())
}

/// 到期即返回；期间有活动就顺延，转入半关闭就按新的时限重算。
async fn watchdog(activity: &Activity, timeouts: &Timeouts) {
    loop {
        let deadline = activity.deadline(timeouts);
        if Instant::now() >= deadline {
            return;
        }
        tokio::select! {
            _ = sleep_until(deadline) => {},
            _ = activity.changed.notified() => {},
        }
    }
}

/// 单方向：读到 EOF 就关对端写端，并让另一方向转入半关闭计时。
async fn pump<R, W>(mut r: R, mut w: W, activity: &Activity) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            activity.half_close();
            return w.shutdown().await;
        }
        activity.touch();
        w.write_all(&buf[..n]).await?;
        // Vision 写入可能只是入了帧缓冲，必须 flush 才保证送出。
        w.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncReadExt, AsyncWriteExt, duplex };

    const LONG: Timeouts = Timeouts { idle: Duration::from_secs(10), half_close: Duration::from_secs(10) };
    const SHORT: Timeouts = Timeouts { idle: Duration::from_millis(100), half_close: Duration::from_millis(50) };

    #[tokio::test]
    async fn relays_both_directions() {
        let (a_ext, a_int) = duplex(64);
        let (b_ext, b_int) = duplex(64);
        tokio::spawn(async move {
            let _ = relay(a_int, b_int, LONG).await;
        });

        let (mut a_ext, mut b_ext) = (a_ext, b_ext);
        a_ext.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        b_ext.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        b_ext.write_all(b"pong").await.unwrap();
        a_ext.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    /// 超过单个缓冲的数据要完整搬过去。
    #[tokio::test]
    async fn relays_payload_larger_than_buffer() {
        let (mut a_ext, a_int) = duplex(16 * 1024);
        let (mut b_ext, b_int) = duplex(16 * 1024);
        tokio::spawn(async move {
            let _ = relay(a_int, b_int, LONG).await;
        });

        let data: Vec<u8> = (0..300 * 1024).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        tokio::spawn(async move {
            a_ext.write_all(&sent).await.unwrap();
            a_ext.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        b_ext.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, data);
    }

    /// 一端关闭后转发应当结束，而不是挂住。
    #[tokio::test]
    async fn finishes_when_one_side_closes() {
        let (mut a_ext, a_int) = duplex(64);
        let (mut b_ext, b_int) = duplex(64);
        let task = tokio::spawn(async move { relay(a_int, b_int, LONG).await });

        a_ext.write_all(b"bye").await.unwrap();
        a_ext.shutdown().await.unwrap();
        drop(a_ext);

        let mut got = Vec::new();
        b_ext.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"bye");

        drop(b_ext);
        task.await.unwrap().unwrap();
    }

    /// 两个方向都没有数据超过 idle：转发结束（不报错），连接随之释放。
    #[tokio::test]
    async fn idle_connection_is_closed() {
        let (_a_ext, a_int) = duplex(64);
        let (_b_ext, b_int) = duplex(64);
        let start = std::time::Instant::now();
        tokio::time::timeout(Duration::from_secs(2), relay(a_int, b_int, SHORT))
            .await
            .expect("空闲连接没被关掉")
            .unwrap();
        assert!(start.elapsed() >= SHORT.idle);
    }

    /// 有数据流动就不算空闲。
    #[tokio::test]
    async fn activity_keeps_connection_alive() {
        let (mut a_ext, a_int) = duplex(64);
        let (mut b_ext, b_int) = duplex(64);
        let task = tokio::spawn(relay(a_int, b_int, SHORT));

        let mut byte = [0u8; 1];
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            a_ext.write_all(b"x").await.unwrap();
            b_ext.read_exact(&mut byte).await.unwrap();
        }
        assert!(!task.is_finished(), "有流量时被当成空闲关掉了");
        task.await.unwrap().unwrap(); // 停止发送后按 idle 结束
    }

    /// 一个方向结束后，另一方向改用更短的 half_close 计时（xray UplinkOnly/DownlinkOnly）。
    #[tokio::test]
    async fn half_closed_connection_uses_short_timeout() {
        let (mut a_ext, a_int) = duplex(64);
        let (_b_ext, b_int) = duplex(64);
        let timeouts = Timeouts { idle: Duration::from_secs(10), half_close: Duration::from_millis(50) };
        let task = tokio::spawn(relay(a_int, b_int, timeouts));

        a_ext.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("半关闭后没有按 half_close 结束")
            .unwrap()
            .unwrap();
    }
}
