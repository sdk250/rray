//! TLS 记录闸门 —— 支撑 Vision 的 Direct（直通）切换。
//!
//! # 为什么需要它
//!
//! xtls-rprx-vision 的流控里，服务端一旦嗅探到内层是 TLS 1.3
//! （`xray proxy/proxy.go:654` 设 `EnableXtls`），就会发一帧 `CommandPaddingDirect`，
//! **此后把下行数据直接写进裸 TCP，绕过 TLS 加密**
//! （`UnwrapRawConn` 把 `*reality.Conn` 拆到 `NetConn()`）。
//!
//! 于是客户端在收到 Direct 之后必须停止用 TLS 解密，改从裸套接字读。
//! 麻烦在于 TLS 库通常会预读：Direct 所在记录之后的裸字节，很可能已经躺在
//! TLS 库的内部缓冲里了。Go 版靠 REALITY fork 暴露的 `rawInput` 把它捞出来
//! （`proxy.go:259-264`），rustls 没有这种接口。
//!
//! 所以这里在 rustls **下面**插一层：由我们持有套接字缓冲，一次只向 rustls
//! 交付一条完整 TLS 记录，交完就关闸。上层每解出一段明文、确认还没切直通，
//! 才开闸放下一条。这样 Direct 边界之后的裸字节永远留在我们手里。
//!
//! 闸门只在 padding 阶段生效（记录数很少）；切直通后完全不经过 rustls。

use std::io;
use std::pin::Pin;
use std::task::{ Context, Poll };

use bytes::{ Buf, BytesMut };
use tokio::io::{ AsyncRead, AsyncWrite, ReadBuf };

/// TLS 记录头长度：type(1) + version(2) + length(2)。
const TLS_RECORD_HEADER_LEN: usize = 5;

pub struct RecordGate<S> {
    inner: S,
    /// 已从套接字读入、尚未交给 rustls 的字节（等价于 Go 版的 `rawInput`）。
    buf: BytesMut,
    /// 是否启用逐记录闸门。握手期间必须关掉，否则握手自己就卡住了。
    gating: bool,
    /// 当前这条记录还剩多少字节没交。
    record_remaining: usize,
    /// 是否允许开始交付下一条记录。
    gate_open: bool,
}

impl<S> RecordGate<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(32 * 1024),
            gating: false,
            record_remaining: 0,
            gate_open: true,
        }
    }

    /// 握手完成后启用闸门。此时 rustls 内部缓冲里即便有残留也只会是正常 TLS 记录，
    /// 而 Direct 边界还在后面，所以是安全的启用点。
    pub fn start_gating(&mut self) {
        self.gating = true;
        self.gate_open = true;
    }

    /// 允许再交付一条记录。
    pub fn open(&mut self) {
        self.gate_open = true;
    }

    /// 取走尚未交给 rustls 的裸字节 —— 切直通后，这就是直通流的开头。
    pub fn take_buffered(&mut self) -> BytesMut {
        std::mem::take(&mut self.buf)
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> RecordGate<S> {
    /// 从套接字补一批数据进 `buf`。返回读到的字节数（0 = EOF）。
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut chunk = [0u8; 16 * 1024];
        let mut rb = ReadBuf::new(&mut chunk);
        std::task::ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
        let n = rb.filled().len();
        self.buf.extend_from_slice(rb.filled());
        Poll::Ready(Ok(n))
    }

    /// 把 `buf` 开头最多 `limit` 字节交给 `dst`。
    fn hand_over(&mut self, dst: &mut ReadBuf<'_>, limit: usize) -> usize {
        let n = limit.min(self.buf.len()).min(dst.remaining());
        dst.put_slice(&self.buf[..n]);
        self.buf.advance(n);
        n
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordGate<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();

        // 未启用闸门（握手期间）：先吐残留，再直接转发。
        if !me.gating {
            if !me.buf.is_empty() {
                me.hand_over(dst, usize::MAX);
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut me.inner).poll_read(cx, dst);
        }

        loop {
            // 正在交付某条记录。
            if me.record_remaining > 0 {
                if me.buf.is_empty() {
                    let n = std::task::ready!(me.poll_fill(cx))?;
                    if n == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                let n = me.hand_over(dst, me.record_remaining);
                me.record_remaining -= n;
                return Poll::Ready(Ok(()));
            }

            // 处在记录边界上，且还没开闸：让上层先看过刚解出的明文再说。
            // 自唤醒而不是干等 —— 上层每轮读循环都会开闸，所以最多多一次 poll。
            if !me.gate_open {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            // 读记录头，定出这条记录的长度。
            if me.buf.len() < TLS_RECORD_HEADER_LEN {
                let n = std::task::ready!(me.poll_fill(cx))?;
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }
                continue;
            }
            let len = u16::from_be_bytes([me.buf[3], me.buf[4]]) as usize;
            me.record_remaining = TLS_RECORD_HEADER_LEN + len;
            me.gate_open = false;
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordGate<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------

/// Vision 切直通时需要的两件事：把闸门开着，以及在切换后越过 TLS 直接读套接字。
///
/// 为普通流提供退化实现（没有 TLS 层，也就没有裸字节残留），供测试使用。
pub trait DirectSwitch {
    /// 允许 TLS 层再消费一条记录。
    fn open_record_gate(&mut self) {}

    /// 取走 TLS 层下面已缓冲、尚未解析的裸字节。
    fn take_buffered_raw(&mut self) -> BytesMut {
        BytesMut::new()
    }

    /// 切直通后：越过 TLS 直接从套接字读。
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>;
}

impl<S: AsyncRead + AsyncWrite + Unpin> DirectSwitch
    for tokio_rustls::client::TlsStream<RecordGate<S>>
{
    fn open_record_gate(&mut self) {
        self.get_mut().0.open();
    }

    fn take_buffered_raw(&mut self) -> BytesMut {
        self.get_mut().0.take_buffered()
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let gate = &mut self.get_mut().get_mut().0;
        Pin::new(gate.get_mut()).poll_read(cx, buf)
    }
}

impl DirectSwitch for tokio::io::DuplexStream {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncReadExt, AsyncWriteExt };

    /// 造一条假 TLS 记录：header(5) + payload。
    fn record(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![kind, 0x03, 0x03];
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// 未启用闸门时就是透明转发。
    #[tokio::test]
    async fn passes_through_before_gating() {
        let (mut peer, sock) = tokio::io::duplex(4096);
        let mut gate = RecordGate::new(sock);
        peer.write_all(b"anything at all").await.unwrap();

        let mut got = vec![0u8; 15];
        gate.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"anything at all");
    }

    /// 启用闸门后：一次只放行一条记录，闸门不开就再也读不到下一条。
    #[tokio::test]
    async fn hands_one_record_then_closes() {
        let (mut peer, sock) = tokio::io::duplex(16 * 1024);
        let mut gate = RecordGate::new(sock);
        gate.start_gating();

        let r1 = record(0x17, b"first record");
        let r2 = record(0x17, b"second record");
        let raw_tail = b"RAW BYTES NOT A RECORD";
        let mut wire = r1.clone();
        wire.extend_from_slice(&r2);
        wire.extend_from_slice(raw_tail);
        peer.write_all(&wire).await.unwrap();
        peer.flush().await.unwrap();

        // 第一条记录能完整读出
        let mut got = vec![0u8; r1.len()];
        gate.read_exact(&mut got).await.unwrap();
        assert_eq!(got, r1);

        // 闸门已关：再读会一直 Pending（这里用超时代替"读不到"）
        let mut more = [0u8; 1];
        let blocked = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            gate.read(&mut more)
        ).await;
        assert!(blocked.is_err(), "闸门关着还放行了数据");

        // 开闸后能读到第二条
        gate.open();
        let mut got2 = vec![0u8; r2.len()];
        gate.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, r2);

        // 关键：记录之后的裸字节还完整留在我们手里，没被喂给 TLS 层
        assert_eq!(&gate.take_buffered()[..], raw_tail);
    }

    /// 记录被拆成小块到达时也要正确定界。
    #[tokio::test]
    async fn reassembles_fragmented_record() {
        let (mut peer, sock) = tokio::io::duplex(16 * 1024);
        let mut gate = RecordGate::new(sock);
        gate.start_gating();

        let r = record(0x17, b"fragmented record payload");
        tokio::spawn(async move {
            for b in r {
                peer.write_all(&[b]).await.unwrap();
                peer.flush().await.unwrap();
            }
        });

        let expect = record(0x17, b"fragmented record payload");
        let mut got = vec![0u8; expect.len()];
        gate.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expect);
    }
}
