//! Vision (xtls-rprx-vision) padding 状态机。
//!
//! 帧格式与状态机对照 xray-core `proxy/proxy.go`，见 docs/reference/vision-format.md。
//!
//! 作用：被代理流量本身多半是 TLS（HTTPS），直接套在外层 TLS 里会形成
//! "TLS-in-TLS" 的长度特征。Vision 在内层 TLS 握手期间给每个包套一层
//! `command | contentLen | paddingLen | content | padding` 打散长度，
//! 一旦内层握手结束（出现 application_data 记录）就发 `End` 命令切到直通。

use bytes::{ Buf, BytesMut };

use crate::error::{ Result, RError };

pub(crate) const CMD_PADDING_CONTINUE: u8 = 0x00;
pub(crate) const CMD_PADDING_END: u8 = 0x01;
pub(crate) const CMD_PADDING_DIRECT: u8 = 0x02;

/// 帧头：command(1) + contentLen(2) + paddingLen(2)。
const HEADER_LEN: usize = 5;
/// 第一帧前缀的 UUID 长度。
const UUID_LEN: usize = 16;

/// 内层 TLS 的 application_data 记录起始字节 —— 见到它说明内层握手已完成。
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
/// 内层 TLS 握手记录起始字节，用于判定"被代理流量是 TLS"。
const TLS_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_RECORD_HEADER_LEN: usize = 5;

/// xray 的 `buf.Size`，padding 上限按它算。
const BUF_SIZE: usize = 8192;
/// testseed 默认值 `{900, 500, 900, 256}`（`proxy.go:307`）。
const SEED_LONG_THRESHOLD: usize = 900;
const SEED_LONG_RANGE: u32 = 500;
const SEED_LONG_BASE: usize = 900;
const SEED_SHORT_RANGE: u32 = 256;

/// 按 xray `XtlsPadding` 的公式算 padding 长度。
/// 只影响流量特征，不影响互通 —— 接收端按帧头里的 paddingLen 跳过。
fn padding_len(content_len: usize, long_padding: bool) -> usize {
    use rand::RngExt;

    let mut rng = rand::rng();
    let mut pad = if content_len < SEED_LONG_THRESHOLD && long_padding {
        (rng.random_range(0..SEED_LONG_RANGE) as usize + SEED_LONG_BASE)
            .saturating_sub(content_len)
    } else {
        rng.random_range(0..SEED_SHORT_RANGE) as usize
    };
    let cap = BUF_SIZE.saturating_sub(21 + content_len);
    if pad > cap {
        pad = cap;
    }
    pad
}

/// 打一个 Vision 帧。`uuid` 只在**第一帧**传 `Some`（xray 的 `writeOnceUserUUID`）。
pub(crate) fn xtls_padding(
    data: &[u8],
    command: u8,
    uuid: Option<&[u8; 16]>,
    long_padding: bool,
) -> Vec<u8> {
    let pad = padding_len(data.len(), long_padding);
    let mut out = Vec::with_capacity(UUID_LEN + HEADER_LEN + data.len() + pad);
    if let Some(id) = uuid {
        out.extend_from_slice(id);
    }
    out.push(command);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&(pad as u16).to_be_bytes());
    out.extend_from_slice(data);
    out.resize(out.len() + pad, 0);
    out
}

/// 解帧状态机。对应 xray `XtlsUnpadding` 的三个 remaining 计数器。
#[derive(Debug, Default)]
pub(crate) struct Unpadder {
    /// 是否还没吃掉服务端第一帧的 UUID 前缀。
    expect_uuid: bool,
    /// 已进入直通：不再解帧，字节原样交付。
    direct: bool,
}

impl Unpadder {
    pub(crate) fn new() -> Self {
        Self { expect_uuid: true, direct: false }
    }

    pub(crate) fn is_direct(&self) -> bool {
        self.direct
    }

    /// 尽可能从 `buf` 里解出数据追加到 `out`。
    /// 不足一整帧就原样留在 `buf` 里等更多字节。
    /// 收到 `End`/`Direct` 命令后切直通，其后的字节直接透传。
    pub(crate) fn unpad(&mut self, buf: &mut BytesMut, out: &mut Vec<u8>) -> Result<()> {
        loop {
            if self.direct {
                out.extend_from_slice(buf);
                buf.clear();
                return Ok(());
            }

            let prefix = if self.expect_uuid { UUID_LEN } else { 0 };
            if buf.len() < prefix + HEADER_LEN {
                return Ok(());
            }

            let h = &buf[prefix..prefix + HEADER_LEN];
            let command = h[0];
            let content_len = u16::from_be_bytes([h[1], h[2]]) as usize;
            let pad_len = u16::from_be_bytes([h[3], h[4]]) as usize;
            let total = prefix + HEADER_LEN + content_len + pad_len;
            if buf.len() < total {
                return Ok(());
            }

            buf.advance(prefix + HEADER_LEN);
            self.expect_uuid = false;
            out.extend_from_slice(&buf[..content_len]);
            buf.advance(content_len + pad_len);

            match command {
                CMD_PADDING_CONTINUE => {},
                CMD_PADDING_END | CMD_PADDING_DIRECT => self.direct = true,
                _ => return Err(RError::Protocol("unknown vision padding command".into())),
            }
        }
    }
}

/// 写方向状态机。对应 xray `VisionWriter` 的 `isPadding` 与 TLS 嗅探。
#[derive(Debug)]
pub(crate) struct Padder {
    /// 还在加 padding 阶段。
    padding: bool,
    /// 第一帧要带的 UUID，写一次后置 None。
    uuid: Option<[u8; 16]>,
    /// 已嗅探到被代理流量是 TLS。
    is_tls: bool,
    /// 还剩几个包要嗅探（xray 的 NumberOfPacketToFilter = 8）。
    filter_budget: u32,
}

impl Padder {
    pub(crate) fn new(uuid: [u8; 16]) -> Self {
        Self { padding: true, uuid: Some(uuid), is_tls: false, filter_budget: 8 }
    }

    pub(crate) fn is_direct(&self) -> bool {
        !self.padding
    }

    /// 嗅探被代理流量是否是 TLS（xray `XtlsFilterTls` 的客户端所需部分）。
    fn filter_tls(&mut self, data: &[u8]) {
        if self.filter_budget == 0 {
            return;
        }
        self.filter_budget -= 1;
        if data.len() >= 6
            && data[..2] == TLS_HANDSHAKE_START
            && data[5] == 0x01 // ClientHello
        {
            self.is_tls = true;
        }
    }

    /// 给一次写入加帧。返回真正要写进 TLS 流的字节。
    ///
    /// `data` 为空表示"只有 VLESS 头"的首次写入 —— xray 对它用长 padding 遮长度特征。
    pub(crate) fn pad(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.padding {
            return data.to_vec();
        }

        self.filter_tls(data);

        // 内层 TLS 已经进入 application_data ⇒ 握手结束 ⇒ 这一帧发 End 并切直通。
        let handshake_done = self.is_tls
            && data.len() >= 6
            && data[..3] == TLS_APPLICATION_DATA_START
            && is_complete_record(data);

        let (command, long_padding) = if handshake_done {
            (CMD_PADDING_END, false)
        } else {
            (CMD_PADDING_CONTINUE, true)
        };

        let framed = xtls_padding(data, command, self.uuid.as_ref(), long_padding);
        self.uuid = None;
        if handshake_done {
            self.padding = false;
        }
        framed
    }
}

/// 判断这批字节是否恰好是若干个完整的 application_data 记录
/// （xray `IsCompleteRecord`：不完整就还不能切直通）。
fn is_complete_record(data: &[u8]) -> bool {
    let mut i = 0;
    while i < data.len() {
        if data.len() - i < TLS_RECORD_HEADER_LEN {
            return false;
        }
        if data[i] != TLS_APPLICATION_DATA_START[0] {
            return false;
        }
        let len = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
        i += TLS_RECORD_HEADER_LEN + len;
    }
    i == data.len()
}

// ---------------------------------------------------------------------------
// 流包装
// ---------------------------------------------------------------------------

/// 把 Vision 的 padding 状态机套在一条 TLS 流上，对外仍是普通的 `AsyncRead + AsyncWrite`。
/// 切到直通后读写都退化成对 `inner` 的直接转发。
pub struct VisionStream<S> {
    inner: S,
    padder: Padder,
    unpadder: Unpadder,
    /// 已成帧但还没写完的字节。
    write_pending: BytesMut,
    /// 从 inner 读到、还不够一整帧的字节。
    read_raw: BytesMut,
    /// 已解出、待交付上层的数据。
    read_out: BytesMut,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            padder: Padder::new(uuid),
            unpadder: Unpadder::new(),
            write_pending: BytesMut::new(),
            read_raw: BytesMut::with_capacity(16 * 1024),
            read_out: BytesMut::new(),
        }
    }

    /// 首帧（携带 UUID 的伪装帧）已经由调用方连同 VLESS 头一起发出时用这个构造器，
    /// 避免 UUID 前缀被写第二次。见 docs/reference/vision-format.md。
    pub fn with_first_frame_sent(inner: S) -> Self {
        let mut s = Self::new(inner, [0u8; 16]);
        s.padder.uuid = None;
        s
    }
}

/// 伪装帧：空内容 + 长 padding，用来和 VLESS 头拼在同一次写入里遮住头的长度特征。
/// 对应 xray 的 `XtlsPadding(nil, CommandPaddingContinue, &writeOnceUserUUID, true, ...)`。
pub fn camouflage_frame(uuid: &[u8; 16]) -> Vec<u8> {
    xtls_padding(&[], CMD_PADDING_CONTINUE, Some(uuid), true)
}

impl<S: tokio::io::AsyncWrite + Unpin> VisionStream<S> {
    /// 把 `write_pending` 尽量写进 inner；写空返回 Ready。
    fn poll_drain(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        while !self.write_pending.is_empty() {
            match std::pin::Pin::new(&mut self.inner).poll_write(cx, &self.write_pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "vision: inner stream accepted no bytes",
                    )));
                },
                Poll::Ready(Ok(n)) => {
                    self.write_pending.advance(n);
                },
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;

        let me = self.get_mut();

        // 上一次成的帧还没写完：先排空，避免无限缓冲。
        std::task::ready!(me.poll_drain(cx))?;

        // 直通阶段没有帧，直接写，省一次拷贝。
        if me.padder.is_direct() {
            return std::pin::Pin::new(&mut me.inner).poll_write(cx, buf);
        }

        me.write_pending.extend_from_slice(&me.padder.pad(buf));
        // 帧已接管全部输入，故对上层报告写入完成；余下由 poll_drain / poll_flush 负责送出。
        match me.poll_drain(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_drain(cx))?;
        std::pin::Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_drain(cx))?;
        std::pin::Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for VisionStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;

        let me = self.get_mut();

        loop {
            // 先把已解出的数据交付上层。
            if !me.read_out.is_empty() {
                let n = me.read_out.len().min(buf.remaining());
                buf.put_slice(&me.read_out[..n]);
                me.read_out.advance(n);
                return Poll::Ready(Ok(()));
            }

            // 直通且无残留：直接读进上层缓冲，省一次拷贝。
            if me.unpadder.is_direct() && me.read_raw.is_empty() {
                return std::pin::Pin::new(&mut me.inner).poll_read(cx, buf);
            }

            let mut chunk = [0u8; 16 * 1024];
            let mut read_buf = tokio::io::ReadBuf::new(&mut chunk);
            std::task::ready!(std::pin::Pin::new(&mut me.inner).poll_read(cx, &mut read_buf))?;
            let filled = read_buf.filled().len();
            if filled == 0 {
                // EOF：残留的半帧只能丢弃（对端已关闭）。
                return Poll::Ready(Ok(()));
            }
            me.read_raw.extend_from_slice(read_buf.filled());

            let mut out = Vec::new();
            me.unpadder
                .unpad(&mut me.read_raw, &mut out)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            me.read_out.extend_from_slice(&out);
            // out 可能为空（帧还没收全），循环回去继续读。
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncReadExt, AsyncWriteExt };

    const UUID: [u8; 16] = [0xAA; 16];

    fn unpad_all(frames: &[u8]) -> (Unpadder, Vec<u8>) {
        let mut buf = BytesMut::from(frames);
        let mut out = Vec::new();
        let mut u = Unpadder::new();
        u.unpad(&mut buf, &mut out).unwrap();
        (u, out)
    }

    #[test]
    fn padding_roundtrip() {
        let data = b"hello world";
        let framed = xtls_padding(data, CMD_PADDING_CONTINUE, Some(&UUID), false);
        assert_eq!(&framed[..16], &UUID); // 第一帧带 UUID 前缀
        let (u, out) = unpad_all(&framed);
        assert_eq!(out, data);
        assert!(!u.is_direct());
    }

    /// 只有第一帧带 UUID，后续帧不带。
    #[test]
    fn only_first_frame_carries_uuid() {
        let mut p = Padder::new(UUID);
        let first = p.pad(b"aaa");
        let second = p.pad(b"bbb");
        assert_eq!(&first[..16], &UUID);
        assert_ne!(&second[..16], &UUID);

        let mut all = first;
        all.extend_from_slice(&second);
        let (_, out) = unpad_all(&all);
        assert_eq!(out, b"aaabbb");
    }

    #[test]
    fn unpadding_needs_full_frame() {
        let framed = xtls_padding(b"abc", CMD_PADDING_END, None, false);
        let mut buf = BytesMut::from(&framed[..framed.len() - 1]); // 缺最后一字节
        let mut out = Vec::new();
        let mut u = Unpadder { expect_uuid: false, direct: false };
        u.unpad(&mut buf, &mut out).unwrap();
        assert!(out.is_empty());
        assert!(!u.is_direct());

        // 补上最后一字节即可解出
        buf.extend_from_slice(&framed[framed.len() - 1..]);
        u.unpad(&mut buf, &mut out).unwrap();
        assert_eq!(out, b"abc");
        assert!(u.is_direct());
    }

    /// 收到 End 后剩余字节原样透传，不再当帧解析。
    #[test]
    fn end_switches_to_direct_passthrough() {
        let mut framed = xtls_padding(b"last", CMD_PADDING_END, None, false);
        framed.extend_from_slice(b"raw bytes after end");

        let mut buf = BytesMut::from(&framed[..]);
        let mut out = Vec::new();
        let mut u = Unpadder { expect_uuid: false, direct: false };
        u.unpad(&mut buf, &mut out).unwrap();
        assert_eq!(out, b"lastraw bytes after end");
        assert!(u.is_direct());
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_unknown_command() {
        let framed = xtls_padding(b"x", 0x7F, None, false);
        let mut buf = BytesMut::from(&framed[..]);
        let mut out = Vec::new();
        let mut u = Unpadder { expect_uuid: false, direct: false };
        assert!(u.unpad(&mut buf, &mut out).is_err());
    }

    /// 非 TLS 流量不会误切直通：一直加 padding。
    #[test]
    fn plain_traffic_keeps_padding() {
        let mut p = Padder::new(UUID);
        for _ in 0..4 {
            p.pad(b"plain http payload");
            assert!(!p.is_direct());
        }
    }

    /// 内层 TLS：握手记录继续 padding，出现完整 application_data 才发 End 切直通。
    #[test]
    fn switches_to_direct_on_inner_application_data() {
        let mut p = Padder::new(UUID);

        // 内层 ClientHello（0x16 0x03 0x01 ... 0x01）
        let mut client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        client_hello.extend_from_slice(&[0u8; 4]);
        let framed = p.pad(&client_hello);
        assert_eq!(framed[16], CMD_PADDING_CONTINUE); // 跳过 UUID 前缀
        assert!(!p.is_direct());

        // 内层 application_data：0x17 0x03 0x03 + 长度 + 载荷
        let mut app_data = vec![0x17, 0x03, 0x03, 0x00, 0x08];
        app_data.extend_from_slice(&[0x42u8; 8]);
        let framed = p.pad(&app_data);
        assert_eq!(framed[0], CMD_PADDING_END);
        assert!(p.is_direct());

        // 切直通后原样透传
        assert_eq!(p.pad(b"raw"), b"raw");
    }

    /// application_data 记录不完整时不能切直通（长度字段说还有更多字节）。
    #[test]
    fn incomplete_record_does_not_switch() {
        let mut p = Padder::new(UUID);
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        ch.extend_from_slice(&[0u8; 4]);
        p.pad(&ch);

        // 声称载荷 8 字节，实际只给 3
        let mut partial = vec![0x17, 0x03, 0x03, 0x00, 0x08];
        partial.extend_from_slice(&[0x42u8; 3]);
        let framed = p.pad(&partial);
        assert_eq!(framed[0], CMD_PADDING_CONTINUE);
        assert!(!p.is_direct());
    }

    /// VisionStream 写出去的字节，必须能被独立的解帧状态机还原成原始数据。
    #[tokio::test]
    async fn stream_write_is_unpaddable() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(sock, UUID);

        vs.write_all(b"first").await.unwrap();
        vs.write_all(b"second").await.unwrap();
        vs.flush().await.unwrap();

        let mut raw = vec![0u8; 8192];
        let n = peer.read(&mut raw).await.unwrap();
        let mut buf = BytesMut::from(&raw[..n]);
        let mut out = Vec::new();
        let mut u = Unpadder::new();
        u.unpad(&mut buf, &mut out).unwrap();
        assert_eq!(out, b"firstsecond");
    }

    /// 对端发来的帧，VisionStream 读出来必须是原始数据；End 之后转直通。
    #[tokio::test]
    async fn stream_read_unpads_then_passes_through() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(sock, UUID);

        let mut wire = xtls_padding(b"hello", CMD_PADDING_CONTINUE, Some(&UUID), false);
        wire.extend_from_slice(&xtls_padding(b"world", CMD_PADDING_END, None, false));
        wire.extend_from_slice(b"direct tail");
        peer.write_all(&wire).await.unwrap();
        peer.flush().await.unwrap();

        let mut got = Vec::new();
        while got.len() < b"helloworlddirect tail".len() {
            let mut chunk = [0u8; 1024];
            let n = vs.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "过早 EOF");
            got.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(got, b"helloworlddirect tail");
    }

    /// 帧被拆成一次一字节送达时，解帧状态机仍要正确还原。
    #[tokio::test]
    async fn stream_read_handles_fragmented_frames() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(sock, UUID);

        let wire = xtls_padding(b"fragmented", CMD_PADDING_CONTINUE, Some(&UUID), true);
        tokio::spawn(async move {
            for b in wire {
                peer.write_all(&[b]).await.unwrap();
                peer.flush().await.unwrap();
            }
        });

        let mut got = vec![0u8; 10];
        vs.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"fragmented");
    }

    /// padding 长度必须落在 xray 的公式范围内，且不越 buf.Size 上限。
    #[test]
    fn padding_length_follows_xray_formula() {
        for _ in 0..50 {
            let short = padding_len(10, false);
            assert!(short < SEED_SHORT_RANGE as usize);

            let long = padding_len(10, true);
            assert!((SEED_LONG_BASE - 10..SEED_LONG_BASE + SEED_LONG_RANGE as usize - 10)
                .contains(&long));

            // content 超过阈值时走短 padding 分支
            assert!(padding_len(1000, true) < SEED_SHORT_RANGE as usize);

            // 上限：21 + content + padding 不超过 buf.Size
            let huge = padding_len(BUF_SIZE - 25, true);
            assert!(21 + (BUF_SIZE - 25) + huge <= BUF_SIZE);
        }
    }
}
