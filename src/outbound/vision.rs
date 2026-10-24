//! Vision (xtls-rprx-vision) padding 状态机。
//!
//! 帧格式与状态机对照 xray-core `proxy/proxy.go`，见 docs/reference/vision-format.md。
//!
//! 作用：被代理流量本身多半是 TLS（HTTPS），直接套在外层 TLS 里会形成
//! "TLS-in-TLS" 的长度特征。Vision 在内层 TLS 握手期间给每个包套一层
//! `command | contentLen | paddingLen | content | padding` 打散长度，
//! 内层握手结束（出现 application_data 记录）时结束 padding：内层是 TLS 1.3 发
//! `Direct`，此后该方向越过外层 TLS 直写裸 TCP；否则发 `End`，此后不加 padding
//! 但仍走外层 TLS。非 TLS 流量在嗅探名额快用完时提前 `End`。

use bytes::{ Buf, BufMut, BytesMut };

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
/// ServerHello 所在握手记录的起始字节。
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
/// ServerHello 里的 supported_versions 扩展 = TLS 1.3。
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// 允许 XTLS 直通的 TLS 1.3 套件：xray `Tls13CipherSuiteDic` 去掉 CCM_8（0x1305）。
const XTLS_CIPHERS: std::ops::RangeInclusive<u16> = 0x1301..=0x1304;
/// xray 的 `NumberOfPacketToFilter`：两个方向合计只嗅探前这么多个包。
const FILTER_PACKETS: i32 = 8;
const TLS_RECORD_HEADER_LEN: usize = 5;

/// padding 阶段每次从 TLS 读的块大小（一条 TLS 记录的明文上限）。
const READ_CHUNK: usize = 16 * 1024;
/// xray 的 `buf.Size`，padding 上限按它算。
const BUF_SIZE: usize = 8192;
/// 单帧内容上限：xray `ReshapeMultiBuffer` 会把 ≥ `buf.Size - 21` 的 buffer 拆开。
pub(crate) const MAX_FRAME_CONTENT: usize = BUF_SIZE - UUID_LEN - HEADER_LEN;
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
    let mut out = Vec::new();
    xtls_padding_into(&mut out, data, command, uuid, long_padding);
    out
}

/// 同 [`xtls_padding`]，直接追加进 `out`，省一次分配和拷贝。
fn xtls_padding_into(
    out: &mut impl BufMut,
    data: &[u8],
    command: u8,
    uuid: Option<&[u8; 16]>,
    long_padding: bool,
) {
    let pad = padding_len(data.len(), long_padding);
    if let Some(id) = uuid {
        out.put_slice(id);
    }
    out.put_u8(command);
    out.put_u16(data.len() as u16);
    out.put_u16(pad as u16);
    out.put_slice(data);
    out.put_bytes(0, pad);
}

/// 解帧状态机。对应 xray `XtlsUnpadding` 的三个 remaining 计数器。
#[derive(Debug, Default)]
pub(crate) struct Unpadder {
    /// 是否还没吃掉服务端第一帧的 UUID 前缀。
    expect_uuid: bool,
    /// 已收到 `End` 或 `Direct`：padding 结束，不再解帧，字节原样交付。
    done: bool,
    /// 收到的是 `Direct`：服务端此后越过 TLS 直写裸 TCP，读端也要跟着切。
    /// `End` 不会置它 —— 之后的数据仍是 TLS 记录（xray `proxy.go`：命令 1 只结束 padding）。
    direct: bool,
}

impl Unpadder {
    pub(crate) fn new() -> Self {
        Self { expect_uuid: true, done: false, direct: false }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    pub(crate) fn is_direct(&self) -> bool {
        self.direct
    }

    /// 尽可能从 `buf` 里解出数据追加到 `out`。
    /// 不足一整帧就原样留在 `buf` 里等更多字节。
    /// 收到 `End`/`Direct` 命令后不再解帧，其后的字节直接透传。
    pub(crate) fn unpad(&mut self, buf: &mut BytesMut, out: &mut impl BufMut) -> Result<()> {
        loop {
            if self.done {
                out.put_slice(buf);
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
            out.put_slice(&buf[..content_len]);
            buf.advance(content_len + pad_len);

            tracing::debug!(command, content_len, pad_len, "vision frame in");
            match command {
                CMD_PADDING_CONTINUE => {},
                CMD_PADDING_END => self.done = true,
                CMD_PADDING_DIRECT => {
                    self.done = true;
                    self.direct = true;
                },
                _ => return Err(RError::Protocol("unknown vision padding command".into())),
            }
        }
    }
}

/// 被代理流量的嗅探结果，读写两个方向共用。对应 xray `TrafficState` 中
/// 由 `XtlsFilterTls` 维护的那部分：写方向看到内层 ClientHello，读方向看到
/// 内层 ServerHello，后者决定能不能开 XTLS 直通。
#[derive(Debug)]
pub(crate) struct TrafficState {
    /// 还剩几个包要嗅探。判定出结果后清零。
    filter_budget: i32,
    is_tls: bool,
    /// 见到了 ServerHello（TLS 1.2 及以上）。
    is_tls12_or_above: bool,
    /// 内层是 TLS 1.3 且套件允许：padding 结束时发 Direct 而不是 End。
    enable_xtls: bool,
    cipher: u16,
    /// ServerHello 还剩多少字节没看完（可能跨多个包）。
    remaining_server_hello: i32,
}

impl TrafficState {
    pub(crate) fn new() -> Self {
        Self {
            filter_budget: FILTER_PACKETS,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: -1,
        }
    }

    /// 嗅探一个包。逐行对照 xray `proxy.go` 的 `XtlsFilterTls`。
    pub(crate) fn filter(&mut self, b: &[u8]) {
        if self.filter_budget <= 0 {
            return;
        }
        self.filter_budget -= 1;

        if b.len() >= 6 {
            if b[..3] == TLS_SERVER_HANDSHAKE_START && b[5] == TLS_HANDSHAKE_SERVER_HELLO {
                self.remaining_server_hello =
                    (i32::from(b[3]) << 8 | i32::from(b[4])) + TLS_RECORD_HEADER_LEN as i32;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                // record(5) + type(1) + len(3) + version(2) + random(32) = 43：session_id 长度
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid = b[43] as usize;
                    if let Some(c) = b.get(44 + sid..46 + sid) {
                        self.cipher = u16::from_be_bytes([c[0], c[1]]);
                    }
                }
            } else if b[..2] == TLS_HANDSHAKE_START && b[5] == TLS_HANDSHAKE_CLIENT_HELLO {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if b[..end].windows(TLS13_SUPPORTED_VERSIONS.len()).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                self.enable_xtls = XTLS_CIPHERS.contains(&self.cipher);
                tracing::debug!(cipher = self.cipher, xtls = self.enable_xtls, "vision sniffed inner tls 1.3");
                self.filter_budget = 0;
            } else if self.remaining_server_hello <= 0 {
                tracing::debug!("vision sniffed inner tls 1.2");
                self.filter_budget = 0;
            }
        }
    }
}

/// 写方向状态机。对应 xray `VisionWriter` 的 `isPadding` / `UplinkWriterDirectCopy`。
#[derive(Debug)]
pub(crate) struct Padder {
    /// 还在加 padding 阶段。
    padding: bool,
    /// padding 以 Direct 结束：此后的上行要越过外层 TLS 写裸 socket。
    direct: bool,
    /// 第一帧要带的 UUID，写一次后置 None。
    uuid: Option<[u8; 16]>,
}

impl Padder {
    pub(crate) fn new(uuid: [u8; 16]) -> Self {
        Self { padding: true, direct: false, uuid: Some(uuid) }
    }

    pub(crate) fn padding_done(&self) -> bool {
        !self.padding
    }

    pub(crate) fn wants_direct(&self) -> bool {
        self.direct
    }

    /// 伪装帧：空内容 + 长 padding，用来和 VLESS 头拼在同一次写入里遮住头的长度特征。
    /// 对应 xray 的 `XtlsPadding(nil, CommandPaddingContinue, &writeOnceUserUUID, true, ...)`。
    /// 它不是被代理的数据，不占 TLS 嗅探的名额。
    fn camouflage(&mut self) -> Vec<u8> {
        xtls_padding(&[], CMD_PADDING_CONTINUE, self.uuid.take().as_ref(), true)
    }

    /// 给一次写入加帧，返回真正要写进 TLS 流的字节。
    pub(crate) fn pad(&mut self, data: &[u8], ts: &mut TrafficState) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + UUID_LEN + HEADER_LEN + 1024);
        self.pad_into(data, ts, &mut out);
        out
    }

    /// 给一次写入加帧，追加进 `out`。对照 xray `VisionWriter.WriteMultiBuffer`：
    /// 先按 `ReshapeMultiBuffer` 拆块，逐块成帧；padding 若在这批里结束，结束命令落在最后一帧。
    pub(crate) fn pad_into(&mut self, data: &[u8], ts: &mut TrafficState, out: &mut impl BufMut) {
        ts.filter(data);
        if !self.padding {
            out.put_slice(data);
            return;
        }

        let end_command = |ts: &TrafficState| {
            if ts.enable_xtls { CMD_PADDING_DIRECT } else { CMD_PADDING_END }
        };
        let is_complete = is_complete_record(data);
        let pieces = reshape(data);
        let last = pieces.len() - 1;
        let mut long_padding = ts.is_tls;

        for (i, b) in pieces.iter().enumerate() {
            if ts.is_tls && b.len() >= 6 && b[..3] == TLS_APPLICATION_DATA_START && is_complete {
                // 内层握手结束：TLS 1.3 发 Direct（之后上行写裸 socket），否则发 End。
                self.padding = false;
                self.direct = ts.enable_xtls;
                let command = if i == last { end_command(ts) } else { CMD_PADDING_CONTINUE };
                xtls_padding_into(out, b, command, self.uuid.take().as_ref(), true);
                long_padding = false;
                continue;
            } else if !ts.is_tls12_or_above && ts.filter_budget <= 1 {
                // 不是 TLS 1.2+：嗅探名额快用完就提前结束（xray："finish padding 1 packet early"）。
                // 这批余下的块不再成帧，对端收到 End 后原样透传。
                self.padding = false;
                xtls_padding_into(out, b, CMD_PADDING_END, self.uuid.take().as_ref(), long_padding);
                for rest in &pieces[i + 1..] {
                    out.put_slice(rest);
                }
                break;
            }
            let command = if i == last && !self.padding { end_command(ts) } else { CMD_PADDING_CONTINUE };
            xtls_padding_into(out, b, command, self.uuid.take().as_ref(), long_padding);
        }
    }
}

/// 把一次写入拆成单帧装得下的块。对照 xray `ReshapeMultiBuffer`：长度 ≥ `buf.Size - 21`
/// 的块要拆，拆点优先取块内最后一个 application_data 记录头（不落在 [21, buf.Size - 21]
/// 之外），否则取 `buf.Size / 2`。xray 的块最大 8KB 只拆一刀，我们的写入可能有 64KB，循环拆。
fn reshape(data: &[u8]) -> Vec<&[u8]> {
    let mut pieces = Vec::with_capacity(data.len() / (BUF_SIZE / 2) + 1);
    let mut rest = data;
    while rest.len() >= MAX_FRAME_CONTENT {
        let window = &rest[..(MAX_FRAME_CONTENT + TLS_APPLICATION_DATA_START.len()).min(rest.len())];
        let at = window
            .windows(TLS_APPLICATION_DATA_START.len())
            .rposition(|w| w == TLS_APPLICATION_DATA_START)
            .filter(|i| (UUID_LEN + HEADER_LEN..=MAX_FRAME_CONTENT).contains(i))
            .unwrap_or(BUF_SIZE / 2);
        let (head, tail) = rest.split_at(at);
        pieces.push(head);
        rest = tail;
    }
    pieces.push(rest);
    pieces
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
    traffic: TrafficState,
    padder: Padder,
    unpadder: Unpadder,
    /// 上行已越过外层 TLS 改写裸 socket（Direct 帧已完整刷出 TLS 之后才置）。
    uplink_raw: bool,
    /// 已成帧但还没写完的字节。
    write_pending: BytesMut,
    /// 从 inner 读到、还不够一整帧的字节。
    read_raw: BytesMut,
    /// 已解出、待交付上层的数据。
    read_out: BytesMut,
    /// VLESS 响应头在读路径上惰性剥离（同步等会死锁，见 vless::ResponseHeader）。
    response_header: super::vless::ResponseHeader,
}

impl<S> VisionStream<S> {
    pub fn new(inner: S, uuid: [u8; 16]) -> Self {
        Self {
            inner,
            traffic: TrafficState::new(),
            padder: Padder::new(uuid),
            unpadder: Unpadder::new(),
            uplink_raw: false,
            write_pending: BytesMut::new(),
            read_raw: BytesMut::with_capacity(16 * 1024),
            read_out: BytesMut::new(),
            // 纯 Vision 流（测试用）不带 VLESS 响应头。
            response_header: super::vless::ResponseHeader::already_consumed(),
        }
    }

    /// 客户端出站路径的构造器。首帧要由 [`Self::write_first`] 连同 VLESS 头一起发出；
    /// VLESS **响应**头还没读，要在读路径上惰性剥离。见 docs/reference/vision-format.md。
    pub fn client(inner: S, uuid: [u8; 16]) -> Self {
        let mut s = Self::new(inner, uuid);
        s.response_header = super::vless::ResponseHeader::new();
        s
    }
}

impl<S: tokio::io::AsyncWrite + Unpin + super::record_gate::DirectSwitch> VisionStream<S> {
    /// 首次写入：VLESS 头（裸，不进 Vision 帧）‖ 第一个 Vision 帧，**一次写出**，
    /// 二者落在同一条 TLS 记录里，头的长度特征被 padding 遮住。
    /// 有首包就让它走正常的 padding（也参与 TLS 嗅探）；没有就发伪装帧。
    /// 对照 xray `vless/outbound/outbound.go` 的 BufferedWriter + `ReadMultiBufferTimeout`。
    pub async fn write_first(&mut self, header: &[u8], payload: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let frame = if payload.is_empty() {
            self.padder.camouflage()
        } else {
            self.padder.pad(payload, &mut self.traffic)
        };
        let mut first = Vec::with_capacity(header.len() + frame.len());
        first.extend_from_slice(header);
        first.extend_from_slice(&frame);
        self.inner.write_all(&first).await?;
        self.inner.flush().await
    }

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

    /// 排空已成的帧；若刚发出 Direct 帧，再把外层 TLS 完整刷出，然后才切裸写。
    /// 顺序不能反：TLS 记录还没出 socket 就开始裸写，两者会交错（xray #5737）。
    fn poll_settle(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.poll_drain(cx))?;
        if self.padder.wants_direct() && !self.uplink_raw {
            std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_flush(cx))?;
            self.uplink_raw = true;
            tracing::debug!("vision uplink switched to direct");
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl<S: tokio::io::AsyncWrite + Unpin + super::record_gate::DirectSwitch> tokio::io::AsyncWrite
    for VisionStream<S>
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;

        let me = self.get_mut();

        // 上一次成的帧还没写完：先排空（必要时完成裸写切换），避免无限缓冲。
        std::task::ready!(me.poll_settle(cx))?;

        // padding 结束后没有帧：Direct 之后写裸 socket，End 之后仍写外层 TLS。
        if me.padder.padding_done() {
            me.traffic.filter(buf);
            return if me.uplink_raw {
                std::pin::Pin::new(&mut me.inner).poll_write_direct(cx, buf)
            } else {
                std::pin::Pin::new(&mut me.inner).poll_write(cx, buf)
            };
        }

        me.padder.pad_into(buf, &mut me.traffic, &mut me.write_pending);
        // 帧已接管全部输入，故对上层报告写入完成；余下由 poll_settle / poll_flush 负责送出。
        match me.poll_settle(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(buf.len())),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_settle(cx))?;
        if me.uplink_raw {
            std::pin::Pin::new(&mut me.inner).poll_flush_direct(cx)
        } else {
            std::pin::Pin::new(&mut me.inner).poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::task::ready!(me.poll_settle(cx))?;
        // 上行已是裸流：只关套接字写端。经 TLS 关会发 close_notify，对端在裸流里
        // 读到一条 TLS alert（xray `SuppressOuterCloseNotify`）。
        if me.uplink_raw {
            std::pin::Pin::new(&mut me.inner).poll_shutdown_direct(cx)
        } else {
            std::pin::Pin::new(&mut me.inner).poll_shutdown(cx)
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin + super::record_gate::DirectSwitch> tokio::io::AsyncRead
    for VisionStream<S>
{
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

            // 已切直通：服务端此后写的是裸 TCP，越过 TLS 直接读。
            if me.unpadder.is_direct() {
                return std::pin::Pin::new(&mut me.inner).poll_read_direct(cx, buf);
            }

            // End 之后不再有帧：经 TLS 直接读进调用方的缓冲，省掉中转拷贝。
            if me.unpadder.is_done() && me.read_raw.is_empty() {
                let before = buf.filled().len();
                std::task::ready!(std::pin::Pin::new(&mut me.inner).poll_read(cx, buf))?;
                me.traffic.filter(&buf.filled()[before..]);
                return Poll::Ready(Ok(()));
            }

            // 还在 padding 阶段：放行下一条 TLS 记录，好让我们逐条检查明文里
            // 有没有 Direct 命令。见 record_gate 模块。
            me.inner.open_record_gate();

            // 直接读进 read_raw 的尾部，不经中转缓冲。
            let len = me.read_raw.len();
            me.read_raw.resize(len + READ_CHUNK, 0);
            let mut read_buf = tokio::io::ReadBuf::new(&mut me.read_raw[len..]);
            let polled = std::pin::Pin::new(&mut me.inner).poll_read(cx, &mut read_buf);
            let filled = read_buf.filled().len();
            me.read_raw.truncate(len + filled);
            std::task::ready!(polled)?;
            if filled == 0 {
                // EOF：残留的半帧只能丢弃（对端已关闭）。
                return Poll::Ready(Ok(()));
            }

            // 先吃掉 VLESS 响应头，其后才是 Vision 帧。
            let header_done = me
                .response_header
                .feed(&mut me.read_raw)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            if !header_done {
                continue;
            }

            let was_done = me.unpadder.is_done();
            let was_direct = me.unpadder.is_direct();
            // 走到这里 read_out 必为空（循环开头已交付），直接解进去。
            me.unpadder
                .unpad(&mut me.read_raw, &mut me.read_out)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            if !me.read_out.is_empty() {
                // 下行嗅探内层 ServerHello：决定上行结束 padding 时发 Direct 还是 End。
                me.traffic.filter(&me.read_out);
            }

            // 刚收到 End：此后不会再有 Direct，记录闸门停用，免得每条记录都多一次调度。
            if !was_done && me.unpadder.is_done() && !me.unpadder.is_direct() {
                me.inner.stop_record_gate();
            }

            // 刚刚切到直通：把 TLS 层下面已缓冲、尚未解析的裸字节接上，
            // 它们就是直通流的开头（等价于 Go 版合并 rawInput 的那一步）。
            if !was_direct && me.unpadder.is_direct() {
                let leftover = me.inner.take_buffered_raw();
                tracing::debug!(leftover = leftover.len(), "vision switched to direct");
                me.read_out.extend_from_slice(&leftover);
            }
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
        let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
        let first = p.pad(b"aaa", &mut ts);
        let second = p.pad(b"bbb", &mut ts);
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
        let mut u = Unpadder::default();
        u.unpad(&mut buf, &mut out).unwrap();
        assert!(out.is_empty());
        assert!(!u.is_direct());

        // 补上最后一字节即可解出
        buf.extend_from_slice(&framed[framed.len() - 1..]);
        u.unpad(&mut buf, &mut out).unwrap();
        assert_eq!(out, b"abc");
        assert!(u.done);
        assert!(!u.is_direct());
    }

    /// 收到 End 后剩余字节原样透传，不再当帧解析；但不切裸 socket。
    #[test]
    fn end_stops_unpadding_passthrough() {
        let mut framed = xtls_padding(b"last", CMD_PADDING_END, None, false);
        framed.extend_from_slice(b"raw bytes after end");

        let mut buf = BytesMut::from(&framed[..]);
        let mut out = Vec::new();
        let mut u = Unpadder::default();
        u.unpad(&mut buf, &mut out).unwrap();
        assert_eq!(out, b"lastraw bytes after end");
        assert!(!u.is_direct());
        assert!(buf.is_empty());
    }

    #[test]
    fn rejects_unknown_command() {
        let framed = xtls_padding(b"x", 0x7F, None, false);
        let mut buf = BytesMut::from(&framed[..]);
        let mut out = Vec::new();
        let mut u = Unpadder::default();
        assert!(u.unpad(&mut buf, &mut out).is_err());
    }

    /// 内层 ClientHello（0x16 0x03 0x01 ... 0x01）。
    fn client_hello() -> Vec<u8> {
        let mut ch = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        ch.extend_from_slice(&[0u8; 4]);
        ch
    }

    /// 完整的内层 application_data 记录。
    fn app_data() -> Vec<u8> {
        let mut ad = vec![0x17, 0x03, 0x03, 0x00, 0x08];
        ad.extend_from_slice(&[0x42u8; 8]);
        ad
    }

    /// 内层 ServerHello 记录。`tls13` 决定是否带 supported_versions(0x0304) 扩展。
    fn server_hello(cipher: u16, tls13: bool) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x5A; 32]); // random
        body.push(32);
        body.extend_from_slice(&[0x33; 32]); // legacy_session_id_echo
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0); // compression
        let mut exts = vec![0x00, 0x33, 0x00, 0x02, 0x00, 0x1d]; // 随便一个扩展垫位置
        if tls13 {
            exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x02, 0x00];
        hs.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x03];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sniffs_tls13_server_hello_enables_xtls() {
        let mut ts = TrafficState::new();
        ts.filter(&server_hello(0x1301, true));
        assert!(ts.is_tls && ts.is_tls12_or_above && ts.enable_xtls);
        assert_eq!(ts.filter_budget, 0, "判定出结果后停止嗅探");
    }

    /// TLS_AES_128_CCM_8_SHA256 不开 XTLS（xray `XtlsFilterTls`）。
    #[test]
    fn sniffs_tls13_ccm8_without_xtls() {
        let mut ts = TrafficState::new();
        ts.filter(&server_hello(0x1305, true));
        assert!(ts.is_tls12_or_above && !ts.enable_xtls);
    }

    #[test]
    fn sniffs_tls12_server_hello() {
        let mut ts = TrafficState::new();
        ts.filter(&server_hello(0xc02f, false));
        assert!(ts.is_tls && ts.is_tls12_or_above && !ts.enable_xtls);
        assert_eq!(ts.filter_budget, 0);
    }

    #[test]
    fn sniffs_client_hello_and_counts_packets() {
        let mut ts = TrafficState::new();
        ts.filter(&client_hello());
        assert!(ts.is_tls && !ts.is_tls12_or_above);
        assert_eq!(ts.filter_budget, 7);
    }

    /// 非 TLS 流量：嗅探名额快用完时提前发 End 结束 padding（xray："finish padding
    /// 1 packet early"）。名额两个方向共用，第 7 个包之后只剩 1 个。
    #[test]
    fn plain_traffic_ends_padding_when_filter_runs_out() {
        let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
        let first = p.pad(b"plain http payload", &mut ts);
        assert_eq!(first[UUID_LEN], CMD_PADDING_CONTINUE);
        for _ in 0..5 {
            assert_eq!(p.pad(b"more", &mut ts)[0], CMD_PADDING_CONTINUE);
        }
        assert!(!p.padding_done());

        assert_eq!(p.pad(b"seventh", &mut ts)[0], CMD_PADDING_END);
        assert!(p.padding_done() && !p.wants_direct());
        assert_eq!(p.pad(b"after", &mut ts), b"after");
    }

    /// 非 TLS 流量用短 padding（xray：`longPadding := IsTLS`）。
    #[test]
    fn plain_traffic_uses_short_padding() {
        for _ in 0..20 {
            let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
            let framed = p.pad(b"x", &mut ts);
            let pad_len = u16::from_be_bytes([framed[UUID_LEN + 3], framed[UUID_LEN + 4]]);
            assert!((pad_len as u32) < SEED_SHORT_RANGE);
        }
    }

    /// 内层 TLS 1.3：完整 application_data 记录这一帧发 Direct，并要求切裸写。
    #[test]
    fn tls13_application_data_sends_direct() {
        let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
        assert_eq!(p.pad(&client_hello(), &mut ts)[UUID_LEN], CMD_PADDING_CONTINUE);
        ts.filter(&server_hello(0x1301, true)); // 下行读路径嗅探到的
        assert!(!p.padding_done());

        assert_eq!(p.pad(&app_data(), &mut ts)[0], CMD_PADDING_DIRECT);
        assert!(p.padding_done() && p.wants_direct());
        assert_eq!(p.pad(b"raw", &mut ts), b"raw");
    }

    /// 内层 TLS 1.2（或没见到 ServerHello）：同一位置发 End，仍走外层 TLS。
    #[test]
    fn tls12_application_data_sends_end() {
        let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
        p.pad(&client_hello(), &mut ts);
        ts.filter(&server_hello(0xc02f, false));

        assert_eq!(p.pad(&app_data(), &mut ts)[0], CMD_PADDING_END);
        assert!(p.padding_done() && !p.wants_direct());
    }

    /// 逐帧解析：返回每帧的 (command, content)。
    fn frames(mut wire: &[u8], first_has_uuid: bool) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        if first_has_uuid {
            wire = &wire[UUID_LEN..];
        }
        while !wire.is_empty() {
            let (cmd, clen, plen) = (
                wire[0],
                u16::from_be_bytes([wire[1], wire[2]]) as usize,
                u16::from_be_bytes([wire[3], wire[4]]) as usize,
            );
            assert!(HEADER_LEN + UUID_LEN + clen + plen <= BUF_SIZE, "帧超出 xray buf.Size");
            out.push((cmd, wire[HEADER_LEN..HEADER_LEN + clen].to_vec()));
            wire = &wire[HEADER_LEN + clen + plen..];
        }
        out
    }

    /// 大块写入要按 xray `ReshapeMultiBuffer` 拆成多帧：每帧内容 < buf.Size - 21，
    /// 否则 64KB 的写入会让 u16 的 contentLen 溢出。
    #[test]
    fn large_write_is_reshaped_into_frames() {
        for size in [8171, 8192, 20_000, 65_536] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
            let wire = p.pad(&data, &mut ts);

            let fs = frames(&wire, true);
            assert!(fs.len() >= 2, "size {size} 没被拆开");
            assert!(fs.iter().all(|(cmd, c)| *cmd == CMD_PADDING_CONTINUE && c.len() <= MAX_FRAME_CONTENT));
            assert_eq!(fs.concat_content(), data, "size {size}");
        }
    }

    /// 拆分点优先落在 application_data 记录头上；整批的最后一帧才带 Direct。
    #[test]
    fn reshape_splits_at_record_boundaries_and_ends_on_last_frame() {
        let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
        p.pad(&client_hello(), &mut ts);
        ts.filter(&server_hello(0x1301, true));

        let mut data = Vec::new();
        for _ in 0..4 {
            data.extend_from_slice(&[0x17, 0x03, 0x03]);
            data.extend_from_slice(&5000u16.to_be_bytes());
            data.extend_from_slice(&[0x42; 5000]);
        }
        let fs = frames(&p.pad(&data, &mut ts), false);

        assert!(fs.len() >= 2);
        assert!(fs.iter().all(|(_, c)| c[..3] == TLS_APPLICATION_DATA_START), "拆在了记录中间");
        let (last, init) = fs.split_last().unwrap();
        assert!(init.iter().all(|(cmd, _)| *cmd == CMD_PADDING_CONTINUE));
        assert_eq!(last.0, CMD_PADDING_DIRECT);
        assert!(p.wants_direct());
        assert_eq!(fs.concat_content(), data);
    }

    trait ConcatContent {
        fn concat_content(&self) -> Vec<u8>;
    }

    impl ConcatContent for Vec<(u8, Vec<u8>)> {
        fn concat_content(&self) -> Vec<u8> {
            self.iter().flat_map(|(_, c)| c.clone()).collect()
        }
    }

    /// application_data 记录不完整时不能结束 padding（长度字段说还有更多字节）。
    #[test]
    fn incomplete_record_does_not_switch() {
        let (mut p, mut ts) = (Padder::new(UUID), TrafficState::new());
        p.pad(&client_hello(), &mut ts);
        ts.filter(&server_hello(0x1301, true));

        // 声称载荷 8 字节，实际只给 3
        let mut partial = vec![0x17, 0x03, 0x03, 0x00, 0x08];
        partial.extend_from_slice(&[0x42u8; 3]);
        let framed = p.pad(&partial, &mut ts);
        assert_eq!(framed[0], CMD_PADDING_CONTINUE);
        assert!(!p.padding_done());
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

    /// 出站路径：VLESS 响应头必须在读路径上被吃掉，且不能同步等它（会死锁）。
    #[tokio::test]
    async fn stream_strips_vless_response_header_lazily() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::client(sock, UUID);

        // 客户端必须能在收到任何下行字节之前就把上行载荷发出去，
        // 否则就是那个环等死锁。
        vs.write_all(b"uplink first").await.unwrap();
        vs.flush().await.unwrap();
        let mut sink = vec![0u8; 4096];
        let n = peer.read(&mut sink).await.unwrap();
        assert!(n > 0, "上行数据没能在收到响应头之前发出 —— 死锁");

        // 服务端这才回：VLESS 响应头(ver=0, addonLen=0) + Vision 帧
        let mut wire = vec![0x00, 0x00];
        wire.extend_from_slice(&xtls_padding(b"downlink", CMD_PADDING_END, Some(&UUID), false));
        peer.write_all(&wire).await.unwrap();
        peer.flush().await.unwrap();

        let mut got = vec![0u8; 8];
        vs.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"downlink");
    }

    /// 响应头带 addons 时也要正确跳过。
    #[tokio::test]
    async fn stream_skips_response_header_with_addons() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::client(sock, UUID);

        let mut wire = vec![0x00, 0x03, 0xAA, 0xBB, 0xCC];
        wire.extend_from_slice(&xtls_padding(b"payload", CMD_PADDING_END, Some(&UUID), false));
        peer.write_all(&wire).await.unwrap();
        peer.flush().await.unwrap();

        let mut got = vec![0u8; 7];
        vs.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"payload");
    }

    /// 首次写入 = VLESS 头（裸）‖ 携带首包的第一个 Vision 帧（带 UUID 前缀），一次写出。
    #[tokio::test]
    async fn first_write_merges_header_and_payload() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::client(sock, UUID);
        vs.write_first(b"HDR", b"client hello").await.unwrap();
        vs.write_all(b" and more").await.unwrap();
        vs.flush().await.unwrap();

        let mut raw = vec![0u8; 8192];
        let n = peer.read(&mut raw).await.unwrap();
        assert_eq!(&raw[..3], b"HDR");
        let (_, out) = unpad_all(&raw[3..n]);
        assert_eq!(out, b"client hello and more");
    }

    /// 没有首包（服务端先说话的协议）：头后面跟空内容的伪装帧，之后的帧不再带 UUID。
    #[tokio::test]
    async fn first_write_without_payload_sends_camouflage() {
        let (mut peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::client(sock, UUID);
        vs.write_first(b"HDR", b"").await.unwrap();

        let mut raw = vec![0u8; 8192];
        let n = peer.read(&mut raw).await.unwrap();
        assert_eq!(&raw[..3], b"HDR");
        assert_eq!(&raw[3..3 + UUID_LEN], &UUID);
        assert_eq!(raw[3 + UUID_LEN], CMD_PADDING_CONTINUE);
        let (_, out) = unpad_all(&raw[3..n]);
        assert!(out.is_empty());

        vs.write_all(b"later").await.unwrap();
        vs.flush().await.unwrap();
        let n2 = peer.read(&mut raw[n..]).await.unwrap();
        let (_, out) = unpad_all(&raw[3..n + n2]);
        assert_eq!(out, b"later");
    }

    /// 首包多半是内层 ClientHello，必须经过 Padder 的 TLS 嗅探，否则永远切不了直通。
    #[tokio::test]
    async fn first_payload_feeds_tls_sniffing() {
        let (_peer, sock) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::client(sock, UUID);
        vs.write_first(b"HDR", &client_hello()).await.unwrap();
        assert!(vs.traffic.is_tls);

        vs.write_all(&app_data()).await.unwrap();
        assert!(vs.padder.padding_done());
    }

    /// 测试替身：区分"经 TLS 读"（`tls`）与"越过 TLS 读裸 socket"（`raw`）。
    struct SplitInner {
        tls: tokio::io::DuplexStream,
        raw: tokio::io::DuplexStream,
        gate_stopped: bool,
    }

    impl tokio::io::AsyncRead for SplitInner {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.tls).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for SplitInner {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.tls).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.tls).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.tls).poll_shutdown(cx)
        }
    }

    impl super::super::record_gate::DirectSwitch for SplitInner {
        fn stop_record_gate(&mut self) {
            self.gate_stopped = true;
        }

        fn poll_read_direct(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.raw), cx, buf)
        }

        fn poll_write_direct(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.raw), cx, buf)
        }

        fn poll_flush_direct(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.raw), cx)
        }

        fn poll_shutdown_direct(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.raw), cx)
        }
    }

    /// 读满 `want` 字节；超时说明读错了来源。
    async fn read_n<R: tokio::io::AsyncRead + Unpin>(r: &mut R, want: usize) -> Vec<u8> {
        let mut got = vec![0u8; want];
        tokio::time::timeout(std::time::Duration::from_secs(2), r.read_exact(&mut got))
            .await
            .expect("读超时：数据没从预期的来源到达")
            .unwrap();
        got
    }

    /// `End` 只结束 padding，之后的数据**仍然经 TLS 读**（xray `proxy.go`：
    /// 命令 1 只置 `withinPaddingBuffers = false`）。明文 HTTP、内层 TLS 1.2 走这条路。
    #[tokio::test]
    async fn end_keeps_reading_through_tls() {
        let (mut tls_peer, tls) = tokio::io::duplex(64 * 1024);
        let (mut raw_peer, raw) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(SplitInner { tls, raw, gate_stopped: false }, UUID);

        tls_peer.write_all(&xtls_padding(b"hello", CMD_PADDING_END, Some(&UUID), false)).await.unwrap();
        assert_eq!(read_n(&mut vs, 5).await, b"hello");
        assert!(!vs.unpadder.is_direct());

        // 之后的数据在后续 TLS 记录里到达；裸 socket 上的字节不该被读到。
        raw_peer.write_all(b"WRONG: raw socket bytes").await.unwrap();
        tls_peer.write_all(b" after end via tls").await.unwrap();
        assert_eq!(read_n(&mut vs, 18).await, b" after end via tls");
    }

    /// 收到 End 后不会再有 Direct，记录闸门没用了，应当停用（省掉逐条记录的调度）。
    #[tokio::test]
    async fn end_stops_record_gating() {
        let (mut tls_peer, tls) = tokio::io::duplex(64 * 1024);
        let (_raw_peer, raw) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(SplitInner { tls, raw, gate_stopped: false }, UUID);

        tls_peer.write_all(&xtls_padding(b"pad", CMD_PADDING_CONTINUE, Some(&UUID), false)).await.unwrap();
        assert_eq!(read_n(&mut vs, 3).await, b"pad");
        assert!(!vs.inner.gate_stopped, "padding 阶段闸门必须开着");

        tls_peer.write_all(&xtls_padding(b"end", CMD_PADDING_END, None, false)).await.unwrap();
        assert_eq!(read_n(&mut vs, 3).await, b"end");
        assert!(vs.inner.gate_stopped);
    }

    /// `Direct` 才切到越过 TLS 直接读裸 socket。
    #[tokio::test]
    async fn direct_switches_to_raw_socket() {
        let (mut tls_peer, tls) = tokio::io::duplex(64 * 1024);
        let (mut raw_peer, raw) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(SplitInner { tls, raw, gate_stopped: false }, UUID);

        tls_peer.write_all(&xtls_padding(b"hello", CMD_PADDING_DIRECT, Some(&UUID), false)).await.unwrap();
        raw_peer.write_all(b" raw tail").await.unwrap();

        assert_eq!(read_n(&mut vs, 14).await, b"hello raw tail");
        assert!(vs.unpadder.is_direct());
    }

    /// 上行 Direct：下行嗅探到内层 TLS 1.3 ServerHello 后，第一个完整 application_data
    /// 记录发 Direct 帧（仍经 TLS），**此后**的上行写裸 socket。Direct 帧必须先完整
    /// 刷出 TLS，裸写才开始（xray #5737 修的就是这里的竞态）。
    #[tokio::test]
    async fn uplink_direct_switches_writes_to_raw_socket() {
        let (mut tls_peer, tls) = tokio::io::duplex(64 * 1024);
        let (mut raw_peer, raw) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(SplitInner { tls, raw, gate_stopped: false }, UUID);

        vs.write_all(&client_hello()).await.unwrap();
        let sh = server_hello(0x1301, true);
        tls_peer.write_all(&xtls_padding(&sh, CMD_PADDING_CONTINUE, Some(&UUID), true)).await.unwrap();
        assert_eq!(read_n(&mut vs, sh.len()).await, sh);
        assert!(vs.traffic.enable_xtls, "读路径要嗅探内层 ServerHello");

        vs.write_all(&app_data()).await.unwrap();
        vs.write_all(b"raw uplink").await.unwrap();
        vs.flush().await.unwrap();

        // TLS 侧：ClientHello 帧 + Direct 帧（携带 app_data），之后没有别的。
        let mut wire = vec![0u8; 8192];
        let n = tls_peer.read(&mut wire).await.unwrap();
        let (u, out) = unpad_all(&wire[..n]);
        assert!(u.is_direct());
        let mut want = client_hello();
        want.extend_from_slice(&app_data());
        assert_eq!(out, want);

        // 裸 socket 侧：Direct 之后的上行数据。
        assert_eq!(read_n(&mut raw_peer, 10).await, b"raw uplink");
    }

    /// 上行已切裸 socket 后关闭：只关裸 socket 的写端，不能经 TLS 发 close_notify
    /// （xray `SuppressOuterCloseNotify`），否则对端在裸流里读到一条 TLS alert。
    #[tokio::test]
    async fn shutdown_after_uplink_direct_skips_tls() {
        let (mut tls_peer, tls) = tokio::io::duplex(64 * 1024);
        let (mut raw_peer, raw) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(SplitInner { tls, raw, gate_stopped: false }, UUID);

        vs.write_all(&client_hello()).await.unwrap();
        vs.traffic.filter(&server_hello(0x1301, true));
        vs.write_all(&app_data()).await.unwrap();
        vs.write_all(b"bye").await.unwrap();
        vs.shutdown().await.unwrap();

        assert_eq!(read_n(&mut raw_peer, 3).await, b"bye");
        let mut rest = Vec::new();
        raw_peer.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "裸 socket 写端应已关闭");

        let mut wire = vec![0u8; 8192];
        let _ = tls_peer.read(&mut wire).await.unwrap(); // 两个帧
        let closed = tokio::time::timeout(std::time::Duration::from_millis(100), tls_peer.read(&mut wire)).await;
        assert!(closed.is_err(), "TLS 侧不该被关闭（不该有 close_notify / shutdown）");
    }

    /// 没切裸写（End 路径）时关闭照常走 TLS。
    #[tokio::test]
    async fn shutdown_without_uplink_direct_uses_tls() {
        let (mut tls_peer, tls) = tokio::io::duplex(64 * 1024);
        let (_raw_peer, raw) = tokio::io::duplex(64 * 1024);
        let mut vs = VisionStream::new(SplitInner { tls, raw, gate_stopped: false }, UUID);

        vs.write_all(b"plain").await.unwrap();
        vs.shutdown().await.unwrap();
        let mut all = Vec::new();
        tls_peer.read_to_end(&mut all).await.unwrap();
        let (_, out) = unpad_all(&all);
        assert_eq!(out, b"plain");
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
