pub mod reality;
pub mod record_gate;
pub mod vision;
pub mod vless;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{ OutboundCfg, TimeoutCfg };
use crate::error::{ Result, RError };
use crate::net::{ dial, Target };
use record_gate::RecordGate;
use vision::VisionStream;

/// 第一版只支持 Vision flow；其它 flow 的分支（无 flow 直连）不在本阶段范围内。
const REQUIRED_FLOW: &str = "xtls-rprx-vision";

/// 打开一条出站连接：拨号 → Reality 握手 → VLESS 头 → Vision 包裹。
pub async fn open(
    out: &OutboundCfg,
    to: &TimeoutCfg,
    target: &Target,
) -> Result<VisionStream<tokio_rustls::client::TlsStream<RecordGate<TcpStream>>>> {
    if out.vless.flow != REQUIRED_FLOW {
        return Err(RError::Config(
            format!("only flow \"{REQUIRED_FLOW}\" is supported, got \"{}\"", out.vless.flow).into()
        ));
    }

    let tcp = dial(&out.server, out.port, to.connect_ms, to.dial_retries).await?;
    // 在 TCP 与 rustls 之间夹一层记录闸门，握手期间透明，握手后启用 ——
    // Vision 切 Direct 时要靠它拿回"TLS 层已预读但还没解析"的裸字节。
    let mut tls = reality::connect(RecordGate::new(tcp), &out.reality, to.handshake_ms).await?;
    tracing::debug!("reality handshake ok");
    tls.get_mut().0.start_gating();

    // VLESS 头本身不进 Vision 帧，但必须与第一个 Vision 帧**一次写出**，
    // 这样二者落在同一条 TLS 记录里，头的长度特征被 padding 遮住。
    // 对照 xray `vless/outbound/outbound.go` 的 BufferedWriter + 空内容伪装帧。
    let mut first = vless::encode_request_header(&out.vless.uuid, &out.vless.flow, target);
    first.extend_from_slice(&vision::camouflage_frame(&out.vless.uuid));
    tls.write_all(&first).await?;
    tls.flush().await?;

    // 这里**不能**同步等 VLESS 响应头：xray 服务端把它写在 BufferedWriter 里，
    // 要等有下行数据才 flush；而下行数据要等目标站响应，目标站又要等我们把
    // 客户端载荷送上去 —— 而客户端要等 SOCKS5 回复才发载荷。同步等即死锁。
    // 响应头改由 VisionStream 在读路径上惰性剥离。
    Ok(VisionStream::with_first_frame_sent(tls))
}
