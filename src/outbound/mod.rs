pub mod reality;
pub mod vision;
pub mod vless;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{ OutboundCfg, TimeoutCfg };
use crate::error::{ Result, RError };
use crate::net::{ dial, Target };
use vision::VisionStream;

/// 第一版只支持 Vision flow；其它 flow 的分支（无 flow 直连）不在本阶段范围内。
const REQUIRED_FLOW: &str = "xtls-rprx-vision";

/// 打开一条出站连接：拨号 → Reality 握手 → VLESS 头 → Vision 包裹。
pub async fn open(
    out: &OutboundCfg,
    to: &TimeoutCfg,
    target: &Target,
) -> Result<VisionStream<tokio_rustls::client::TlsStream<TcpStream>>> {
    if out.vless.flow != REQUIRED_FLOW {
        return Err(RError::Config(
            format!("only flow \"{REQUIRED_FLOW}\" is supported, got \"{}\"", out.vless.flow).into()
        ));
    }

    let tcp = dial(&out.server, out.port, to.connect_ms, to.dial_retries).await?;
    let mut tls = reality::connect(tcp, &out.reality, to.handshake_ms).await?;

    // VLESS 头本身不进 Vision 帧，但必须与第一个 Vision 帧**一次写出**，
    // 这样二者落在同一条 TLS 记录里，头的长度特征被 padding 遮住。
    // 对照 xray `vless/outbound/outbound.go` 的 BufferedWriter + 空内容伪装帧。
    let mut first = vless::encode_request_header(&out.vless.uuid, &out.vless.flow, target);
    first.extend_from_slice(&vision::camouflage_frame(&out.vless.uuid));
    tls.write_all(&first).await?;
    tls.flush().await?;

    // 响应头也是裸的（不带 Vision 帧），必须在套上 VisionStream 之前读掉。
    vless::read_response_header(&mut tls).await?;

    Ok(VisionStream::with_first_frame_sent(tls))
}
