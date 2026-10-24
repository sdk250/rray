pub mod reality;
pub mod record_gate;
pub mod vision;
pub mod vless;

use tokio::io::{ AsyncRead, AsyncReadExt };
use tokio::net::TcpStream;
use tokio::time::{ timeout, Duration };

use crate::config::{ OutboundCfg, TimeoutCfg };
use crate::error::{ Result, RError };
use crate::net::{ dial, Target };
use record_gate::RecordGate;
use vision::VisionStream;

/// 第一版只支持 Vision flow；其它 flow 的分支（无 flow 直连）不在本阶段范围内。
const REQUIRED_FLOW: &str = "xtls-rprx-vision";

/// 握手完成后最多等客户端首包多久（xray `ReadMultiBufferTimeout(500ms)`）。
/// 首包通常早就躺在 socket 缓冲里了，这个时限只对"服务端先说话"的协议生效。
const FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(500);

/// 打开一条出站连接：拨号 → Reality 握手 → 等客户端首包 → VLESS 头 + 首帧 → Vision 包裹。
pub async fn open<R: AsyncRead + Unpin>(
    out: &OutboundCfg,
    to: &TimeoutCfg,
    target: &Target,
    client: &mut R,
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

    let payload = read_first_payload(client, FIRST_PAYLOAD_WAIT).await?;
    let header = vless::encode_request_header(&out.vless.uuid, &out.vless.flow, target);
    let mut vs = VisionStream::client(tls, out.vless.uuid);
    vs.write_first(&header, &payload).await?;

    // 这里**不能**同步等 VLESS 响应头：xray 服务端把它写在 BufferedWriter 里，
    // 要等有下行数据才 flush；而下行数据要等目标站响应，目标站又可能要等
    // 客户端的后续载荷。同步等即死锁。响应头改由 VisionStream 在读路径上惰性剥离。
    Ok(vs)
}

/// 读客户端首包，最多等 `wait`。超时或 EOF 返回空（之后由伪装帧顶上）。
/// 读取上限是单帧内容上限，超出的部分留在 socket 里由后续转发处理。
async fn read_first_payload<R: AsyncRead + Unpin>(r: &mut R, wait: Duration) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; vision::MAX_FRAME_CONTENT];
    match timeout(wait, r.read(&mut buf)).await {
        Ok(n) => {
            buf.truncate(n?);
            Ok(buf)
        },
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncWriteExt, duplex };

    const WAIT: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn first_payload_returns_buffered_data() {
        let (mut client, mut ours) = duplex(1024);
        client.write_all(b"GET / HTTP/1.1").await.unwrap();
        assert_eq!(read_first_payload(&mut ours, WAIT).await.unwrap(), b"GET / HTTP/1.1");
    }

    /// 客户端不先发数据（服务端先说话的协议）：等满时限后返回空，不报错。
    #[tokio::test]
    async fn first_payload_times_out_empty() {
        let (_client, mut ours) = duplex(1024);
        let start = std::time::Instant::now();
        assert!(read_first_payload(&mut ours, WAIT).await.unwrap().is_empty());
        assert!(start.elapsed() >= WAIT);
    }

    #[tokio::test]
    async fn first_payload_is_empty_on_eof() {
        let (client, mut ours) = duplex(1024);
        drop(client);
        assert!(read_first_payload(&mut ours, WAIT).await.unwrap().is_empty());
    }

    /// 首包不能超过单个 Vision 帧的内容上限。
    #[tokio::test]
    async fn first_payload_fits_one_frame() {
        let (mut client, mut ours) = duplex(64 * 1024);
        client.write_all(&vec![0x42u8; 20 * 1024]).await.unwrap();
        let got = read_first_payload(&mut ours, WAIT).await.unwrap();
        assert!(!got.is_empty() && got.len() <= vision::MAX_FRAME_CONTENT);
    }
}
