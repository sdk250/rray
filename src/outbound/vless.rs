//! VLESS 请求/响应头编解码。
//! 字节布局对照 xray-core `proxy/vless/encoding/encoding.go`，见 docs/reference/vless-format.md。

use std::net::IpAddr;

use tokio::io::{ AsyncRead, AsyncReadExt };

use crate::error::{ Result, RError };
use crate::net::{ Address, Target };

const VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
// 注意：与 SOCKS5 的 ATYP 取值不同。
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// addons protobuf：`Addons { string Flow = 1; }` → tag 0x0A, len, bytes。Seed 省略。
/// flow 为空时 xray 只写一个 0 长度字节，故这里返回空 Vec。
fn encode_addons(flow: &str) -> Vec<u8> {
    if flow.is_empty() {
        return Vec::new();
    }
    let f = flow.as_bytes();
    let mut v = Vec::with_capacity(2 + f.len());
    v.push(0x0A); // field 1, wire type 2 (length-delimited)
    v.push(f.len() as u8); // flow 字符串长度（< 128，单字节 varint）
    v.extend_from_slice(f);
    v
}

pub fn encode_request_header(uuid: &[u8; 16], flow: &str, target: &Target) -> Vec<u8> {
    let addons = encode_addons(flow);
    let mut h = Vec::with_capacity(24 + addons.len());
    h.push(VERSION);
    h.extend_from_slice(uuid);
    h.push(addons.len() as u8);
    h.extend_from_slice(&addons);
    h.push(CMD_TCP);
    h.extend_from_slice(&target.port.to_be_bytes()); // 大端
    match &target.addr {
        Address::Ip(IpAddr::V4(ip)) => {
            h.push(ATYP_IPV4);
            h.extend_from_slice(&ip.octets());
        },
        Address::Domain(d) => {
            h.push(ATYP_DOMAIN);
            h.push(d.len() as u8);
            h.extend_from_slice(d.as_bytes());
        },
        Address::Ip(IpAddr::V6(ip)) => {
            h.push(ATYP_IPV6);
            h.extend_from_slice(&ip.octets());
        },
    }
    h
}

/// 在**读路径**上惰性剥离响应头 `version(1) | addonLen(1) | addons`。
///
/// 不能在发完请求后同步等这个头：xray 服务端把响应头写在 BufferedWriter 里，
/// 要等有下行数据才 flush，而下行数据又要等我们先发上行载荷 —— 同步等会死锁。
/// （xray 自己的客户端把读响应头放在独立 goroutine 里。）
#[derive(Debug, Default)]
pub struct ResponseHeader {
    done: bool,
}

impl ResponseHeader {
    pub fn new() -> Self {
        Self { done: false }
    }

    /// 响应头已由别处消费（或本来就没有）时用这个。
    pub fn already_consumed() -> Self {
        Self { done: true }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// 尝试从 `buf` 头部吃掉响应头。字节不够就原样留着，返回 `Ok(false)`。
    pub fn feed(&mut self, buf: &mut bytes::BytesMut) -> Result<bool> {
        use bytes::Buf;

        if self.done {
            return Ok(true);
        }
        if buf.len() < 2 {
            return Ok(false);
        }
        if buf[0] != VERSION {
            return Err(RError::Vless("bad response version".into()));
        }
        let addon_len = buf[1] as usize;
        if buf.len() < 2 + addon_len {
            return Ok(false);
        }
        buf.advance(2 + addon_len);
        self.done = true;
        Ok(true)
    }
}

/// 同步读掉响应头。仅用于测试与不存在死锁风险的场景。
#[allow(dead_code)]
pub async fn read_response_header<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).await?; // version, addonLen
    if head[0] != VERSION {
        return Err(RError::Vless("bad response version".into()));
    }
    let addon_len = head[1] as usize;
    if addon_len > 0 {
        let mut buf = vec![0u8; addon_len];
        r.read_exact(&mut buf).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{ Ipv4Addr, Ipv6Addr };
    use crate::net::{ Address, Target };
    use tokio::io::{ AsyncReadExt, AsyncWriteExt, duplex };

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53,
        0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
    ];

    #[test]
    fn encodes_domain_vision_header() {
        let t = Target { addr: Address::Domain("ex.com".into()), port: 443 };
        let h = encode_request_header(&UUID, "xtls-rprx-vision", &t);
        assert_eq!(h[0], 0x00); // version
        assert_eq!(&h[1..17], &UUID); // uuid
        let addon_len = h[17] as usize; // addons protobuf length
        let mut p = 18 + addon_len;
        assert_eq!(h[p], 0x01);
        p += 1; // command = TCP
        assert_eq!(&h[p..p + 2], &443u16.to_be_bytes());
        p += 2; // port
        assert_eq!(h[p], 0x02);
        p += 1; // atyp = domain
        assert_eq!(h[p], 6);
        p += 1; // domain len
        assert_eq!(&h[p..p + 6], b"ex.com");
    }

    /// addons = protobuf `Addons{Flow=1}`，即 tag 0x0A + len + utf8。
    /// 对照 xray `EncodeHeaderAddons` / addons.proto。
    #[test]
    fn addons_are_flow_protobuf() {
        let t = Target { addr: Address::Domain("ex.com".into()), port: 443 };
        let h = encode_request_header(&UUID, "xtls-rprx-vision", &t);
        assert_eq!(h[17], 18); // 2 字节 tag/len + 16 字节 flow
        assert_eq!(h[18], 0x0A); // field 1, wire type 2
        assert_eq!(h[19], 16);
        assert_eq!(&h[20..36], b"xtls-rprx-vision");
    }

    /// flow 为空时只写一个 0 长度字节，不写 protobuf。
    #[test]
    fn empty_flow_writes_zero_addon_len() {
        let t = Target { addr: Address::Ip(Ipv4Addr::new(1, 2, 3, 4).into()), port: 80 };
        let h = encode_request_header(&UUID, "", &t);
        assert_eq!(h[17], 0);
        assert_eq!(h[18], 0x01); // 紧接着就是 command
    }

    /// VLESS 的 atyp 与 SOCKS5 不同：IPv4=1 / Domain=2 / IPv6=3。
    #[test]
    fn ip_atyp_values() {
        let v4 = encode_request_header(
            &UUID, "", &Target { addr: Address::Ip(Ipv4Addr::new(1, 2, 3, 4).into()), port: 80 }
        );
        assert_eq!(v4[21], 0x01);
        assert_eq!(&v4[22..26], &[1, 2, 3, 4]);

        let v6 = encode_request_header(
            &UUID, "", &Target { addr: Address::Ip(Ipv6Addr::LOCALHOST.into()), port: 80 }
        );
        assert_eq!(v6[21], 0x03);
        assert_eq!(&v6[22..38], &Ipv6Addr::LOCALHOST.octets());
    }

    #[tokio::test]
    async fn reads_response_header() {
        let (mut a, mut b) = duplex(64);
        tokio::spawn(async move {
            // ver=0, addonLen=0, then payload
            a.write_all(&[0x00, 0x00, 0xAB, 0xCD]).await.unwrap();
        });
        read_response_header(&mut b).await.unwrap();
        // 头消费后，剩余的 0xAB 0xCD 由调用方继续读
        let mut rest = [0u8; 2];
        b.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, [0xAB, 0xCD]);
    }

    #[tokio::test]
    async fn skips_response_addons() {
        let (mut a, mut b) = duplex(64);
        tokio::spawn(async move {
            a.write_all(&[0x00, 0x03, 0x11, 0x22, 0x33, 0xEE]).await.unwrap();
        });
        read_response_header(&mut b).await.unwrap();
        let mut rest = [0u8; 1];
        b.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, [0xEE]);
    }

    #[tokio::test]
    async fn rejects_bad_response_version() {
        let (mut a, mut b) = duplex(64);
        tokio::spawn(async move {
            a.write_all(&[0x01, 0x00]).await.unwrap();
        });
        assert!(read_response_header(&mut b).await.is_err());
    }
}
