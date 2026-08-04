use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr };

use tokio::io::{ AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt };

use crate::error::{ Result, RError };
use crate::net::{ Address, Target };

/// 完成 no-auth 协商并读取 CONNECT 请求，返回目标地址；**不**发送回复。
pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<Target> {
    // ---- greeting ----
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(RError::Socks5("unsupported version"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        s.write_all(&[0x05, 0xFF]).await?;
        return Err(RError::Socks5("no acceptable auth method"));
    }
    s.write_all(&[0x05, 0x00]).await?; // no-auth

    // ---- request ----
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(RError::Socks5("bad request version"));
    }
    if req[1] != 0x01 {
        return Err(RError::Socks5("only CONNECT supported"));
    }
    let addr = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Address::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        },
        0x04 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            Address::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        },
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            Address::Domain(String::from_utf8(d).map_err(|_| RError::Socks5("bad domain"))?)
        },
        _ => return Err(RError::Socks5("bad ATYP")),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;

    Ok(Target { addr, port: u16::from_be_bytes(p) })
}

/// 回复 CONNECT 结果；BND 字段固定填 0.0.0.0:0（客户端不使用）。
pub async fn reply<S: AsyncWrite + Unpin>(s: &mut S, ok: bool) -> Result<()> {
    let rep = if ok { 0x00 } else { 0x01 };
    // VER REP RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
    s.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{ AsyncReadExt, AsyncWriteExt, duplex };
    use crate::net::Address;

    /// 模拟一个正常客户端：发 no-auth greeting、读方法回复、再发请求。
    /// （必须读回复——否则连接在 handshake 写回复前就被丢弃，得到 BrokenPipe。）
    fn spawn_client(mut client: tokio::io::DuplexStream, req: Vec<u8>) {
        tokio::spawn(async move {
            // greeting: VER=5, NMETHODS=1, METHOD=0
            client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [0x05, 0x00]);
            client.write_all(&req).await.unwrap();
        });
    }

    #[tokio::test]
    async fn parses_domain_connect() {
        let (client, mut server) = duplex(1024);
        // request: VER CMD RSV ATYP(domain) LEN "ex.com" PORT 443
        let mut req = vec![0x05, 0x01, 0x00, 0x03, 0x06];
        req.extend_from_slice(b"ex.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        spawn_client(client, req);

        let target = handshake(&mut server).await.unwrap();
        match target.addr {
            Address::Domain(d) => assert_eq!(d, "ex.com"),
            _ => panic!(),
        }
        assert_eq!(target.port, 443);
    }

    #[tokio::test]
    async fn rejects_bad_version() {
        let (mut client, mut server) = duplex(16);
        tokio::spawn(async move {
            client.write_all(&[0x04, 0x01, 0x00]).await.unwrap();
        });
        assert!(handshake(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn parses_ipv4_connect() {
        let (client, mut server) = duplex(64);
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4];
        req.extend_from_slice(&80u16.to_be_bytes());
        spawn_client(client, req);

        let t = handshake(&mut server).await.unwrap();
        match t.addr {
            Address::Ip(ip) => assert_eq!(ip.to_string(), "1.2.3.4"),
            _ => panic!(),
        }
        assert_eq!(t.port, 80);
    }

    #[tokio::test]
    async fn parses_ipv6_connect() {
        let (client, mut server) = duplex(64);
        let mut req = vec![0x05, 0x01, 0x00, 0x04];
        req.extend_from_slice(&[0u8; 15]);
        req.push(1);
        req.extend_from_slice(&443u16.to_be_bytes());
        spawn_client(client, req);

        let t = handshake(&mut server).await.unwrap();
        match t.addr {
            Address::Ip(ip) => assert_eq!(ip.to_string(), "::1"),
            _ => panic!(),
        }
    }

    /// 非 CONNECT 命令（如 UDP ASSOCIATE）第一版不支持。
    #[tokio::test]
    async fn rejects_non_connect_command() {
        let (client, mut server) = duplex(64);
        spawn_client(client, vec![0x05, 0x03, 0x00, 0x01, 1, 2, 3, 4, 0, 80]);

        assert!(handshake(&mut server).await.is_err());
    }

    /// 客户端不提供 no-auth 时要回 0xFF 并失败。
    #[tokio::test]
    async fn rejects_when_no_acceptable_method() {
        let (mut client, mut server) = duplex(64);
        let task = tokio::spawn(async move {
            client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut resp = [0u8; 2];
            client.read_exact(&mut resp).await.unwrap();
            resp
        });
        assert!(handshake(&mut server).await.is_err());
        assert_eq!(task.await.unwrap(), [0x05, 0xFF]);
    }

    #[tokio::test]
    async fn reply_writes_success_frame() {
        let (mut client, mut server) = duplex(64);
        reply(&mut server, true).await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn reply_writes_failure_frame() {
        let (mut client, mut server) = duplex(64);
        reply(&mut server, false).await.unwrap();
        let mut buf = [0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[1], 0x01);
    }
}
