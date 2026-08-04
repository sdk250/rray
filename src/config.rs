use std::net::IpAddr;

use serde::Deserialize;

use crate::error::{ Result, RError };

#[derive(Debug, Clone)]
pub struct Config {
    pub log: LogCfg,
    pub inbound: InboundCfg,
    pub outbound: OutboundCfg,
    pub timeout: TimeoutCfg,
}

#[derive(Debug, Clone)]
pub struct LogCfg {
    pub level: String,
}

#[derive(Debug, Clone)]
pub struct InboundCfg {
    pub listen: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct OutboundCfg {
    pub server: String,
    pub port: u16,
    pub vless: VlessCfg,
    pub reality: RealityCfg,
}

#[derive(Debug, Clone)]
pub struct VlessCfg {
    pub uuid: [u8; 16],
    pub flow: String,
}

#[derive(Debug, Clone)]
pub struct RealityCfg {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub server_name: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TimeoutCfg {
    pub connect_ms: u64,
    pub handshake_ms: u64,
    pub dial_retries: u32,
}

// ---- 原始可反序列化结构（贴近 TOML） ----

#[derive(Deserialize)]
struct RawConfig {
    log: RawLog,
    inbound: RawInbound,
    outbound: RawOutbound,
    timeout: RawTimeout,
}

#[derive(Deserialize)]
struct RawLog {
    level: String,
}

#[derive(Deserialize)]
struct RawInbound {
    listen: IpAddr,
    port: u16,
}

#[derive(Deserialize)]
struct RawOutbound {
    server: String,
    port: u16,
    vless: RawVless,
    reality: RawReality,
}

#[derive(Deserialize)]
struct RawVless {
    uuid: String,
    flow: String,
}

#[derive(Deserialize)]
struct RawReality {
    public_key: String,
    short_id: String,
    server_name: String,
    #[serde(default)]
    fingerprint: Option<String>,
}

#[derive(Deserialize)]
struct RawTimeout {
    connect_ms: u64,
    handshake_ms: u64,
    dial_retries: u32,
}

/// 解析 `8-4-4-4-12` 形式的 UUID 为 16 字节（连字符位置不作要求）。
pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let bytes = parse_hex(&hex)?;
    if bytes.len() != 16 {
        return Err(RError::Config("uuid must be 16 bytes".into()));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return Err(RError::Config("hex length must be even".into()));
    }
    fn nibble(c: u8) -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(RError::Config("invalid hex".into())),
        }
    }
    s.chunks(2).map(|p| Ok((nibble(p[0])? << 4) | nibble(p[1])?)).collect()
}

/// Reality 服务端公钥：xray 用 base64url 无填充；这里同时容忍标准字母表与填充。
fn parse_pubkey_b64(s: &str) -> Result<[u8; 32]> {
    let raw = base64_decode(s)?;
    if raw.len() != 32 {
        return Err(RError::Config("reality public_key must decode to 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// 极小的 base64 解码：同时接受标准（`+/`）与 URL 安全（`-_`）字母表，填充可选。
fn base64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in s {
        let v = val(c).ok_or_else(|| RError::Config("invalid base64".into()))? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

impl TryFrom<RawConfig> for Config {
    type Error = RError;

    fn try_from(r: RawConfig) -> Result<Config> {
        Ok(Config {
            log: LogCfg { level: r.log.level },
            inbound: InboundCfg { listen: r.inbound.listen, port: r.inbound.port },
            outbound: OutboundCfg {
                server: r.outbound.server,
                port: r.outbound.port,
                vless: VlessCfg {
                    uuid: parse_uuid(&r.outbound.vless.uuid)?,
                    flow: r.outbound.vless.flow,
                },
                reality: RealityCfg {
                    public_key: parse_pubkey_b64(&r.outbound.reality.public_key)?,
                    short_id: parse_hex(&r.outbound.reality.short_id)?,
                    server_name: r.outbound.reality.server_name,
                    fingerprint: r.outbound.reality.fingerprint,
                },
            },
            timeout: TimeoutCfg {
                connect_ms: r.timeout.connect_ms,
                handshake_ms: r.timeout.handshake_ms,
                dial_retries: r.timeout.dial_retries,
            },
        })
    }
}

pub fn load(path: &str) -> Result<Config> {
    let text = std::fs::read_to_string(path)?;
    let raw: RawConfig = toml::from_str(&text).map_err(|e| RError::Config(e.to_string()))?;
    raw.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[log]
level = "info"
[inbound]
listen = "127.0.0.1"
port = 1080
[outbound]
server = "ex.com"
port = 443
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

    #[test]
    fn parse_uuid_to_bytes() {
        let id = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        assert_eq!(id[0], 0xb8);
        assert_eq!(id[15], 0x11);
    }

    #[test]
    fn parse_short_id_hex() {
        assert_eq!(parse_hex("0123abcd").unwrap(), vec![0x01, 0x23, 0xab, 0xcd]);
    }

    #[test]
    fn rejects_bad_uuid() {
        assert!(parse_uuid("b831381d-6324-4d53-ad4f-8cda48b308").is_err());
        assert!(parse_uuid("zz31381d-6324-4d53-ad4f-8cda48b30811").is_err());
    }

    /// xray 的 reality public_key 是 base64url **无填充**；标准字母表也应能解。
    #[test]
    fn pubkey_accepts_both_base64_alphabets() {
        let expect: Vec<u8> = (1u8..=32).collect();
        let url = parse_pubkey_b64("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA").unwrap();
        let std = parse_pubkey_b64("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=").unwrap();
        assert_eq!(url.as_slice(), expect.as_slice());
        assert_eq!(std.as_slice(), expect.as_slice());
    }

    #[test]
    fn rejects_short_pubkey() {
        assert!(parse_pubkey_b64("MC4CAQAwBQYDK2VuBCIEIA==").is_err());
    }

    #[test]
    fn loads_full_config() {
        let cfg: Config = toml::from_str::<RawConfig>(SAMPLE).unwrap().try_into().unwrap();
        assert_eq!(cfg.inbound.port, 1080);
        assert_eq!(cfg.outbound.vless.flow, "xtls-rprx-vision");
        assert_eq!(cfg.outbound.reality.short_id, vec![0x01, 0x23, 0xab, 0xcd]);
        assert_eq!(cfg.timeout.dial_retries, 2);
    }
}
