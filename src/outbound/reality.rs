//! Reality 握手。
//!
//! 字节布局对照 xray-core `transport/internet/reality/reality.go`，见 docs/reference/reality-format.md。
//!
//! 难点：Reality 把认证密文写进 ClientHello 的 legacy_session_id，而密文的 AEAD **AAD 是整条
//! 序列化后的 ClientHello**（session_id 区域置零）。也就是说密文依赖 ClientHello 的完整字节，
//! 而 ClientHello 又要携带该密文 —— 看似循环。
//!
//! 解法是"两趟构造"，全部使用 rustls 公开 API，无需 fork：
//!
//! 1. **A 趟**：用确定性 RNG 造一条 ClientConnection，把 ClientHello 取出但不发送。
//!    把 session_id 区域置零即得 AAD，据此算出 32 字节密文。
//! 2. **B 趟**：重放同一 RNG 种子，只把"取 session_id 的那次随机"替换成密文。
//!    于是 rustls 自己认为它发出的 session_id 就是密文 —— transcript 与
//!    ServerHello 的 legacy_session_id_echo 校验全部自洽。
//!
//! 哪一次取随机是 session_id 不靠猜：A 趟记录每次 RNG 返回值，再看哪一个落在
//! ClientHello 的 session_id 偏移上，反查出调用序号。

use std::cell::RefCell;
use std::sync::OnceLock;

use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, SecureRandom, SharedSecret,
    SupportedKxGroup
};
use rustls::{ Error as TlsError, NamedGroup };
use sha2::{ Digest, Sha256 };

use crate::error::{ Result, RError };

/// ClientHello 握手消息内 legacy_session_id 的固定偏移：
/// handshake type(1) + length(3) + legacy_version(2) + random(32) + session_id_len(1)。
pub(crate) const SESSION_ID_OFFSET: usize = 39;
pub(crate) const SESSION_ID_LEN: usize = 32;

// ---------------------------------------------------------------------------
// 确定性随机脚本
// ---------------------------------------------------------------------------

/// SHA-256(seed ‖ counter) 派生的确定性字节流，用于让两趟构造出同样的 ClientHello。
struct SeedStream {
    seed: [u8; 32],
    counter: u64,
    buf: Vec<u8>,
}

impl SeedStream {
    fn new(seed: [u8; 32]) -> Self {
        Self { seed, counter: 0, buf: Vec::new() }
    }

    fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.buf.is_empty() {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.counter.to_le_bytes());
                self.buf.extend_from_slice(&h.finalize());
                self.counter += 1;
            }
            let n = (out.len() - done).min(self.buf.len());
            out[done..done + n].copy_from_slice(&self.buf[..n]);
            self.buf.drain(..n);
            done += n;
        }
    }
}

/// 一次 ClientHello 构造期间生效的随机脚本。
struct Script {
    stream: SeedStream,
    /// 每次 `fill` 返回的字节，供事后定位哪一次是 session_id。
    calls: Vec<Vec<u8>>,
    /// B 趟用：把第 n 次 `fill` 的返回值换成指定字节。
    replace: Option<(usize, Vec<u8>)>,
    /// key_share 用的 x25519 私钥（两趟必须一致）。
    kx_secret: [u8; 32],
}

thread_local! {
    static SCRIPT: RefCell<Option<Script>> = const { RefCell::new(None) };
}

/// rustls 的 `CryptoProvider.secure_random` 必须是 `&'static`，所以这里放一个单元类型，
/// 内部按线程局部脚本分流：脚本生效时回放确定性字节，否则退回真随机。
#[derive(Debug)]
struct ScriptedRandom;

static FALLBACK_RANDOM: OnceLock<&'static dyn SecureRandom> = OnceLock::new();

fn fallback_random() -> &'static dyn SecureRandom {
    *FALLBACK_RANDOM.get_or_init(|| rustls::crypto::aws_lc_rs::default_provider().secure_random)
}

impl SecureRandom for ScriptedRandom {
    fn fill(&self, buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
        SCRIPT.with(|s| {
            let mut slot = s.borrow_mut();
            match slot.as_mut() {
                Some(script) => {
                    script.stream.fill(buf);
                    let idx = script.calls.len();
                    if let Some((n, bytes)) = &script.replace {
                        if *n == idx && bytes.len() == buf.len() {
                            buf.copy_from_slice(bytes);
                        }
                    }
                    script.calls.push(buf.to_vec());
                    Ok(())
                },
                None => fallback_random().fill(buf),
            }
        })
    }
}

static SCRIPTED_RANDOM: ScriptedRandom = ScriptedRandom;

// ---------------------------------------------------------------------------
// 固定私钥的 x25519 key share
// ---------------------------------------------------------------------------

/// x25519 组，但私钥取自当前脚本而非随机生成 —— Reality 要用这把私钥和服务端公钥做 ECDH。
#[derive(Debug)]
struct ScriptedX25519;

static SCRIPTED_X25519: ScriptedX25519 = ScriptedX25519;

struct ScriptedX25519Kx {
    secret: [u8; 32],
    public: [u8; 32],
}

impl SupportedKxGroup for ScriptedX25519 {
    fn start(&self) -> std::result::Result<Box<dyn ActiveKeyExchange>, TlsError> {
        let secret = SCRIPT.with(|s| s.borrow().as_ref().map(|sc| sc.kx_secret));
        let secret = secret.ok_or(TlsError::General("reality: no key share script active".into()))?;
        let public = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        Ok(Box::new(ScriptedX25519Kx { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for ScriptedX25519Kx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> std::result::Result<SharedSecret, TlsError> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| TlsError::General("reality: bad x25519 peer key".into()))?;
        Ok(SharedSecret::from(&x25519_dalek::x25519(self.secret, peer)[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// 以 aws-lc-rs 为底，仅替换 `secure_random` 与 `kx_groups` 的 provider。
/// 限定纯 x25519：既是 Reality 的要求，也避开 rustls 默认优先的混合组分支。
pub(crate) fn reality_provider() -> CryptoProvider {
    CryptoProvider {
        secure_random: &SCRIPTED_RANDOM,
        kx_groups: vec![&SCRIPTED_X25519 as &'static dyn SupportedKxGroup],
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// 在脚本生效的作用域内执行 `f`，返回其结果与本次记录的随机调用序列。
fn with_script<T>(
    seed: [u8; 32],
    kx_secret: [u8; 32],
    replace: Option<(usize, Vec<u8>)>,
    f: impl FnOnce() -> T,
) -> (T, Vec<Vec<u8>>) {
    SCRIPT.with(|s| {
        *s.borrow_mut() = Some(Script {
            stream: SeedStream::new(seed),
            calls: Vec::new(),
            replace,
            kx_secret,
        });
    });
    let out = f();
    let calls = SCRIPT.with(|s| s.borrow_mut().take().map(|sc| sc.calls).unwrap_or_default());
    (out, calls)
}

/// 从 `write_tls` 产出的 TLS 记录里取出 ClientHello 握手消息体（等价于 xray 的 `hello.Raw`）。
fn client_hello_body(records: &[u8]) -> Result<Vec<u8>> {
    if records.len() < 5 || records[0] != 0x16 {
        return Err(RError::Reality("first record is not a handshake record".into()));
    }
    let len = u16::from_be_bytes([records[3], records[4]]) as usize;
    let body = records
        .get(5..5 + len)
        .ok_or_else(|| RError::Reality("truncated ClientHello record".into()))?;
    if body.first() != Some(&0x01) {
        return Err(RError::Reality("first handshake message is not ClientHello".into()));
    }
    if body.len() < SESSION_ID_OFFSET + SESSION_ID_LEN {
        return Err(RError::Reality("ClientHello too short for session_id".into()));
    }
    Ok(body.to_vec())
}

/// 在 A 趟的随机调用序列里定位"哪一次取的是 session_id"。
fn locate_session_id_call(hello: &[u8], calls: &[Vec<u8>]) -> Result<usize> {
    let sid = &hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN];
    calls
        .iter()
        .position(|c| c.as_slice() == sid)
        .ok_or_else(|| RError::Reality("cannot locate session_id draw in RNG call log".into()))
}

// ---------------------------------------------------------------------------
// Reality 认证数据
// ---------------------------------------------------------------------------

/// ClientHello 内 TLS random 的偏移：type(1) + length(3) + legacy_version(2)。
const RANDOM_OFFSET: usize = 6;
const RANDOM_LEN: usize = 32;
/// HKDF 的 salt 只取 random 的前 20 字节（xray：`hello.Random[:20]`）。
const HKDF_SALT_LEN: usize = 20;
const HKDF_INFO: &[u8] = b"REALITY";
/// AEAD nonce 取 random 的后 12 字节（xray：`hello.Random[20:]`）。
const NONCE_LEN: usize = 12;
/// 认证明文固定 16 字节，密文 = 16 明文 + 16 GCM tag = 32 字节，正好填满 session_id。
const AUTH_PLAINTEXT_LEN: usize = 16;
/// 伪装成的 xray 版本（`core/core.go` 的 Version_x/y/z）。
/// 服务端仅在配置了 MinClientVer/MaxClientVer 时校验，但仍应填真实值。
const CLIENT_VERSION: [u8; 3] = [26, 7, 28];
/// 服务端按 `[8]byte` 查表，short_id 必须零填充到 8 字节。
const SHORT_ID_LEN: usize = 8;

/// `HKDF-SHA256(ikm = ECDH 共享密钥, salt = hello.random[:20], info = "REALITY")`。
fn derive_auth_key(
    kx_secret: &[u8; 32],
    server_public_key: &[u8; 32],
    hello_random: &[u8],
) -> Result<[u8; 32]> {
    let shared = x25519_dalek::x25519(*kx_secret, *server_public_key);
    if shared.iter().all(|b| *b == 0) {
        return Err(RError::Reality("x25519 shared secret is all zero".into()));
    }
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&hello_random[..HKDF_SALT_LEN]), &shared);
    let mut auth_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut auth_key)
        .map_err(|_| RError::Reality("hkdf expand failed".into()))?;
    Ok(auth_key)
}

/// 16 字节认证明文：版本(3) | 保留(1) | 大端 Unix 秒(4) | short_id 零填充(8)。
fn build_auth_plaintext(short_id: &[u8], unix_secs: u32) -> Result<[u8; AUTH_PLAINTEXT_LEN]> {
    if short_id.len() > SHORT_ID_LEN {
        return Err(RError::Reality("short_id longer than 8 bytes".into()));
    }
    let mut p = [0u8; AUTH_PLAINTEXT_LEN];
    p[..3].copy_from_slice(&CLIENT_VERSION);
    p[3] = 0; // reserved
    p[4..8].copy_from_slice(&unix_secs.to_be_bytes());
    p[8..8 + short_id.len()].copy_from_slice(short_id);
    Ok(p)
}

/// AES-256-GCM 加密认证明文，AAD 是 session_id 置零后的整条 ClientHello。
fn seal_session_id(
    auth_key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8; AUTH_PLAINTEXT_LEN],
) -> Result<[u8; SESSION_ID_LEN]> {
    use aes_gcm::aead::{ Aead, KeyInit, Payload };

    let cipher = aes_gcm::Aes256Gcm::new(auth_key.into());
    let out = cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .map_err(|_| RError::Reality("aes-gcm seal failed".into()))?;
    out.try_into()
        .map_err(|_| RError::Reality("sealed session_id is not 32 bytes".into()))
}

/// 把 ClientHello 的 session_id 区域置零，得到 AAD。
fn aad_from_hello(hello: &[u8]) -> Vec<u8> {
    let mut aad = hello.to_vec();
    aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
    aad
}

// ---------------------------------------------------------------------------
// 服务端身份校验
// ---------------------------------------------------------------------------

/// Ed25519 的 SubjectPublicKeyInfo 前缀：
/// `SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 } BIT STRING(33, 0 unused) }`，其后即 32 字节公钥。
const ED25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];
/// 证书末尾的 signatureValue：`BIT STRING(65, 0 unused)` + 64 字节 Ed25519 签名。
const ED25519_SIG_PREFIX: [u8; 3] = [0x03, 0x41, 0x00];
const ED25519_SIG_LEN: usize = 64;

/// 取叶子证书里的 Ed25519 SPKI 公钥（32 字节）。
fn ed25519_public_key(der: &[u8]) -> Result<[u8; 32]> {
    let pos = der
        .windows(ED25519_SPKI_PREFIX.len())
        .position(|w| w == ED25519_SPKI_PREFIX)
        .ok_or_else(|| RError::Reality("certificate has no Ed25519 SubjectPublicKeyInfo".into()))?;
    let start = pos + ED25519_SPKI_PREFIX.len();
    der.get(start..start + 32)
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| RError::Reality("truncated Ed25519 public key".into()))
}

/// 取证书的 signatureValue。它是 Certificate SEQUENCE 的最后一个字段，故位于 DER 末尾。
fn certificate_signature(der: &[u8]) -> Result<&[u8]> {
    let head = der
        .len()
        .checked_sub(ED25519_SIG_LEN + ED25519_SIG_PREFIX.len())
        .ok_or_else(|| RError::Reality("certificate too short for Ed25519 signature".into()))?;
    if der[head..head + ED25519_SIG_PREFIX.len()] != ED25519_SIG_PREFIX {
        return Err(RError::Reality("certificate signature is not a 64-byte Ed25519 BIT STRING".into()));
    }
    Ok(&der[head + ED25519_SIG_PREFIX.len()..])
}

/// Reality 的服务端身份校验：证书不走 X.509 信任链，而是校验
/// `HMAC-SHA512(auth_key, ed25519_pubkey) == certificate.signature`。
/// 校验不过说明对面是被前置的真站（或 MITM），不是我们的 Reality 服务端。
#[derive(Debug)]
struct RealityVerifier {
    auth_key: [u8; 32],
    provider: std::sync::Arc<CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, TlsError> {
        use hmac::{ Mac, digest::KeyInit };

        let der = end_entity.as_ref();
        let pubkey = ed25519_public_key(der).map_err(|e| TlsError::General(e.to_string()))?;
        let signature = certificate_signature(der).map_err(|e| TlsError::General(e.to_string()))?;

        let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(&self.auth_key)
            .map_err(|_| TlsError::General("reality: bad auth key length".into()))?;
        mac.update(&pubkey);
        mac.verify_slice(signature).map_err(|_| {
            TlsError::General(
                "reality: server is not a REALITY endpoint (certificate HMAC mismatch)".into(),
            )
        })?;

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// 握手
// ---------------------------------------------------------------------------

/// 构造 TLS 客户端配置。两趟必须用**结构完全相同**的配置，否则 ClientHello 字节会不一致；
/// `auth_key` 只影响证书校验（A 趟根本不会走到），不影响 ClientHello。
fn client_config(auth_key: [u8; 32]) -> std::sync::Arc<rustls::ClientConfig> {
    let provider = std::sync::Arc::new(reality_provider());
    let verifier = std::sync::Arc::new(RealityVerifier { auth_key, provider: provider.clone() });

    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS1.3 is supported by the reality provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    // xray 设 SessionTicketsDisabled：会话恢复会让 ClientHello 带上 PSK，破坏两趟的确定性。
    cfg.resumption = rustls::client::Resumption::disabled();
    std::sync::Arc::new(cfg)
}

/// A 趟的产物：造 B 趟所需的全部参数。
struct Prepared {
    seed: [u8; 32],
    kx_secret: [u8; 32],
    /// session_id 是第几次取随机。
    session_id_call: usize,
    /// 认证密文，B 趟要顶替进 session_id。
    session_id: [u8; SESSION_ID_LEN],
    auth_key: [u8; 32],
    /// A 趟记录的取随机次数，用于确认 B 趟确实跑在脚本内。
    call_count: usize,
}

/// A 趟：造一条不上网的连接取出 ClientHello，据此算出认证密文。
fn prepare(
    cfg: &crate::config::RealityCfg,
    sni: rustls::pki_types::ServerName<'static>,
    seed: [u8; 32],
    kx_secret: [u8; 32],
    unix_secs: u32,
) -> Result<Prepared> {
    let (records, calls) = with_script(seed, kx_secret, None, || {
        let mut conn = rustls::ClientConnection::new(client_config([0u8; 32]), sni)
            .map_err(|e| RError::Reality(format!("build ClientHello: {e}").into()))?;
        let mut out = Vec::new();
        conn.write_tls(&mut out)
            .map_err(|e| RError::Reality(format!("extract ClientHello: {e}").into()))?;
        Ok::<_, RError>(out)
    });

    let hello = client_hello_body(&records?)?;
    let session_id_call = locate_session_id_call(&hello, &calls)?;

    let random = &hello[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
    let auth_key = derive_auth_key(&kx_secret, &cfg.public_key, random)?;

    let nonce: [u8; NONCE_LEN] = random[HKDF_SALT_LEN..]
        .try_into()
        .map_err(|_| RError::Reality("bad nonce slice".into()))?;
    let plaintext = build_auth_plaintext(&cfg.short_id, unix_secs)?;
    let session_id = seal_session_id(&auth_key, &nonce, &aad_from_hello(&hello), &plaintext)?;

    Ok(Prepared {
        seed,
        kx_secret,
        session_id_call,
        session_id,
        auth_key,
        call_count: calls.len(),
    })
}

/// 完成 Reality TLS 握手，产出可读写的 TLS 流。
pub async fn connect(
    tcp: tokio::net::TcpStream,
    cfg: &crate::config::RealityCfg,
    handshake_ms: u64,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use rand::RngExt;

    let sni = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
        .map_err(|_| RError::Reality("bad server_name".into()))?;

    let mut seed = [0u8; 32];
    let mut kx_secret = [0u8; 32];
    let mut rng = rand::rng();
    rng.fill(&mut seed);
    rng.fill(&mut kx_secret);

    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RError::Reality("system clock before unix epoch".into()))?
        .as_secs() as u32;

    let p = prepare(cfg, sni.clone(), seed, kx_secret, unix_secs)?;

    // B 趟：重放同一脚本，只把 session_id 那次取随机换成认证密文。
    // tokio-rustls 在 `connect()` 里同步构造 ClientConnection，所以脚本只需覆盖这一次调用。
    let connector = tokio_rustls::TlsConnector::from(client_config(p.auth_key));
    let (fut, calls) = with_script(
        p.seed,
        p.kx_secret,
        Some((p.session_id_call, p.session_id.to_vec())),
        || connector.connect(sni, tcp),
    );

    // 自检：确认 ClientHello 确实是在脚本内构造的，且 session_id 已被顶替。
    // 若 tokio-rustls 改成惰性构造，这里会立刻发现，而不是在服务端静默失败。
    if calls.len() != p.call_count {
        return Err(RError::Reality(
            format!("ClientHello was not built under the RNG script ({} vs {} draws)",
                calls.len(), p.call_count).into()
        ));
    }
    if calls[p.session_id_call] != p.session_id {
        return Err(RError::Reality("session_id draw was not replaced".into()));
    }

    tokio::time::timeout(std::time::Duration::from_millis(handshake_ms), fut)
        .await
        .map_err(|_| RError::Reality("handshake timeout".into()))?
        .map_err(|e| RError::Reality(e.to_string().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use rustls::pki_types::ServerName;
    use rustls::{ ClientConfig, ClientConnection };

    fn test_config() -> Arc<ClientConfig> {
        client_config([0u8; 32])
    }

    /// 造一条 ClientConnection 并把它想发的 ClientHello 取出来（不上网）。
    fn emit_hello(
        seed: [u8; 32],
        kx_secret: [u8; 32],
        replace: Option<(usize, Vec<u8>)>,
    ) -> (Vec<u8>, Vec<Vec<u8>>) {
        let (bytes, calls) = with_script(seed, kx_secret, replace, || {
            let name = ServerName::try_from("www.microsoft.com").unwrap();
            let mut conn = ClientConnection::new(test_config(), name).unwrap();
            let mut out = Vec::new();
            conn.write_tls(&mut out).unwrap();
            out
        });
        (client_hello_body(&bytes).unwrap(), calls)
    }

    /// 明文布局逐字段对照 xray 服务端 `tls.go` 的解析。
    #[test]
    fn auth_plaintext_layout() {
        let p = build_auth_plaintext(&[0x01, 0x23, 0xab, 0xcd], 0x1234_5678).unwrap();
        assert_eq!(&p[..3], &CLIENT_VERSION);
        assert_eq!(p[3], 0);
        assert_eq!(&p[4..8], &[0x12, 0x34, 0x56, 0x78]); // 大端
        assert_eq!(&p[8..16], &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]); // 零填充到 8 字节
    }

    #[test]
    fn rejects_oversized_short_id() {
        assert!(build_auth_plaintext(&[0u8; 9], 0).is_err());
    }

    /// 密文必须正好 32 字节（16 明文 + 16 tag），才能填满 session_id。
    #[test]
    fn sealed_session_id_is_32_bytes() {
        let plaintext = build_auth_plaintext(&[0x01], 42).unwrap();
        let sealed = seal_session_id(&[3u8; 32], &[4u8; NONCE_LEN], b"aad", &plaintext).unwrap();
        assert_eq!(sealed.len(), SESSION_ID_LEN);
    }

    /// 与服务端对称：同样的 key/nonce/AAD 必须能解回明文，AAD 变了则失败。
    #[test]
    fn sealed_session_id_round_trips() {
        use aes_gcm::aead::{ Aead, KeyInit, Payload };

        let key = [3u8; 32];
        let nonce = [4u8; NONCE_LEN];
        let aad = b"the client hello";
        let plaintext = build_auth_plaintext(&[0x01, 0x23], 1_700_000_000).unwrap();
        let sealed = seal_session_id(&key, &nonce, aad, &plaintext).unwrap();

        let cipher = aes_gcm::Aes256Gcm::new((&key).into());
        let opened = cipher
            .decrypt((&nonce).into(), Payload { msg: &sealed, aad })
            .unwrap();
        assert_eq!(opened, plaintext);
        assert!(
            cipher
                .decrypt((&nonce).into(), Payload { msg: &sealed, aad: b"other hello" })
                .is_err()
        );
    }

    /// ECDH + HKDF 必须确定（同输入同输出），且换公钥就变。
    #[test]
    fn auth_key_is_deterministic() {
        let random = [5u8; RANDOM_LEN];
        let server_pub = x25519_dalek::x25519([7u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let a = derive_auth_key(&[9u8; 32], &server_pub, &random).unwrap();
        let b = derive_auth_key(&[9u8; 32], &server_pub, &random).unwrap();
        assert_eq!(a, b);

        let other = x25519_dalek::x25519([8u8; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_ne!(a, derive_auth_key(&[9u8; 32], &other, &random).unwrap());
    }

    /// **端到端字节级验证**：完整跑一遍两趟法造出 ClientHello，然后用 xray 服务端
    /// (`XTLS/REALITY` tls.go 224–265) 的算法把 session_id 解回来。
    /// 解得开 ⇒ 我们的 AAD、nonce、HKDF、明文布局与服务端完全一致。
    #[test]
    fn server_side_can_open_our_session_id() {
        use aes_gcm::aead::{ Aead, KeyInit, Payload };

        // 服务端的 Reality 密钥对
        let server_secret = [0x5au8; 32];
        let server_public = x25519_dalek::x25519(server_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        let cfg = crate::config::RealityCfg {
            public_key: server_public,
            short_id: vec![0x01, 0x23, 0xab, 0xcd],
            server_name: "www.microsoft.com".into(),
            fingerprint: None,
        };
        let seed = [0x11u8; 32];
        let kx_secret = [0x22u8; 32];
        let now = 1_800_000_000u32;

        let sni = ServerName::try_from(cfg.server_name.clone()).unwrap();
        let p = prepare(&cfg, sni, seed, kx_secret, now).unwrap();

        // B 趟真正发出去的 ClientHello
        let (hello, _) = emit_hello(seed, kx_secret, Some((p.session_id_call, p.session_id.to_vec())));
        assert_eq!(
            &hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
            &p.session_id
        );

        // ---- 以下完全按服务端的步骤走 ----
        let random = &hello[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
        // 服务端从 ClientHello 的 key_share 里取客户端公钥
        let client_public = x25519_dalek::x25519(kx_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        assert!(hello.windows(32).any(|w| w == client_public), "key_share 里没有客户端公钥");

        let server_auth_key = derive_auth_key(&server_secret, &client_public, random).unwrap();
        assert_eq!(server_auth_key, p.auth_key, "两端 auth_key 不一致");

        // 服务端把 session_id 区域置零后作为 AAD
        let aad = aad_from_hello(&hello);
        let nonce: [u8; NONCE_LEN] = random[HKDF_SALT_LEN..].try_into().unwrap();
        let cipher = aes_gcm::Aes256Gcm::new((&server_auth_key).into());
        let plain = cipher
            .decrypt((&nonce).into(), Payload { msg: &p.session_id, aad: &aad })
            .expect("服务端解不开 session_id —— AAD/nonce/密钥/布局有一处对不上");

        assert_eq!(&plain[..3], &CLIENT_VERSION);
        assert_eq!(u32::from_be_bytes(plain[4..8].try_into().unwrap()), now);
        assert_eq!(&plain[8..16], &[0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0]);
    }

    /// 客户端与服务端必须算出同一把 auth_key（双方 ECDH 方向相反）。
    #[test]
    fn auth_key_matches_server_side_derivation() {
        let random = [5u8; RANDOM_LEN];
        let server_secret = [7u8; 32];
        let server_pub = x25519_dalek::x25519(server_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        let client_secret = [9u8; 32];
        let client_pub = x25519_dalek::x25519(client_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        // 客户端：x25519(自己私钥, 服务端 Reality 公钥)
        let client_key = derive_auth_key(&client_secret, &server_pub, &random).unwrap();
        // 服务端：x25519(自己私钥, ClientHello 里的 key_share 公钥)
        let server_key = derive_auth_key(&server_secret, &client_pub, &random).unwrap();
        assert_eq!(client_key, server_key);
    }

    /// 两趟前提：同种子必须产出逐字节相同的 ClientHello。
    #[test]
    fn same_seed_yields_identical_client_hello() {
        let (a, _) = emit_hello([7u8; 32], [9u8; 32], None);
        let (b, _) = emit_hello([7u8; 32], [9u8; 32], None);
        assert_eq!(a, b);
        let (c, _) = emit_hello([8u8; 32], [9u8; 32], None);
        assert_ne!(a, c);
    }

    /// key_share 必须用脚本给的私钥推出的公钥，而不是随机生成。
    #[test]
    fn key_share_uses_scripted_secret() {
        let secret = [9u8; 32];
        let expect = x25519_dalek::x25519(secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        let (hello, _) = emit_hello([7u8; 32], secret, None);
        assert!(
            hello.windows(32).any(|w| w == expect),
            "ClientHello 里找不到脚本私钥对应的 x25519 公钥"
        );
    }

    /// session_id 必须能在随机调用序列里定位到。
    #[test]
    fn session_id_draw_is_locatable() {
        let (hello, calls) = emit_hello([7u8; 32], [9u8; 32], None);
        let idx = locate_session_id_call(&hello, &calls).unwrap();
        assert_eq!(calls[idx].len(), SESSION_ID_LEN);
    }

    /// 核心断言：替换掉 session_id 那次随机后，ClientHello **只有** session_id 区域变化。
    /// 这正是 Reality 需要的"AAD 不变、密文写进 session_id"。
    #[test]
    fn replacing_session_id_draw_changes_only_session_id() {
        let seed = [7u8; 32];
        let kx = [9u8; 32];
        let (hello_a, calls) = emit_hello(seed, kx, None);
        let idx = locate_session_id_call(&hello_a, &calls).unwrap();

        let ciphertext = vec![0xAB; SESSION_ID_LEN];
        let (hello_b, _) = emit_hello(seed, kx, Some((idx, ciphertext.clone())));

        assert_eq!(hello_a.len(), hello_b.len());
        assert_eq!(
            &hello_b[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
            ciphertext.as_slice()
        );

        let mut a_zeroed = hello_a.clone();
        let mut b_zeroed = hello_b.clone();
        a_zeroed[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        b_zeroed[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
        assert_eq!(a_zeroed, b_zeroed, "除 session_id 外还有别的字节变了，两趟法不成立");
    }
}
