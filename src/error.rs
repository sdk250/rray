use std::{
    io::Error as IoError,
    sync::Arc
};
use tokio::time::error::Elapsed as TimeoutError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, RError>;

#[derive(Error, Debug)]
pub enum RError {
    #[error("I/O error: {0}")]
    IO(#[from] IoError),

    #[error("Timeout error: {0}")]
    Timeout(#[from] TimeoutError),

    #[error("An error occurred in {0}: {1}")]
    Generic(&'static str, Arc<str>),

    #[error("config error: {0}")]
    Config(String),

    #[error("SOCKS5 error: {0}")]
    Socks5(&'static str),

    #[error("Reality error: {0}")]
    Reality(String),

    #[error("VLESS error: {0}")]
    Vless(&'static str),

    #[error("protocol error: {0}")]
    Protocol(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_display() {
        assert_eq!(RError::Socks5("bad ver").to_string(), "SOCKS5 error: bad ver");
        assert_eq!(RError::Vless("short header").to_string(), "VLESS error: short header");
        assert_eq!(RError::Config("missing field".into()).to_string(), "config error: missing field");
        assert_eq!(RError::Reality("auth fail".into()).to_string(), "Reality error: auth fail");
        assert_eq!(RError::Protocol("eof").to_string(), "protocol error: eof");
    }
}
