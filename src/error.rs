use std::{
    io::Error as IoError,
    sync::Arc
};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, RError>;

#[derive(Error, Debug)]
pub enum RError {
    #[error("I/O error: {0}")]
    IO(#[from] IoError),

    #[error("An error occurred in {0}: {1}")]
    Generic(&'static str, Arc<str>),
}
