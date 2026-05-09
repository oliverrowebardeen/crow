use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("AEAD authentication failed")]
    Aead,

    #[error("invalid capability: {0}")]
    Cap(String),

    #[error("catalog error: {0}")]
    Catalog(String),

    #[error("invalid manifest: {0}")]
    Manifest(String),

    #[error("missing chunk: {0}")]
    MissingChunk(String),

    #[error("not enough shares to reconstruct stripe {stripe}: have {have}, need {need}")]
    NotEnoughShares {
        stripe: usize,
        have: usize,
        need: usize,
    },

    #[error("erasure coding error: {0}")]
    Erasure(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid hash: {0}")]
    Hash(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
