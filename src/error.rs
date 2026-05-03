use round_based::PartyIndex;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("round-based protocol error: {0}")]
    Protocol(String),
    #[error("commitment mismatch for party {sender}")]
    CommitmentMismatch { sender: PartyIndex },
    #[error("secret share was zero")]
    ZeroShare,
    #[error("nonce was zero")]
    ZeroNonce,
    #[error("invalid nonce point")]
    InvalidNoncePoint,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("MtA / OT subprotocol is not implemented in this MVP")]
    MtaNotImplemented,
    #[error("serialization error: {0}")]
    Serialization(String),
}
