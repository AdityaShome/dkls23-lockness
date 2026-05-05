use round_based::PartyIndex;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("round-based protocol error: {0}")]
    Protocol(String),
    #[error("invalid protocol configuration: n={n}, threshold={threshold}, party_index={party_index}")]
    InvalidConfiguration {
        n: u16,
        threshold: u16,
        party_index: PartyIndex,
    },
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
    #[error("serialization error: {0}")]
    Serialization(String),
}
