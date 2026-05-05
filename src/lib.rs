//! DKLs23 threshold ECDSA MVP scaffold for the Lockness ecosystem.
//!
//! This crate is intentionally honest about scope: it demonstrates the protocol layout,
//! round-based message flow, and curve-generic key material, but it does not claim production
//! security.

pub mod error;
pub mod key_share;
pub mod keygen;
pub mod msg;
pub mod protocol;
pub mod presign;
pub mod signing;
pub mod transcript;

pub use error::{Error, Result};
pub use key_share::KeyShare;
pub use msg::{KeygenCommitment, KeygenOpen, Msg, PresignMessage, PresignOpen, SigningMessage};
pub use protocol::validate_party_configuration;
pub use round_based::{ProtocolMessage, RoundMessage};
