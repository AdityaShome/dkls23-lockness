use generic_ec::{Curve, Point, Scalar};
use round_based::ProtocolMessage;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KeygenCommitment {
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KeygenOpen<E: Curve> {
    pub secret_share: Scalar<E>,
    pub salt: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PresignMessage<E: Curve> {
    pub nonce_commitment: [u8; 32],
    #[serde(skip)]
    pub _phantom: core::marker::PhantomData<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PresignOpen<E: Curve> {
    pub nonce_share: Scalar<E>,
    pub salt: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SigningMessage<E: Curve> {
    pub message_hash: [u8; 32],
    pub nonce_point: Point<E>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ProtocolMessage)]
#[protocol_message(root = crate)]
#[serde(bound = "")]
pub enum Msg<E: Curve> {
    KeygenR1(KeygenCommitment),
    KeygenR2(KeygenOpen<E>),
    PresignR1(PresignMessage<E>),
    PresignR2(PresignOpen<E>),
    SigningR1(SigningMessage<E>),
}
