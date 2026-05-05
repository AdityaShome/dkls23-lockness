//! Pre-signing for the DKLs23 Lockness implementation.
//!
//! This module keeps the real network shape around nonce commitments and openings,
//! while the MtA boundary stays isolated behind a backend trait.

use core::fmt;

use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use round_based::rounds_router::{simple_store::RoundInput, RoundsRouter};
use round_based::{Delivery, Mpc, MpcParty, Outgoing, PartyIndex, SinkExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::{validate_party_configuration, Error, KeyShare, Msg, PresignMessage, PresignOpen, Result};

pub mod mta;

pub use mta::{DirectMta, MultiplicationToAddition};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Presignature<E: Curve> {
    pub nonce_point: Point<E>,
    pub aggregate_nonce: Scalar<E>,
    pub nonce_secret_product_share: Scalar<E>,
    pub local_nonce_share: SecretScalar<E>,
    pub participants: Vec<PartyIndex>,
    pub threshold: u16,
    pub party_index: PartyIndex,
}

impl<E: Curve> PartialEq for Presignature<E> {
    fn eq(&self, other: &Self) -> bool {
        self.nonce_point == other.nonce_point
            && self.aggregate_nonce == other.aggregate_nonce
            && self.participants == other.participants
            && self.threshold == other.threshold
    }
}

impl<E: Curve> Eq for Presignature<E> {}

impl<E: Curve> Presignature<E> {
    pub fn local_nonce_share(&self) -> &SecretScalar<E> {
        &self.local_nonce_share
    }
}

impl<E: Curve> fmt::Debug for Presignature<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presignature")
            .field("nonce_point", &self.nonce_point)
            .field("aggregate_nonce", &self.aggregate_nonce)
            .field("nonce_secret_product_share", &"<redacted>")
            .field("participants", &self.participants)
            .field("threshold", &self.threshold)
            .field("party_index", &self.party_index)
            .field("local_nonce_share", &"<redacted>")
            .finish()
    }
}

pub fn nonce_commitment_for<E: Curve>(nonce_share: &Scalar<E>, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        serde_json::to_vec(nonce_share).expect("scalar serialization should succeed"),
    );
    hasher.update(salt);
    hasher.finalize().into()
}

fn sample_nonzero_nonce<E: Curve>(rng: &mut StdRng) -> SecretScalar<E> {
    loop {
        let nonce = SecretScalar::<E>::random(rng);
        if !nonce.as_ref().is_zero() {
            return nonce;
        }
    }
}

pub async fn run<E, M, T>(
    party: M,
    key_share: &KeyShare<E>,
    mut mta: T,
    i: PartyIndex,
    n: u16,
    threshold: u16,
    seed: u64,
) -> Result<Presignature<E>>
where
    E: Curve,
    M: Mpc<ProtocolMessage = Msg<E>>,
    T: MultiplicationToAddition<E>,
    T::Error: core::fmt::Debug,
{
    validate_party_configuration(n, threshold, i)?;

    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = Delivery::split(delivery);

    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<PresignMessage<E>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<PresignOpen<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let mut rng = StdRng::seed_from_u64(seed);
    let local_nonce_share = sample_nonzero_nonce::<E>(&mut rng);
    let local_nonce_scalar = local_nonce_share.as_ref().clone();
    let local_nonce_point = Point::<E>::generator() * &local_nonce_scalar;

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let commitment = nonce_commitment_for(&local_nonce_scalar, &salt);

    let commitment_msg: Outgoing<Msg<E>> = Outgoing::broadcast(Msg::PresignR1(PresignMessage {
        nonce_commitment: commitment,
        _phantom: core::marker::PhantomData,
    }));
    outgoings
        .send(commitment_msg)
        .await
        .map_err(|err| Error::Protocol(err.to_string()))?;

    let commitments = rounds
        .complete(round1)
        .await
        .map_err(|err| Error::Protocol(err.to_string()))?;
    let commitments = commitments
        .into_iter_indexed()
        .map(|(sender, _msg_id, commitment_msg)| (sender, commitment_msg))
        .collect::<BTreeMap<_, _>>();

    let open_msg: Outgoing<Msg<E>> = Outgoing::broadcast(Msg::PresignR2(PresignOpen {
        nonce_share: local_nonce_scalar.clone(),
        salt,
    }));
    outgoings
        .send(open_msg)
        .await
        .map_err(|err| Error::Protocol(err.to_string()))?;

    let openings = rounds
        .complete(round2)
        .await
        .map_err(|err| Error::Protocol(err.to_string()))?;

    let mut participants = Vec::new();
    let mut aggregate_nonce_point = Point::<E>::zero();
    let mut aggregate_nonce = Scalar::<E>::zero();

    for (sender, _msg_id, open) in openings.into_iter_indexed() {
        let commitment_msg = commitments
            .get(&sender)
            .ok_or_else(|| Error::Protocol("missing presign commitment".to_string()))?;

        if open.nonce_share.is_zero() {
            return Err(Error::ZeroNonce);
        }

        let expected_commitment = nonce_commitment_for(&open.nonce_share, &open.salt);
        if commitment_msg.nonce_commitment != expected_commitment {
            return Err(Error::CommitmentMismatch { sender });
        }

        let share_point = Point::<E>::generator() * &open.nonce_share;
        aggregate_nonce_point = &aggregate_nonce_point + &share_point;
        aggregate_nonce = &aggregate_nonce + &open.nonce_share;
        participants.push(sender);
    }

    if local_nonce_scalar.is_zero() {
        return Err(Error::ZeroNonce);
    }

    aggregate_nonce_point = &aggregate_nonce_point + &local_nonce_point;
    aggregate_nonce = &aggregate_nonce + &local_nonce_scalar;
    participants.insert(usize::from(i), i);

    if participants.len() < usize::from(threshold) {
        return Err(Error::Protocol("not enough parties to form a presignature".to_string()));
    }

    let nonce_secret_product_share = mta
        .multiply_to_additive_share(
            local_nonce_scalar.clone(),
            key_share.local_secret_share().as_ref().clone(),
        )
        .map_err(|err| Error::Protocol(format!("MtA backend failed: {err:?}")))?;

    if aggregate_nonce.is_zero() || aggregate_nonce_point.is_zero() {
        return Err(Error::ZeroNonce);
    }

    Ok(Presignature {
        nonce_point: aggregate_nonce_point,
        aggregate_nonce,
        nonce_secret_product_share,
        local_nonce_share,
        participants,
        threshold,
        party_index: i,
    })
}
