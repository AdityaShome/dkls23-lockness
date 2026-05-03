use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand::{rngs::StdRng, RngCore, SeedableRng};
use round_based::rounds_router::{simple_store::RoundInput, RoundsRouter};
use round_based::{Delivery, Mpc, MpcParty, Outgoing, PartyIndex, SinkExt};
use sha2::{Digest, Sha256};

use crate::{Error, KeyShare, KeygenCommitment, KeygenOpen, Msg, Result};

pub fn commitment_for<E: Curve>(secret_share: &Scalar<E>, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(
        serde_json::to_vec(secret_share).expect("scalar serialization should succeed"),
    );
    hasher.update(salt);
    hasher.finalize().into()
}

pub async fn run<E, M>(party: M, i: PartyIndex, n: u16, threshold: u16, seed: u64) -> Result<KeyShare<E>>
where
    E: Curve,
    M: Mpc<ProtocolMessage = Msg<E>>,
{
    let MpcParty { delivery, .. } = party.into_party();
    let (incomings, mut outgoings) = Delivery::split(delivery);

    let mut rounds = RoundsRouter::builder();
    let round1 = rounds.add_round(RoundInput::<KeygenCommitment>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<KeygenOpen<E>>::broadcast(i, n));
    let mut rounds = rounds.listen(incomings);

    let mut rng = StdRng::seed_from_u64(seed);
    let secret_share = SecretScalar::<E>::random(&mut rng);
    let public_share = Point::<E>::generator() * &secret_share;

    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    let commitment = commitment_for(secret_share.as_ref(), &salt);

    let commit_msg: Outgoing<Msg<E>> = Outgoing::broadcast(Msg::KeygenR1(KeygenCommitment { commitment }));
    outgoings
        .send(commit_msg)
        .await
        .map_err(|err| Error::Protocol(err.to_string()))?;

    let commitments = rounds
        .complete(round1)
        .await
        .map_err(|err| Error::Protocol(err.to_string()))?;
    let _ = commitments;

    let open_msg: Outgoing<Msg<E>> = Outgoing::broadcast(Msg::KeygenR2(KeygenOpen {
            secret_share: secret_share.as_ref().clone(),
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

    let mut public_shares = Vec::new();
    let mut public_key = Point::<E>::zero();
    let mut participants = Vec::new();

    for (sender, _msg_id, open) in openings.into_iter_indexed() {
        let expected_commitment = commitment_for(&open.secret_share, &open.salt);
        if sender == i && expected_commitment != commitment {
            return Err(Error::CommitmentMismatch { sender });
        }
        if expected_commitment != commitment_for(&open.secret_share, &open.salt) {
            return Err(Error::CommitmentMismatch { sender });
        }

        let share_point = Point::<E>::generator() * &open.secret_share;
        public_key = &public_key + &share_point;
        public_shares.push(share_point);
        participants.push(sender);
    }

    public_key = &public_key + &public_share;
    public_shares.insert(usize::from(i), public_share);
    participants.insert(usize::from(i), i);

    Ok(KeyShare::new(
        public_key,
        public_shares,
        participants,
        threshold,
        i,
        secret_share,
    ))
}
