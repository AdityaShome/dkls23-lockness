use core::fmt;

use generic_ec::{Curve, Point, SecretScalar};
use round_based::PartyIndex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct KeyShare<E: Curve> {
    pub public_key: Point<E>,
    pub public_shares: Vec<Point<E>>,
    pub participants: Vec<PartyIndex>,
    pub threshold: u16,
    pub party_index: PartyIndex,
    pub local_secret_share: SecretScalar<E>,
}

impl<E: Curve> KeyShare<E> {
    pub fn new(
        public_key: Point<E>,
        public_shares: Vec<Point<E>>,
        participants: Vec<PartyIndex>,
        threshold: u16,
        party_index: PartyIndex,
        local_secret_share: SecretScalar<E>,
    ) -> Self {
        Self {
            public_key,
            public_shares,
            participants,
            threshold,
            party_index,
            local_secret_share,
        }
    }

    pub fn local_secret_share(&self) -> &SecretScalar<E> {
        &self.local_secret_share
    }
}

impl<E: Curve> PartialEq for KeyShare<E> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
            && self.public_shares == other.public_shares
            && self.participants == other.participants
            && self.threshold == other.threshold
    }
}

impl<E: Curve> Eq for KeyShare<E> {}

impl<E: Curve> fmt::Debug for KeyShare<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyShare")
            .field("public_key", &self.public_key)
            .field("public_shares", &self.public_shares)
            .field("participants", &self.participants)
            .field("threshold", &self.threshold)
            .field("party_index", &self.party_index)
            .field("local_secret_share", &"<redacted>")
            .finish()
    }
}
