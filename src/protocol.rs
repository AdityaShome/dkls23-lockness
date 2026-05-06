use std::collections::BTreeSet;

use round_based::PartyIndex;

use crate::{Error, Result};

pub fn validate_party_configuration(n: u16, threshold: u16, party_index: PartyIndex) -> Result<()> {
    if n == 0 || threshold == 0 || threshold > n || party_index >= n {
        return Err(Error::InvalidConfiguration {
            n,
            threshold,
            party_index,
        });
    }

    Ok(())
}

pub fn validate_participant_set(expected: u16, participants: &[PartyIndex]) -> Result<()> {
    let unique_count = participants.iter().copied().collect::<BTreeSet<_>>().len();
    if participants.len() != usize::from(expected) || unique_count != participants.len() {
        return Err(Error::InvalidParticipantSet {
            expected,
            found: participants.len(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_participant_set, validate_party_configuration};

    #[test]
    fn rejects_zero_threshold() {
        assert!(validate_party_configuration(3, 0, 0).is_err());
    }

    #[test]
    fn rejects_threshold_above_n() {
        assert!(validate_party_configuration(2, 3, 0).is_err());
    }

    #[test]
    fn rejects_out_of_range_party_index() {
        assert!(validate_party_configuration(3, 2, 3).is_err());
    }

    #[test]
    fn accepts_valid_configuration() {
        assert!(validate_party_configuration(3, 2, 1).is_ok());
    }

    #[test]
    fn rejects_duplicate_participants() {
        assert!(validate_participant_set(3, &[0, 1, 1]).is_err());
    }

    #[test]
    fn rejects_incomplete_participants() {
        assert!(validate_participant_set(3, &[0, 1]).is_err());
    }

    #[test]
    fn accepts_complete_unique_participants() {
        assert!(validate_participant_set(3, &[0, 1, 2]).is_ok());
    }
}