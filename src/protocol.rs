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

#[cfg(test)]
mod tests {
    use super::validate_party_configuration;

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
}