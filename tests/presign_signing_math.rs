use dkls23_lockness::presign::{nonce_commitment_for, MockMta, MultiplicationToAddition};
use dkls23_lockness::signing::{sign, verify};
use generic_ec::curves::Secp256k1;
use generic_ec::{Point, Scalar, SecretScalar};
use rand::{rngs::StdRng, SeedableRng};

fn sample_nonzero_secret(rng: &mut StdRng) -> SecretScalar<Secp256k1> {
    loop {
        let candidate = SecretScalar::<Secp256k1>::random(rng);
        if !candidate.as_ref().is_zero() {
            return candidate;
        }
    }
}

#[test]
fn nonce_commitment_detects_tampering() {
    let mut rng = StdRng::seed_from_u64(7);
    let nonce = sample_nonzero_secret(&mut rng);
    let salt = [42u8; 32];

    let commitment = nonce_commitment_for::<Secp256k1>(nonce.as_ref(), &salt);
    let tampered_commitment = nonce_commitment_for::<Secp256k1>(nonce.as_ref(), &[7u8; 32]);

    assert_ne!(commitment, tampered_commitment);
}

#[test]
fn mock_mta_is_explicitly_non_secure() {
    let mut mock = MockMta;
    let lhs = Scalar::<Secp256k1>::from(3u64);
    let rhs = Scalar::<Secp256k1>::from(7u64);

    let share = mock
        .multiply_to_additive_share(lhs, rhs)
        .expect("mock MtA should not fail");

    assert!(share.is_zero());
}

#[test]
fn signing_round_trip_verifies() {
    let mut rng = StdRng::seed_from_u64(99);
    let secret_key = sample_nonzero_secret(&mut rng);
    let nonce = sample_nonzero_secret(&mut rng);
    let message_hash = [11u8; 32];

    let signature = sign::<Secp256k1, _, _>(secret_key.as_ref(), nonce.as_ref(), &message_hash)
        .expect("signature generation should succeed");

    let public_key = Point::<Secp256k1>::generator() * secret_key.as_ref();
    let valid = verify::<Secp256k1>(&public_key, &message_hash, &signature)
        .expect("verification should succeed");

    assert!(valid);
}