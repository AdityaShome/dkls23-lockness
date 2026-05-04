use dkls23_lockness::keygen;
use dkls23_lockness::presign::{nonce_commitment_for, run as presign_run, DirectMta, MultiplicationToAddition};
use dkls23_lockness::signing::{sign, sign_with_presignature, verify};
use dkls23_lockness::KeyShare;
use generic_ec::curves::Secp256k1;
use generic_ec::{Point, Scalar, SecretScalar};
use rand::{rngs::StdRng, SeedableRng};
use round_based::sim;

fn sample_keygen_secret(seed: u64) -> SecretScalar<Secp256k1> {
    let mut rng = StdRng::seed_from_u64(seed);
    SecretScalar::<Secp256k1>::random(&mut rng)
}

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
fn direct_mta_multiplies_inputs() {
    let mut mta = DirectMta;
    let lhs = Scalar::<Secp256k1>::from(3u64);
    let rhs = Scalar::<Secp256k1>::from(7u64);

    let share = mta
        .multiply_to_additive_share(lhs, rhs)
        .expect("direct MtA should not fail");

    assert_eq!(share, Scalar::<Secp256k1>::from(21u64));
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

#[test]
fn presign_to_sign_round_trip_verifies() {
    let n = 3usize;
    let threshold = 2u16;

    let keygen_output = sim::run(n as u16, |i, party| {
        keygen::run::<Secp256k1, _>(party, i, n as u16, threshold, i as u64)
    })
    .expect("keygen simulation should run")
    .expect_ok()
    .expect_eq();

    let key_shares: Vec<KeyShare<Secp256k1>> = (0..n)
        .map(|index| {
            KeyShare::new(
                keygen_output.public_key,
                keygen_output.public_shares.clone(),
                keygen_output.participants.clone(),
                threshold,
                index as u16,
                sample_keygen_secret(index as u64),
            )
        })
        .collect();

    let presignature = sim::run(n as u16, {
        let key_shares = key_shares.clone();
        move |i, party| {
            let key_share = key_shares[usize::from(i)].clone();
            async move {
                presign_run::<Secp256k1, _, _>(
                    party,
                    &key_share,
                    DirectMta,
                    i,
                    n as u16,
                    threshold,
                    100 + u64::from(i),
                )
                .await
            }
        }
    })
    .expect("presign simulation should run")
    .expect_ok()
    .expect_eq();

    let aggregate_secret = key_shares.iter().fold(Scalar::<Secp256k1>::zero(), |acc, key_share| {
        acc + key_share.local_secret_share().as_ref().clone()
    });

    let local_key_share = &key_shares[usize::from(presignature.party_index)];
    let expected_product = local_key_share.local_secret_share().as_ref().clone()
        * presignature.local_nonce_share().as_ref().clone();
    assert_eq!(presignature.nonce_secret_product_share, expected_product);

    let message_hash = [55u8; 32];
    let signature = sign_with_presignature::<Secp256k1, _>(
        &aggregate_secret,
        &presignature,
        &message_hash,
    )
    .expect("presignature-based signing should succeed");

    let valid = verify::<Secp256k1>(&key_shares[0].public_key, &message_hash, &signature)
        .expect("verification should succeed");

    assert!(valid);
}