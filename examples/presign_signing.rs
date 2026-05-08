use dkls23_lockness::keygen;
use dkls23_lockness::presign::{run as presign_run, DirectMta};
use dkls23_lockness::signing::{sign_with_presignature, verify};
use dkls23_lockness::KeyShare;
use generic_ec::curves::Secp256k1;
use generic_ec::{Scalar, SecretScalar};
use rand::{rngs::StdRng, SeedableRng};
use round_based::sim;

fn sample_keygen_secret(seed: u64) -> SecretScalar<Secp256k1> {
    let mut rng = StdRng::seed_from_u64(seed);
    SecretScalar::<Secp256k1>::random(&mut rng)
}

fn main() {
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

    let message_hash = [55u8; 32];
    let signature = sign_with_presignature::<Secp256k1, _>(
        &aggregate_secret,
        &presignature,
        &message_hash,
    )
    .expect("presignature-based signing should succeed");

    let valid = verify::<Secp256k1>(&key_shares[0].public_key, &message_hash, &signature)
        .expect("verification should succeed");

    println!("signature valid: {}", valid);
    println!("r: {:?}", signature.r);
    println!("s: {:?}", signature.s);
}
