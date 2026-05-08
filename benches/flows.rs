use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dkls23_lockness::keygen;
use dkls23_lockness::presign::{nonce_commitment_for, run as presign_run, DirectMta};
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

fn bench_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitments");
    let nonce = sample_keygen_secret(7);
    let salt = [42u8; 32];
    let secret = sample_keygen_secret(11);

    group.bench_function("keygen_commitment", |b| {
        b.iter(|| {
            let _ = black_box(dkls23_lockness::keygen::commitment_for::<Secp256k1>(
                black_box(secret.as_ref()),
                black_box(&salt),
            ));
        });
    });

    group.bench_function("nonce_commitment", |b| {
        b.iter(|| {
            let _ = black_box(nonce_commitment_for::<Secp256k1>(
                black_box(nonce.as_ref()),
                black_box(&salt),
            ));
        });
    });

    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = sign::<Secp256k1, _, _>(
                black_box(secret.as_ref()),
                black_box(nonce.as_ref()),
                black_box(&[11u8; 32]),
            )
            .expect("signing should succeed");
            black_box(signature);
        });
    });

    group.bench_function("verify", |b| {
        let public_key = Point::<Secp256k1>::generator() * secret.as_ref();
        let signature = sign::<Secp256k1, _, _>(secret.as_ref(), nonce.as_ref(), &[11u8; 32])
            .expect("signature generation should succeed");

        b.iter(|| {
            let valid = verify::<Secp256k1>(
                black_box(&public_key),
                black_box(&[11u8; 32]),
                black_box(&signature),
            )
            .expect("verification should succeed");
            black_box(valid);
        });
    });

    group.finish();
}

fn bench_keygen_simulation(c: &mut Criterion) {
    c.bench_function("keygen_simulation_n3", |b| {
        b.iter(|| {
            let shared = sim::run(3, |i, party| {
                keygen::run::<Secp256k1, _>(party, i, 3, 2, i as u64)
            })
            .expect("keygen simulation should run")
            .expect_ok()
            .expect_eq();
            black_box(shared);
        });
    });
}

fn bench_presign_and_sign(c: &mut Criterion) {
    c.bench_function("presign_sign_round_trip_n3", |b| {
        b.iter(|| {
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

            let signature = sign_with_presignature::<Secp256k1, _>(
                &aggregate_secret,
                &presignature,
                &[55u8; 32],
            )
            .expect("presignature-based signing should succeed");

            let valid = verify::<Secp256k1>(&key_shares[0].public_key, &[55u8; 32], &signature)
                .expect("verification should succeed");
            black_box(valid);
        });
    });
}

criterion_group!(
    benches,
    bench_commitments,
    bench_keygen_simulation,
    bench_presign_and_sign
);
criterion_main!(benches);
