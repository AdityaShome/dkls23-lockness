use dkls23_lockness::keygen;
use dkls23_lockness::Error;
use generic_ec::curves::Secp256k1;
use round_based::sim;

#[test]
fn keygen_simulation_produces_matching_public_key() {
    let n = 3;
    let threshold = 2;

    let shared = sim::run(n, |i, party| {
        keygen::run::<Secp256k1, _>(party, i, n as u16, threshold, i as u64)
    })
    .unwrap();

    let shared = shared.expect_ok().expect_eq();

    assert_eq!(shared.threshold, threshold);
    assert_eq!(shared.participants.len(), usize::from(n));
    assert!(!shared.public_shares.is_empty());
}

#[test]
fn keygen_rejects_invalid_threshold() {
    let n = 3u16;

    let results = sim::run(n, |i, party| {
        keygen::run::<Secp256k1, _>(party, i, n, 0, i as u64)
    })
    .expect("simulation should run");

    assert!(results
        .0
        .iter()
        .all(|result| matches!(result, Err(Error::InvalidConfiguration { threshold: 0, .. }))));
}
