use dkls23_lockness::keygen;
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
