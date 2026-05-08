use dkls23_lockness::keygen;
use generic_ec::curves::Secp256k1;
use round_based::sim;

fn main() {
    let n = 3u16;
    let threshold = 2u16;

    let shared = sim::run(n, |i, party| {
        keygen::run::<Secp256k1, _>(party, i, n, threshold, i as u64)
    })
    .expect("keygen simulation should run")
    .expect_ok()
    .expect_eq();

    println!("public key: {:?}", shared.public_key);
    println!("participants: {:?}", shared.participants);
    println!("threshold: {}", shared.threshold);
}
