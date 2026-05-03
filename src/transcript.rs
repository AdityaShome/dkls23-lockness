use generic_ec::{Curve, Point, Scalar};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl Transcript {
    pub fn new(domain: &'static [u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        Self { hasher }
    }

    pub fn absorb_bytes(&mut self, label: &'static [u8], bytes: &[u8]) {
        self.hasher.update(label);
        self.hasher.update((bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    pub fn absorb_scalar<E: Curve>(&mut self, label: &'static [u8], scalar: &Scalar<E>) {
        let bytes = serde_json::to_vec(scalar).expect("scalar serialization should succeed");
        self.absorb_bytes(label, &bytes);
    }

    pub fn absorb_point<E: Curve>(&mut self, label: &'static [u8], point: &Point<E>) {
        let bytes = serde_json::to_vec(point).expect("point serialization should succeed");
        self.absorb_bytes(label, &bytes);
    }

    pub fn finalize(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }
}
