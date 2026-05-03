# dkls23-lockness

MVP scaffold for DKLs23 threshold ECDSA in the Lockness ecosystem.

This repository is intentionally honest about scope: it demonstrates typed MPC message flow, curve-generic key material, a simulated key-generation path, real ECDSA sign/verify helpers, and explicit presign / MtA boundaries. It does not claim to implement the full DKLs23 protocol or production-grade security yet.

## What Works

- Keygen round 1: commitment broadcast
- Keygen round 2: decommitment broadcast and verification
- Presign nonce commitment and opening helpers
- Real ECDSA signing and verification helpers
- Simulation test: all parties agree on the same public key

## Status

- Implemented: key generation MVP slice
- Implemented: presign commitment/opening flow and signing math helpers
- Scaffolded: OT extension and MtA boundary via a mock trait
- Deferred: the full DKLs23 threshold signing flow

## Validate

```bash
cargo test
```

## Docs

- [Paper mapping](docs/paper_mapping.md)
- [Security boundaries](docs/security_boundaries.md)
