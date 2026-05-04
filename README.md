
# DKLs23 Lockness — Threshold ECDSA MVP

<div align="center">
	<img src="https://img.shields.io/badge/status-MVP-blue" alt="MVP Status"/>
	<img src="https://img.shields.io/badge/security-honest-yellow" alt="Honest Security"/>
</div>

---

## What does this project do?

**DKLs23 Lockness** is a Rust library demonstrating the core protocol flow for threshold ECDSA signatures using the DKLs23 design, built for the Lockness ecosystem. It shows how multiple parties can jointly generate a key, pre-sign, and sign messages without any single party ever holding the full secret key.

**Key features:**

- Honest, readable protocol structure — no fake security claims
- Multi-party key generation (MPC DKG)
- Pre-signing and signing helpers
- Curve-generic cryptography (works for any supported curve)
- Explicit boundaries for unimplemented cryptography (OT/MtA)
- Simulation tests for protocol correctness

---

## Protocol Flowchart
<img width="1116" height="3727" alt="image" src="https://github.com/user-attachments/assets/67dcf0a9-496b-44e6-a7d2-aa8b0e415a14" />


---

## How it works (in plain English)

1. **Key Generation:** Each party creates a secret share, commits to it, then reveals it. All parties verify everyone was honest and compute a shared public key.
2. **Pre-signing:** Each party samples a random nonce, commits, and reveals. (The real protocol would use advanced OT/MtA here; this MVP uses a mock.)
3. **Signing:** Parties combine their shares and nonces to produce a valid ECDSA signature, without any single party ever knowing the full secret key.
4. **Simulation:** The protocol is tested in-memory with multiple parties to ensure correctness.

---

## What works today

- Keygen round 1: commitment broadcast
- Keygen round 2: decommitment and verification
- Presign nonce commitment/opening helpers
- Real ECDSA signing and verification helpers
- Simulation test: all parties agree on the same public key

---

## Honest status

| Component                | Status      |
|--------------------------|-------------|
| Key generation           | Implemented |
| Presign commitment/open  | Implemented |
| Signing helpers          | Implemented |
| OT extension / MtA       | Testing     |
| Malicious checks         | Not yet     |
| Full threshold signing   | Not yet     |

---

## Quickstart

```bash
cargo test
```

---

## Documentation

- [Paper mapping](docs/paper_mapping.md) — See how the code maps to the DKLs23 paper
- [Security boundaries](docs/security_boundaries.md) — What is real, what is mocked

---

## Why this matters

Threshold ECDSA lets you split a private key across multiple parties, so no single party can ever sign alone or leak the key. This is critical for secure wallets, HSMs, and distributed trust systems. DKLs23 is a modern, efficient protocol for this — and this repo shows how to build it honestly, step by step.
