
# DKLs23 Lockness, Threshold ECDSA MVP

## What does this project do?

**DKLs23 Lockness** is a Rust library demonstrating the core protocol flow for threshold ECDSA signatures using the DKLs23 design, built for the Lockness ecosystem. It shows how multiple parties can jointly generate a key, pre-sign, and sign messages without any single party ever holding the full secret key.

**Key features:**

- Honest, readable protocol structure
- Multi-party key generation (MPC DKG)
- Pre-signing and signing helpers
- Curve-generic cryptography (works for any supported curve)
- Explicit boundaries for unimplemented cryptography (OT/MtA)
- Simulation tests for protocol correctness

---
## Example output:
<img width="1242" height="187" alt="image" src="https://github.com/user-attachments/assets/6c15312f-b2e2-4f70-badb-395299633bee" />
<img width="1242" height="187" alt="image" src="https://github.com/user-attachments/assets/f55bd696-0872-4097-8649-f768497f659b" />

## Benchmarks

Benchmark plots are saved in [bench_results](bench_results):

- [benchmark_flows.png](bench_results/benchmark_flows.png)

To regenerate them:

```bash
cargo bench --bench flows -- --noplot
python3 scripts/plot_benchmarks.py
```

## Protocol Flowchart
<img width="1116" height="3727" alt="image" src="https://github.com/user-attachments/assets/2ffb2add-e570-4435-95b5-f6ed3a71040c" />


---

## How it works

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

## Why this matters

This MVP shows that the DKLs23 paper can be translated into a clean Lockness style Rust layout with typed protocol flow, curve-generic key material, and simulation-backed tests. It gives a starting point for the cryptographic work that is still ahead, while being explicit about what is implemented and what remains deferred.
