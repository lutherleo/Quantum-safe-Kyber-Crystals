# pq-secure-comm — Post-Quantum Secure Channel Comparison

A research-grade C implementation of a post-quantum-secure channel between two
endpoints (Alice ↔ Bob), implemented twice with two **different families** of
post-quantum primitives, then attacked and benchmarked under a unified test
harness.

> NYU CS6903 — Project 3.5

## What's in the box

Two end-to-end secure channels at NIST PQ Category 3:

| | Scheme A (lattice) | Scheme B (diversified, lattice-free) |
|---|---|---|
| KEM       | ML-KEM-768 (Kyber)    | HQC-192 |
| Signature | ML-DSA-65 (Dilithium) | SLH-DSA-SHA2-192s (SPHINCS+) |
| AEAD      | AES-256-GCM           | AES-256-GCM |
| KDF       | HKDF-SHA256           | HKDF-SHA256 |

Both pluggable behind the same `pq_backend_t` interface — pick at runtime with
`--backend A` / `--backend B`.

## Quickstart

You only need Docker.

```bash
git clone <this-repo> pq-secure-comm && cd pq-secure-comm

make build         # builds the image (pulls liboqs, ~10 min on first build)
make test          # runs all three attack demos; non-zero exit = failure
make benchmark     # runs the perf harness, drops PNGs into ./results/
```

## Architecture

```
                 ┌─────────────────────────────────────────────┐
                 │              docker network "pqnet"          │
                 │                                              │
   alice ──────► attacker ──────► bob                           │
   (initiator) (MITM proxy)      (responder)                    │
                                                                │
   benchmark (one-shot)                                         │
                 └─────────────────────────────────────────────┘
                          │
                          ▼
                    ./results/  (CSVs + PNGs + pcaps + logs)
```

The wire protocol is documented in [docs/protocol.md](docs/protocol.md). The
short version:

```
[ HELLO ── KEM_pk_eph + sig of (kem_pk||nonces) signed by responder ]
[ KEM_CT signed by initiator                                        ]
[ HKDF-SHA256(KEM_ss || transcript_nonces) → per-direction AEAD keys ]
[ DATA frames, AES-256-GCM with AAD = msg_type||seq, sliding-window replay defense ]
```

## Running each demo manually

### Eavesdropping (passive)
```bash
make demo-eavesdrop
```
- Starts bob, alice, and a passive proxy.
- `tcpdump`s the proxy's interface.
- `strings` over the pcap looking for the plaintext message.
- **Pass** = plaintext NOT found.

### Active modification
```bash
make demo-modify
```
- Proxy flips one bit in the first DATA frame.
- **Pass** = bob logs `GCM auth failure` and exits non-zero.

### Replay
```bash
make demo-replay
```
- Proxy captures DATA frame #1 and resends it after delivering it.
- **Pass** = bob logs `replay detected` and exits non-zero.

## Benchmark output

`make benchmark` runs 1000 iterations of each operation per backend and emits:

- `results/bench_raw.csv`     — every individual sample
- `results/bench_summary.csv` — median / mean / stddev / p95 / p99 per (backend, op)
- `results/bench_sizes.csv`   — artifact byte sizes
- `results/handshake_latency.png`
- `results/per_op_latency.png`
- `results/artifact_sizes.png`
- A markdown summary table printed to stdout, ready to paste into slides.

## File map

```
.
├── Dockerfile               # ubuntu 24.04 + liboqs + openssl
├── docker-compose.yml       # alice / bob / attacker / benchmark services
├── CMakeLists.txt
├── Makefile                 # high-level make targets (test, benchmark, ...)
├── docs/
│   ├── protocol.md                   # wire format + state machine
│   ├── shor_grover_analysis.md       # quantum threat write-up
│   └── key_length_justification.md   # NIST Cat 3 rationale
├── src/
│   ├── protocol.{h,c}       # framing + sliding-window replay defense
│   ├── crypto_backend.h     # abstract KEM/SIG interface
│   ├── crypto_a.c           # Scheme A bindings (ML-KEM-768 + ML-DSA-65)
│   ├── crypto_b.c           # Scheme B bindings (HQC-192 + SLH-DSA-SHA2-192s)
│   ├── session.{h,c}        # handshake state machine, HKDF, AES-GCM
│   ├── net.{h,c}            # TCP socket helpers
│   ├── alice.c              # initiator main()
│   ├── bob.c                # responder main()
│   ├── attacker.c           # MITM proxy: passthrough / flip / replay
│   ├── benchmark.c          # statistical perf harness
│   └── test_protocol.c      # unit tests for framing + replay window
└── scripts/
    ├── demo_eavesdrop.sh
    ├── demo_modify.sh
    ├── demo_replay.sh
    ├── run_benchmark.sh
    └── plot_results.py
```

## Security caveats

This is **research code**. Do not deploy as-is.

- No formal verification, no third-party audit.
- liboqs implementations are not constant-time on all platforms.
- The handshake binds both nonces but does not include a key-confirmation
  finished message — it's relying on the first-DATA-frame GCM auth as a de
  facto key confirmation.
- Long-term signature keys are generated fresh on every run rather than
  loaded from a trust store; in production you'd pin the peer's `sig_pk`
  out-of-band or via a PKI.
- `liboqs` itself is moving fast; pinned to `0.12.0` for reproducibility.

## References

- NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA)
- NSA CNSA 2.0
- Open Quantum Safe project — <https://openquantumsafe.org>
- Gidney & Ekerå, "How to factor 2048 bit RSA integers in 8 hours using 20
  million noisy qubits", *Quantum* 5 (2021).
- See [docs/shor_grover_analysis.md](docs/shor_grover_analysis.md) for the
  threat-model write-up.
