# Key length / parameter set justification

## Target security level

Both schemes are instantiated at **NIST Post-Quantum Security Category 3**,
which NIST defines as "at least as hard to break as AES-192 (key search)".
This is the level CNSA 2.0 mandates for U.S. government national-security
systems and which NIST recommends for systems whose data must remain
confidential through ~2035 and beyond.

We chose Cat 3 (rather than Cat 1 or Cat 5) for three reasons:

1. **Apples-to-apples comparison.** Picking the same NIST category for both
   schemes is the only way to compare their performance and bandwidth honestly.
2. **CNSA 2.0 alignment.** CNSA 2.0 specifies ML-KEM-1024 / ML-DSA-87
   (Cat 5) for top-secret data and effectively Cat 3 or higher for everything
   else; Cat 3 is the sweet spot for "secret-grade" data and ordinary
   commercial sensitive material.
3. **Symmetric-key parity.** With AES-256 + Grover we have ~128 bits of PQ
   symmetric security, which is comparable to NIST Cat 3's ~AES-192 PQ floor.
   The system is balanced — no leg is a weak link.

## Scheme A — lattice (NIST-standardised)

| Algorithm  | Spec       | Public key | Secret key | Ciphertext / signature | Notes |
|------------|-----------|-----------:|-----------:|-----------------------:|-------|
| ML-KEM-768 | FIPS 203 | 1184 B | 2400 B | 1088 B (ct) | Module-LWE/MLWR. Cat 3. |
| ML-DSA-65  | FIPS 204 | 1952 B | 4032 B | 3309 B (sig) | Module-LWE + Fiat-Shamir. Cat 3. |

ML-KEM and ML-DSA are the NIST-standardised winners of round 3 of the PQ
competition. Their security is conjectured to lie in the structured-lattice
LWE family; the best classical and quantum attacks are super-polynomial
(roughly `2^150+` core SVP cost at this parameter set).

## Scheme B — diversified (code + hash, lattice-free)

| Algorithm           | Spec                                | Public key | Secret key | Ciphertext / signature | Notes |
|---------------------|-------------------------------------|-----------:|-----------:|-----------------------:|-------|
| HQC-192             | HQC v2024 / NIST FIPS draft       |  4522 B    |  4562 B    |   9026 B (ct) | Code-based (rank-metric Hamming Quasi-Cyclic). Cat 3. |
| SLH-DSA-SHA2-192s   | FIPS 205                            |    48 B    |    96 B    |  16224 B (sig) | Hash-based (SPHINCS+). Cat 3. |

We picked HQC + SLH-DSA-SHA2-192s for "Scheme B" specifically because
**neither relies on lattices**:

- **HQC** rests on the hardness of decoding random quasi-cyclic codes — a
  classical problem since McEliece (1978).
- **SLH-DSA / SPHINCS+** rests *only* on the (one-way / collision /
  preimage) hardness of its underlying hash function (SHA-256 here). This is
  the most conservative assumption available — if SHA-2 falls,
  approximately every other crypto primitive in production also falls.

If a surprise mathematical breakthrough flattens lattice-based PQ, Scheme B
remains a viable fallback. This is the intent of CNSA 2.0's inclusion of
SLH-DSA / LMS / XMSS as "stateful and stateless hash-based" alternatives to
ML-DSA.

## Symmetric / KDF

| Primitive      | Library      | Justification                                                              |
|----------------|--------------|----------------------------------------------------------------------------|
| AES-256-GCM    | OpenSSL EVP | 128-bit PQ security (post-Grover); ubiquitous; well-analysed nonce/tag sizes. |
| HKDF-SHA256    | OpenSSL EVP | Standard extract-then-expand KDF (RFC 5869); SHA-256 retains ~128-bit PQ. |
| 12-byte GCM nonce, 16-byte tag | — | Standard NIST SP 800-38D parameters.                          |
| 4-byte random salt + 8-byte counter nonce construction | — | Avoids per-direction nonce collisions; safe up to 2⁶⁴ frames per direction. |

## What we did **not** pick, and why

- **ML-KEM-512 / ML-DSA-44 (Cat 1)** — only matches AES-128 PQ-equivalent, too
  thin a margin given that Grover already chews on AES-128.
- **ML-KEM-1024 / ML-DSA-87 (Cat 5)** — overkill for a project demo and would
  exaggerate Scheme A's bandwidth disadvantage relative to a fair comparison.
- **Kyber512 / Kyber-original parameter sets** — superseded by ML-KEM (FIPS 203);
  the wire format and security claims now follow FIPS 203, not the original
  Kyber paper.
- **HQC-128** — Cat 1, would not match Scheme A.
- **SLH-DSA-SHAKE-192f** — chose `SHA2-192s` (small, slow) over `192f` (fast,
  larger) because handshake bandwidth dominates over CPU for this project.
  `192s` keeps signatures down to ~16 KiB versus ~36 KiB for `192f`.

## References

1. NIST, "Status Report on the Third Round of the NIST Post-Quantum
   Cryptography Standardization Process", NISTIR 8413, July 2022.
2. FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard),
   August 2024.
3. FIPS 204 (Module-Lattice-Based Digital Signature Standard), August 2024.
4. FIPS 205 (Stateless Hash-Based Digital Signature Standard), August 2024.
5. NSA, CNSA 2.0, September 2022.
6. NIST IR 8547 draft (2025), KEM standardisation including HQC.
