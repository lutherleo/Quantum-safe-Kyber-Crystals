# Quantum threat analysis: Shor and Grover

## Shor's algorithm (1994)

Shor's algorithm solves integer factorisation and discrete logarithms in
polynomial time on a sufficiently large fault-tolerant quantum computer. This
breaks essentially every classical public-key primitive in widespread use:

- **RSA** — relies on the hardness of factoring `n = p·q`.
- **DH / ECDH** — relies on the hardness of the discrete-log problem in
  multiplicative or elliptic-curve groups.
- **DSA / ECDSA** — also discrete-log-based.

### Concrete cost estimates

Gidney and Ekerå's 2021 analysis ("How to factor 2048-bit RSA integers in 8
hours using 20 million noisy qubits") estimates that breaking RSA-2048 requires
approximately **4099 logical qubits** running for ~177 days, or
**~20 million physical qubits** at current surface-code error rates with 8
hours of wall-clock time. Both numbers assume a physical error rate around
10⁻³ and a surface code with code distance ~27.

For comparison, IBM's largest publicly disclosed processor (Condor, 2023) has
1121 physical qubits, and current logical-qubit demonstrations are in the
single digits. We are not yet at "cryptographically relevant quantum
computer" (CRQC) scale, but the trajectory is steep enough that NIST and NSA
both treat the threat as actionable today.

### Implication for NSA Suite B

NSA's legacy "Suite B" (RSA, ECDH, ECDSA over P-256/P-384, AES) is
**broken** for its public-key components under any "very powerful" quantum
adversary. NSA's CNSA 2.0 (Sept 2022) explicitly deprecates RSA and ECDH/ECDSA
on a 2030–2035 timeline and mandates ML-KEM / ML-DSA / SLH-DSA / LMS / XMSS
replacements.

## Grover's algorithm (1996)

Grover's algorithm provides a quadratic speedup for unstructured search: a
brute-force key recovery against an `n`-bit symmetric key drops from `O(2^n)` to
`O(2^(n/2))` quantum operations.

This **halves the effective security level** of symmetric primitives:

| Algorithm | Classical security | Post-Grover security |
|-----------|-------------------:|---------------------:|
| AES-128   |              128 b |                64 b |
| AES-192   |              192 b |                96 b |
| AES-256   |              256 b |               128 b |
| SHA-256   |              128 b (collision) | 80–85 b (BHT) |
| SHA-512   |              256 b (collision) | 170 b           |

Importantly, the Grover speedup is *not parallelisable* in the same way classical
brute force is — running `k` parallel Grover searches only gives a `√k`
speedup over a single instance, not a linear one (see Zalka 1999). This makes
the asymptotic `2^(n/2)` figure *optimistic from the attacker's perspective*; in
practice Grover may be even less useful than the bound suggests.

### Implication for AES-256

AES-256 retains roughly **128 bits of post-quantum security**, which is the
generally accepted "comfortable" symmetric strength for the foreseeable future
and the level NIST targets for its Category 5 PQ algorithms.

## Conclusion for this project

| Primitive | Classical strength | Quantum strength | Verdict |
|-----------|-------------------:|------------------:|--------|
| RSA-2048              | ~112 b | broken (Shor) | retire |
| ECDH P-256 / ECDSA    | ~128 b | broken (Shor) | retire |
| AES-128               | 128 b  | 64 b (Grover) | weak under PQ |
| AES-256               | 256 b  | ~128 b (Grover) | acceptable |
| ML-KEM-768            | NIST Cat 3 (~AES-192-eq) | best known attack super-polynomial | acceptable |
| ML-DSA-65             | NIST Cat 3 | best known attack super-polynomial | acceptable |
| HQC-192               | NIST Cat 3 | best known attack super-polynomial | acceptable, lattice-free |
| SLH-DSA-SHA2-192s     | NIST Cat 3 | reduces to hash function security; conservative | acceptable, lattice-free |

**This is exactly why we picked PQ KEMs + PQ signatures + AES-256-GCM:**
the symmetric leg shrugs off Grover, and the asymmetric leg sidesteps Shor.

## References

1. Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete
   Logarithms on a Quantum Computer", SIAM J. Comput. 26(5), 1997.
2. Grover, "A fast quantum mechanical algorithm for database search", STOC 1996.
3. Gidney & Ekerå, "How to factor 2048 bit RSA integers in 8 hours using 20
   million noisy qubits", Quantum 5, 433 (2021).
4. Zalka, "Grover's quantum searching algorithm is optimal", Phys. Rev. A 60,
   1999.
5. NSA, "Commercial National Security Algorithm Suite 2.0" (CNSA 2.0),
   September 2022.
6. NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), August 2024.
7. Aguilar Melchor et al., "HQC: Hamming Quasi-Cyclic" — round-4 NIST PQ
   submission, 2023; standardisation announced by NIST in March 2025.
