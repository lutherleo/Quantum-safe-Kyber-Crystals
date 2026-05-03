/* Scheme A: ML-KEM-768 + ML-DSA-65 (NIST Category 3, lattice-based). */

#include "crypto_backend.h"

#include <oqs/oqs.h>
#include <string.h>

static int a_kem_keypair(uint8_t *pk, uint8_t *sk) {
    return OQS_KEM_ml_kem_768_keypair(pk, sk) == OQS_SUCCESS ? 0 : -1;
}
static int a_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return OQS_KEM_ml_kem_768_encaps(ct, ss, pk) == OQS_SUCCESS ? 0 : -1;
}
static int a_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return OQS_KEM_ml_kem_768_decaps(ss, ct, sk) == OQS_SUCCESS ? 0 : -1;
}

static int a_sig_keypair(uint8_t *pk, uint8_t *sk) {
    return OQS_SIG_ml_dsa_65_keypair(pk, sk) == OQS_SUCCESS ? 0 : -1;
}
static int a_sig_sign(uint8_t *sig, size_t *sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *sk) {
    return OQS_SIG_ml_dsa_65_sign(sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS ? 0 : -1;
}
static int a_sig_verify(const uint8_t *sig, size_t sig_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *pk) {
    return OQS_SIG_ml_dsa_65_verify(msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS ? 0 : -1;
}

const pq_backend_t PQ_BACKEND_A = {
    .name = "A",
    .kem_name = "ML-KEM-768",
    .sig_name = "ML-DSA-65",

    .kem_pk_len = OQS_KEM_ml_kem_768_length_public_key,
    .kem_sk_len = OQS_KEM_ml_kem_768_length_secret_key,
    .kem_ct_len = OQS_KEM_ml_kem_768_length_ciphertext,
    .kem_ss_len = OQS_KEM_ml_kem_768_length_shared_secret,

    .sig_pk_len  = OQS_SIG_ml_dsa_65_length_public_key,
    .sig_sk_len  = OQS_SIG_ml_dsa_65_length_secret_key,
    .sig_max_len = OQS_SIG_ml_dsa_65_length_signature,

    .kem_keypair = a_kem_keypair,
    .kem_encaps  = a_kem_encaps,
    .kem_decaps  = a_kem_decaps,

    .sig_keypair = a_sig_keypair,
    .sig_sign    = a_sig_sign,
    .sig_verify  = a_sig_verify,
};

const pq_backend_t *pq_backend_by_name(const char *name) {
    if (!name) return NULL;
    if (name[0] == 'A' || name[0] == 'a') return &PQ_BACKEND_A;
    if (name[0] == 'B' || name[0] == 'b') return &PQ_BACKEND_B;
    return NULL;
}
