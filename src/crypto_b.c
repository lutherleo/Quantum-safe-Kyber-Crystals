/* Scheme B: HQC-192 (code-based KEM) + SLH-DSA-SHA2-192s (hash-based signature). */

#include "crypto_backend.h"

#include <oqs/oqs.h>
#include <string.h>

static int b_kem_keypair(uint8_t *pk, uint8_t *sk) {
    return OQS_KEM_hqc_192_keypair(pk, sk) == OQS_SUCCESS ? 0 : -1;
}
static int b_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return OQS_KEM_hqc_192_encaps(ct, ss, pk) == OQS_SUCCESS ? 0 : -1;
}
static int b_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return OQS_KEM_hqc_192_decaps(ss, ct, sk) == OQS_SUCCESS ? 0 : -1;
}

static int b_sig_keypair(uint8_t *pk, uint8_t *sk) {
    return OQS_SIG_sphincs_sha2_192s_simple_keypair(pk, sk) == OQS_SUCCESS ? 0 : -1;
}
static int b_sig_sign(uint8_t *sig, size_t *sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *sk) {
    return OQS_SIG_sphincs_sha2_192s_simple_sign(sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS ? 0 : -1;
}
static int b_sig_verify(const uint8_t *sig, size_t sig_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *pk) {
    return OQS_SIG_sphincs_sha2_192s_simple_verify(msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS ? 0 : -1;
}

const pq_backend_t PQ_BACKEND_B = {
    .name = "B",
    .kem_name = "HQC-192",
    .sig_name = "SLH-DSA-SHA2-192s",

    .kem_pk_len = OQS_KEM_hqc_192_length_public_key,
    .kem_sk_len = OQS_KEM_hqc_192_length_secret_key,
    .kem_ct_len = OQS_KEM_hqc_192_length_ciphertext,
    .kem_ss_len = OQS_KEM_hqc_192_length_shared_secret,

    .sig_pk_len  = OQS_SIG_sphincs_sha2_192s_simple_length_public_key,
    .sig_sk_len  = OQS_SIG_sphincs_sha2_192s_simple_length_secret_key,
    .sig_max_len = OQS_SIG_sphincs_sha2_192s_simple_length_signature,

    .kem_keypair = b_kem_keypair,
    .kem_encaps  = b_kem_encaps,
    .kem_decaps  = b_kem_decaps,

    .sig_keypair = b_sig_keypair,
    .sig_sign    = b_sig_sign,
    .sig_verify  = b_sig_verify,
};
