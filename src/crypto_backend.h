#ifndef PQ_CRYPTO_BACKEND_H
#define PQ_CRYPTO_BACKEND_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *name;
    const char *kem_name;
    const char *sig_name;

    size_t kem_pk_len, kem_sk_len, kem_ct_len, kem_ss_len;
    size_t sig_pk_len, sig_sk_len, sig_max_len;

    int (*kem_keypair)(uint8_t *pk, uint8_t *sk);
    int (*kem_encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*kem_decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

    int (*sig_keypair)(uint8_t *pk, uint8_t *sk);
    int (*sig_sign)(uint8_t *sig, size_t *sig_len,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *sk);
    int (*sig_verify)(const uint8_t *sig, size_t sig_len,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk);
} pq_backend_t;

extern const pq_backend_t PQ_BACKEND_A;  /* ML-KEM-768 + ML-DSA-65 */
extern const pq_backend_t PQ_BACKEND_B;  /* HQC-192 + SLH-DSA-SHA2-192s */

const pq_backend_t *pq_backend_by_name(const char *name);

#endif
