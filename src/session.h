#ifndef PQ_SESSION_H
#define PQ_SESSION_H

#include "crypto_backend.h"
#include "protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PQ_AEAD_KEY_LEN  32
#define PQ_AEAD_SALT_LEN 4
#define PQ_AEAD_TAG_LEN  16
#define PQ_AEAD_NONCE_LEN 12
#define PQ_HANDSHAKE_NONCE_LEN 16

typedef enum { PQ_ROLE_INITIATOR, PQ_ROLE_RESPONDER } pq_role_t;

typedef struct {
    const pq_backend_t *bk;
    pq_role_t role;

    /* Long-term signature keys for this endpoint. */
    uint8_t *sig_pk;
    uint8_t *sig_sk;

    /* Peer long-term signature public key (learned during handshake). */
    uint8_t *peer_sig_pk;

    /* Per-direction AEAD keys + nonce salts. */
    uint8_t k_send[PQ_AEAD_KEY_LEN];
    uint8_t k_recv[PQ_AEAD_KEY_LEN];
    uint8_t salt_send[PQ_AEAD_SALT_LEN];
    uint8_t salt_recv[PQ_AEAD_SALT_LEN];

    uint64_t send_seq;
    pq_replay_window_t recv_window;

    /* Bytes exchanged on the wire during handshake (for benchmarking). */
    uint64_t handshake_bytes;
} pq_session_t;

int  pq_session_init(pq_session_t *s, const pq_backend_t *bk, pq_role_t role);
void pq_session_free(pq_session_t *s);

int pq_session_handshake_initiator(pq_session_t *s, int sock);
int pq_session_handshake_responder(pq_session_t *s, int sock);

int pq_session_send(pq_session_t *s, int sock, const uint8_t *msg, size_t msg_len);

/* Reads next DATA/CLOSE frame; on DATA, copies plaintext into out (max out_cap),
 * sets *out_len. Returns 0 on DATA, 1 on CLOSE, -1 on error (incl. replay/auth fail). */
int pq_session_recv(pq_session_t *s, int sock, uint8_t *out, size_t out_cap, size_t *out_len);

int pq_session_close(pq_session_t *s, int sock);

#endif
