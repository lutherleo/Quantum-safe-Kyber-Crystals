#ifndef PQ_PROTOCOL_H
#define PQ_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * Wire protocol
 * -------------
 * Frame: [4B length BE][1B msg_type][8B seq_num BE][payload...]
 *   length = 1 (msg_type) + 8 (seq_num) + payload_len
 *
 * Message types:
 *   0x01 HELLO      initiator -> responder, payload = sig_pk_initiator || nonce_i (16B)
 *   0x02 HELLO_ACK  responder -> initiator, payload = sig_pk_responder || kem_pk || nonce_r (16B) || sig
 *   0x03 KEM_CT     initiator -> responder, payload = kem_ct || sig
 *   0x04 DATA       AEAD ciphertext (AES-256-GCM), AAD = msg_type || seq_num
 *   0x05 CLOSE      AEAD ciphertext close notification
 */

#define PQ_MSG_HELLO     0x01
#define PQ_MSG_HELLO_ACK 0x02
#define PQ_MSG_KEM_CT    0x03
#define PQ_MSG_DATA      0x04
#define PQ_MSG_CLOSE     0x05

/* Caps to bound dynamic allocations and reject malformed frames. */
#define PQ_MAX_PAYLOAD_LEN (1u << 20)  /* 1 MiB; SLH-DSA sigs are ~35 KiB */
#define PQ_FRAME_HEADER_LEN 13         /* 4 length + 1 type + 8 seq */

/* Sliding-window replay defense (RFC 4303 style). 64-entry bitmap. */
typedef struct {
    uint64_t highest;   /* highest seq number seen so far */
    uint64_t bitmap;    /* bit i set if (highest - i) was received */
    bool initialized;
} pq_replay_window_t;

void pq_replay_init(pq_replay_window_t *w);

/* Returns true if seq is fresh (and updates window state),
 * false if seq is too old or a duplicate. */
bool pq_replay_check_and_update(pq_replay_window_t *w, uint64_t seq);

/* Frame I/O on a blocking TCP socket. Returns 0 on success, -1 on error.
 * read_frame allocates *payload via malloc; caller must free.
 * Sets *payload_len to actual payload length. */
int pq_write_frame(int sock, uint8_t msg_type, uint64_t seq,
                   const uint8_t *payload, size_t payload_len);
int pq_read_frame(int sock, uint8_t *msg_type, uint64_t *seq,
                  uint8_t **payload, size_t *payload_len);

/* Big-endian helpers. */
void pq_store_be32(uint8_t *out, uint32_t v);
void pq_store_be64(uint8_t *out, uint64_t v);
uint32_t pq_load_be32(const uint8_t *in);
uint64_t pq_load_be64(const uint8_t *in);

#endif
