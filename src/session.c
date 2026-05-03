#include "session.h"
#include "protocol.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

/* -----------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

static void log_step(const char *who, const char *msg) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stderr, "[%ld.%06ld] %s: %s\n",
            (long)ts.tv_sec, ts.tv_nsec / 1000, who, msg);
}

/* HKDF-SHA256 via OpenSSL EVP. */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return -1;
    int rc = -1;
    if (EVP_PKEY_derive_init(ctx) <= 0) goto out;
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) goto out;
    if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) <= 0) goto out;
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) <= 0) goto out;
    if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) <= 0) goto out;
    size_t len = out_len;
    if (EVP_PKEY_derive(ctx, out, &len) <= 0) goto out;
    if (len != out_len) goto out;
    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

/* AES-256-GCM seal: ct||tag into out (must hold pt_len + 16). */
static int aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = -1, len = 0, total = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto out;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto out;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) goto out;
    if (aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len)) goto out;
    }
    if (1 != EVP_EncryptUpdate(ctx, out, &len, pt, (int)pt_len)) goto out;
    total = len;
    if (1 != EVP_EncryptFinal_ex(ctx, out + total, &len)) goto out;
    total += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out + total)) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* AES-256-GCM open: requires in_len >= 16. Writes plaintext into out (in_len-16 bytes).
 * Returns 0 on success, -1 on auth failure or any error. */
static int aead_open(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out) {
    if (in_len < 16) return -1;
    size_t ct_len = in_len - 16;
    const uint8_t *tag = in + ct_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int rc = -1, len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto out;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) goto out;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) goto out;
    if (aad_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len)) goto out;
    }
    if (1 != EVP_DecryptUpdate(ctx, out, &len, in, (int)ct_len)) goto out;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag)) goto out;
    if (1 != EVP_DecryptFinal_ex(ctx, out + len, &len)) goto out;
    rc = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static void build_aad(uint8_t aad[9], uint8_t msg_type, uint64_t seq) {
    aad[0] = msg_type;
    pq_store_be64(aad + 1, seq);
}

static void build_nonce(uint8_t nonce[12], const uint8_t salt[4], uint64_t seq) {
    memcpy(nonce, salt, 4);
    pq_store_be64(nonce + 4, seq);
}

/* -----------------------------------------------------------------------------
 * Init / free
 * -------------------------------------------------------------------------- */

int pq_session_init(pq_session_t *s, const pq_backend_t *bk, pq_role_t role) {
    memset(s, 0, sizeof *s);
    s->bk = bk;
    s->role = role;
    pq_replay_init(&s->recv_window);

    s->sig_pk = (uint8_t *)malloc(bk->sig_pk_len);
    s->sig_sk = (uint8_t *)malloc(bk->sig_sk_len);
    s->peer_sig_pk = (uint8_t *)malloc(bk->sig_pk_len);
    if (!s->sig_pk || !s->sig_sk || !s->peer_sig_pk) {
        pq_session_free(s);
        return -1;
    }
    if (bk->sig_keypair(s->sig_pk, s->sig_sk) != 0) {
        pq_session_free(s);
        return -1;
    }
    return 0;
}

void pq_session_free(pq_session_t *s) {
    if (!s) return;
    free(s->sig_pk);
    free(s->sig_sk);
    free(s->peer_sig_pk);
    OPENSSL_cleanse(s->k_send, sizeof s->k_send);
    OPENSSL_cleanse(s->k_recv, sizeof s->k_recv);
    s->sig_pk = s->sig_sk = s->peer_sig_pk = NULL;
}

/* Derive bidirectional keys + salts from KEM shared secret + handshake nonces. */
static int derive_session_keys(pq_session_t *s,
                               const uint8_t *ss, size_t ss_len,
                               const uint8_t nonce_i[PQ_HANDSHAKE_NONCE_LEN],
                               const uint8_t nonce_r[PQ_HANDSHAKE_NONCE_LEN]) {
    uint8_t salt[2 * PQ_HANDSHAKE_NONCE_LEN];
    memcpy(salt, nonce_i, PQ_HANDSHAKE_NONCE_LEN);
    memcpy(salt + PQ_HANDSHAKE_NONCE_LEN, nonce_r, PQ_HANDSHAKE_NONCE_LEN);

    static const char info[] = "pq-secure-comm v1";
    uint8_t out[2 * PQ_AEAD_KEY_LEN + 2 * PQ_AEAD_SALT_LEN];
    if (hkdf_sha256(ss, ss_len, salt, sizeof salt,
                    (const uint8_t *)info, sizeof info - 1,
                    out, sizeof out) != 0) {
        return -1;
    }

    /* Layout: [k_i2r 32][k_r2i 32][salt_i2r 4][salt_r2i 4] */
    const uint8_t *k_i2r = out;
    const uint8_t *k_r2i = out + 32;
    const uint8_t *salt_i2r = out + 64;
    const uint8_t *salt_r2i = out + 68;

    if (s->role == PQ_ROLE_INITIATOR) {
        memcpy(s->k_send, k_i2r, 32);
        memcpy(s->k_recv, k_r2i, 32);
        memcpy(s->salt_send, salt_i2r, 4);
        memcpy(s->salt_recv, salt_r2i, 4);
    } else {
        memcpy(s->k_send, k_r2i, 32);
        memcpy(s->k_recv, k_i2r, 32);
        memcpy(s->salt_send, salt_r2i, 4);
        memcpy(s->salt_recv, salt_i2r, 4);
    }
    OPENSSL_cleanse(out, sizeof out);
    return 0;
}

/* -----------------------------------------------------------------------------
 * Handshake
 * -------------------------------------------------------------------------- */

int pq_session_handshake_initiator(pq_session_t *s, int sock) {
    const pq_backend_t *bk = s->bk;
    uint8_t nonce_i[PQ_HANDSHAKE_NONCE_LEN];
    if (RAND_bytes(nonce_i, sizeof nonce_i) != 1) return -1;

    /* --- Send HELLO: sig_pk_i || nonce_i --- */
    size_t hello_len = bk->sig_pk_len + sizeof nonce_i;
    uint8_t *hello = (uint8_t *)malloc(hello_len);
    if (!hello) return -1;
    memcpy(hello, s->sig_pk, bk->sig_pk_len);
    memcpy(hello + bk->sig_pk_len, nonce_i, sizeof nonce_i);
    int rc = pq_write_frame(sock, PQ_MSG_HELLO, 0, hello, hello_len);
    s->handshake_bytes += PQ_FRAME_HEADER_LEN + hello_len;
    free(hello);
    if (rc != 0) return -1;
    log_step("initiator", "sent HELLO");

    /* --- Receive HELLO_ACK: sig_pk_r || kem_pk || nonce_r || sig --- */
    uint8_t mt; uint64_t seq; uint8_t *ack = NULL; size_t ack_len = 0;
    if (pq_read_frame(sock, &mt, &seq, &ack, &ack_len) != 0) return -1;
    s->handshake_bytes += PQ_FRAME_HEADER_LEN + ack_len;
    if (mt != PQ_MSG_HELLO_ACK) { free(ack); return -1; }

    size_t expected_min = bk->sig_pk_len + bk->kem_pk_len + PQ_HANDSHAKE_NONCE_LEN;
    if (ack_len < expected_min) { free(ack); return -1; }

    const uint8_t *sig_pk_r = ack;
    const uint8_t *kem_pk   = ack + bk->sig_pk_len;
    const uint8_t *nonce_r  = ack + bk->sig_pk_len + bk->kem_pk_len;
    const uint8_t *sig      = nonce_r + PQ_HANDSHAKE_NONCE_LEN;
    size_t sig_len = ack_len - expected_min;
    if (sig_len == 0 || sig_len > bk->sig_max_len) { free(ack); return -1; }

    /* Verify sig over (sig_pk_r || kem_pk || nonce_r || nonce_i). */
    size_t tbs_len = bk->sig_pk_len + bk->kem_pk_len + PQ_HANDSHAKE_NONCE_LEN + PQ_HANDSHAKE_NONCE_LEN;
    uint8_t *tbs = (uint8_t *)malloc(tbs_len);
    if (!tbs) { free(ack); return -1; }
    memcpy(tbs, sig_pk_r, bk->sig_pk_len);
    memcpy(tbs + bk->sig_pk_len, kem_pk, bk->kem_pk_len);
    memcpy(tbs + bk->sig_pk_len + bk->kem_pk_len, nonce_r, PQ_HANDSHAKE_NONCE_LEN);
    memcpy(tbs + bk->sig_pk_len + bk->kem_pk_len + PQ_HANDSHAKE_NONCE_LEN, nonce_i, PQ_HANDSHAKE_NONCE_LEN);

    if (bk->sig_verify(sig, sig_len, tbs, tbs_len, sig_pk_r) != 0) {
        free(tbs); free(ack);
        log_step("initiator", "HELLO_ACK signature INVALID");
        return -1;
    }
    free(tbs);
    memcpy(s->peer_sig_pk, sig_pk_r, bk->sig_pk_len);
    log_step("initiator", "HELLO_ACK signature verified");

    /* --- KEM encapsulation --- */
    uint8_t *kem_ct = (uint8_t *)malloc(bk->kem_ct_len);
    uint8_t *ss     = (uint8_t *)malloc(bk->kem_ss_len);
    if (!kem_ct || !ss) { free(kem_ct); free(ss); free(ack); return -1; }
    if (bk->kem_encaps(kem_ct, ss, kem_pk) != 0) {
        free(kem_ct); free(ss); free(ack); return -1;
    }
    log_step("initiator", "KEM encaps complete");

    /* --- Sign (kem_ct || nonce_i || nonce_r) and send KEM_CT --- */
    size_t tbs2_len = bk->kem_ct_len + 2 * PQ_HANDSHAKE_NONCE_LEN;
    uint8_t *tbs2 = (uint8_t *)malloc(tbs2_len);
    uint8_t *sig2 = (uint8_t *)malloc(bk->sig_max_len);
    if (!tbs2 || !sig2) { free(tbs2); free(sig2); free(kem_ct); free(ss); free(ack); return -1; }
    memcpy(tbs2, kem_ct, bk->kem_ct_len);
    memcpy(tbs2 + bk->kem_ct_len, nonce_i, PQ_HANDSHAKE_NONCE_LEN);
    memcpy(tbs2 + bk->kem_ct_len + PQ_HANDSHAKE_NONCE_LEN, nonce_r, PQ_HANDSHAKE_NONCE_LEN);
    size_t sig2_len = bk->sig_max_len;
    if (bk->sig_sign(sig2, &sig2_len, tbs2, tbs2_len, s->sig_sk) != 0) {
        free(tbs2); free(sig2); free(kem_ct); free(ss); free(ack); return -1;
    }
    free(tbs2);

    size_t kem_ct_msg_len = bk->kem_ct_len + sig2_len;
    uint8_t *kem_ct_msg = (uint8_t *)malloc(kem_ct_msg_len);
    if (!kem_ct_msg) { free(sig2); free(kem_ct); free(ss); free(ack); return -1; }
    memcpy(kem_ct_msg, kem_ct, bk->kem_ct_len);
    memcpy(kem_ct_msg + bk->kem_ct_len, sig2, sig2_len);
    rc = pq_write_frame(sock, PQ_MSG_KEM_CT, 0, kem_ct_msg, kem_ct_msg_len);
    s->handshake_bytes += PQ_FRAME_HEADER_LEN + kem_ct_msg_len;
    free(kem_ct_msg); free(sig2); free(kem_ct); free(ack);
    if (rc != 0) { free(ss); return -1; }
    log_step("initiator", "sent KEM_CT");

    /* Derive session keys from ss. */
    if (derive_session_keys(s, ss, bk->kem_ss_len, nonce_i, nonce_r) != 0) {
        OPENSSL_cleanse(ss, bk->kem_ss_len); free(ss); return -1;
    }
    OPENSSL_cleanse(ss, bk->kem_ss_len);
    free(ss);
    log_step("initiator", "session keys derived");
    return 0;
}

int pq_session_handshake_responder(pq_session_t *s, int sock) {
    const pq_backend_t *bk = s->bk;

    /* --- Receive HELLO --- */
    uint8_t mt; uint64_t seq; uint8_t *hello = NULL; size_t hello_len = 0;
    if (pq_read_frame(sock, &mt, &seq, &hello, &hello_len) != 0) return -1;
    s->handshake_bytes += PQ_FRAME_HEADER_LEN + hello_len;
    if (mt != PQ_MSG_HELLO) { free(hello); return -1; }
    if (hello_len != bk->sig_pk_len + PQ_HANDSHAKE_NONCE_LEN) { free(hello); return -1; }

    memcpy(s->peer_sig_pk, hello, bk->sig_pk_len);
    uint8_t nonce_i[PQ_HANDSHAKE_NONCE_LEN];
    memcpy(nonce_i, hello + bk->sig_pk_len, PQ_HANDSHAKE_NONCE_LEN);
    free(hello);
    log_step("responder", "received HELLO");

    /* --- Generate ephemeral KEM keypair + nonce_r --- */
    uint8_t *kem_pk = (uint8_t *)malloc(bk->kem_pk_len);
    uint8_t *kem_sk = (uint8_t *)malloc(bk->kem_sk_len);
    if (!kem_pk || !kem_sk) { free(kem_pk); free(kem_sk); return -1; }
    if (bk->kem_keypair(kem_pk, kem_sk) != 0) { free(kem_pk); free(kem_sk); return -1; }

    uint8_t nonce_r[PQ_HANDSHAKE_NONCE_LEN];
    if (RAND_bytes(nonce_r, sizeof nonce_r) != 1) { free(kem_pk); free(kem_sk); return -1; }

    /* --- Sign (sig_pk_r || kem_pk || nonce_r || nonce_i) --- */
    size_t tbs_len = bk->sig_pk_len + bk->kem_pk_len + 2 * PQ_HANDSHAKE_NONCE_LEN;
    uint8_t *tbs = (uint8_t *)malloc(tbs_len);
    if (!tbs) { free(kem_pk); free(kem_sk); return -1; }
    memcpy(tbs, s->sig_pk, bk->sig_pk_len);
    memcpy(tbs + bk->sig_pk_len, kem_pk, bk->kem_pk_len);
    memcpy(tbs + bk->sig_pk_len + bk->kem_pk_len, nonce_r, PQ_HANDSHAKE_NONCE_LEN);
    memcpy(tbs + bk->sig_pk_len + bk->kem_pk_len + PQ_HANDSHAKE_NONCE_LEN, nonce_i, PQ_HANDSHAKE_NONCE_LEN);

    uint8_t *sig = (uint8_t *)malloc(bk->sig_max_len);
    size_t sig_len = bk->sig_max_len;
    if (!sig || bk->sig_sign(sig, &sig_len, tbs, tbs_len, s->sig_sk) != 0) {
        free(tbs); free(sig); free(kem_pk); free(kem_sk); return -1;
    }
    free(tbs);

    /* --- Send HELLO_ACK: sig_pk_r || kem_pk || nonce_r || sig --- */
    size_t ack_len = bk->sig_pk_len + bk->kem_pk_len + PQ_HANDSHAKE_NONCE_LEN + sig_len;
    uint8_t *ack = (uint8_t *)malloc(ack_len);
    if (!ack) { free(sig); free(kem_pk); free(kem_sk); return -1; }
    memcpy(ack, s->sig_pk, bk->sig_pk_len);
    memcpy(ack + bk->sig_pk_len, kem_pk, bk->kem_pk_len);
    memcpy(ack + bk->sig_pk_len + bk->kem_pk_len, nonce_r, PQ_HANDSHAKE_NONCE_LEN);
    memcpy(ack + bk->sig_pk_len + bk->kem_pk_len + PQ_HANDSHAKE_NONCE_LEN, sig, sig_len);

    int rc = pq_write_frame(sock, PQ_MSG_HELLO_ACK, 0, ack, ack_len);
    s->handshake_bytes += PQ_FRAME_HEADER_LEN + ack_len;
    free(ack); free(sig); free(kem_pk);
    if (rc != 0) { free(kem_sk); return -1; }
    log_step("responder", "sent HELLO_ACK");

    /* --- Receive KEM_CT: kem_ct || sig --- */
    uint8_t *ct_msg = NULL; size_t ct_msg_len = 0;
    if (pq_read_frame(sock, &mt, &seq, &ct_msg, &ct_msg_len) != 0) {
        free(kem_sk); return -1;
    }
    s->handshake_bytes += PQ_FRAME_HEADER_LEN + ct_msg_len;
    if (mt != PQ_MSG_KEM_CT || ct_msg_len <= bk->kem_ct_len) {
        free(ct_msg); free(kem_sk); return -1;
    }
    const uint8_t *kem_ct = ct_msg;
    const uint8_t *sig_i  = ct_msg + bk->kem_ct_len;
    size_t sig_i_len = ct_msg_len - bk->kem_ct_len;

    /* Verify sig over (kem_ct || nonce_i || nonce_r). */
    size_t tbs2_len = bk->kem_ct_len + 2 * PQ_HANDSHAKE_NONCE_LEN;
    uint8_t *tbs2 = (uint8_t *)malloc(tbs2_len);
    if (!tbs2) { free(ct_msg); free(kem_sk); return -1; }
    memcpy(tbs2, kem_ct, bk->kem_ct_len);
    memcpy(tbs2 + bk->kem_ct_len, nonce_i, PQ_HANDSHAKE_NONCE_LEN);
    memcpy(tbs2 + bk->kem_ct_len + PQ_HANDSHAKE_NONCE_LEN, nonce_r, PQ_HANDSHAKE_NONCE_LEN);
    if (bk->sig_verify(sig_i, sig_i_len, tbs2, tbs2_len, s->peer_sig_pk) != 0) {
        free(tbs2); free(ct_msg); free(kem_sk);
        log_step("responder", "KEM_CT signature INVALID");
        return -1;
    }
    free(tbs2);
    log_step("responder", "KEM_CT signature verified");

    /* --- KEM decaps --- */
    uint8_t *ss = (uint8_t *)malloc(bk->kem_ss_len);
    if (!ss || bk->kem_decaps(ss, kem_ct, kem_sk) != 0) {
        free(ss); free(ct_msg); free(kem_sk); return -1;
    }
    free(ct_msg);
    OPENSSL_cleanse(kem_sk, bk->kem_sk_len);
    free(kem_sk);

    if (derive_session_keys(s, ss, bk->kem_ss_len, nonce_i, nonce_r) != 0) {
        OPENSSL_cleanse(ss, bk->kem_ss_len); free(ss); return -1;
    }
    OPENSSL_cleanse(ss, bk->kem_ss_len);
    free(ss);
    log_step("responder", "session keys derived");
    return 0;
}

/* -----------------------------------------------------------------------------
 * Data path
 * -------------------------------------------------------------------------- */

static int session_send_typed(pq_session_t *s, int sock, uint8_t msg_type,
                              const uint8_t *msg, size_t msg_len) {
    uint64_t seq = s->send_seq++;
    uint8_t aad[9]; build_aad(aad, msg_type, seq);
    uint8_t nonce[12]; build_nonce(nonce, s->salt_send, seq);

    size_t out_len = msg_len + 16;
    uint8_t *out = (uint8_t *)malloc(out_len);
    if (!out) return -1;
    if (aead_seal(s->k_send, nonce, aad, sizeof aad, msg, msg_len, out) != 0) {
        free(out); return -1;
    }
    int rc = pq_write_frame(sock, msg_type, seq, out, out_len);
    free(out);
    return rc;
}

int pq_session_send(pq_session_t *s, int sock, const uint8_t *msg, size_t msg_len) {
    return session_send_typed(s, sock, PQ_MSG_DATA, msg, msg_len);
}

int pq_session_close(pq_session_t *s, int sock) {
    static const uint8_t empty = 0;
    return session_send_typed(s, sock, PQ_MSG_CLOSE, &empty, 1);
}

int pq_session_recv(pq_session_t *s, int sock, uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t mt; uint64_t seq; uint8_t *payload = NULL; size_t payload_len = 0;
    if (pq_read_frame(sock, &mt, &seq, &payload, &payload_len) != 0) return -1;

    if (mt != PQ_MSG_DATA && mt != PQ_MSG_CLOSE) {
        free(payload);
        fprintf(stderr, "session_recv: unexpected msg_type 0x%02x\n", mt);
        return -1;
    }
    if (!pq_replay_check_and_update(&s->recv_window, seq)) {
        free(payload);
        fprintf(stderr, "replay detected: seq %llu\n", (unsigned long long)seq);
        return -1;
    }

    uint8_t aad[9]; build_aad(aad, mt, seq);
    uint8_t nonce[12]; build_nonce(nonce, s->salt_recv, seq);

    if (payload_len < 16) { free(payload); return -1; }
    size_t pt_len = payload_len - 16;
    if (pt_len > out_cap) { free(payload); return -1; }

    if (aead_open(s->k_recv, nonce, aad, sizeof aad, payload, payload_len, out) != 0) {
        free(payload);
        fprintf(stderr, "GCM auth failure on seq %llu\n", (unsigned long long)seq);
        return -1;
    }
    free(payload);
    *out_len = pt_len;
    return mt == PQ_MSG_CLOSE ? 1 : 0;
}
