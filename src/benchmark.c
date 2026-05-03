/* Statistical perf harness — keygen / encaps / decaps / sign / verify / AEAD. */

#include "crypto_backend.h"
#include "protocol.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ITERS 1000

static double ts_diff_ns(struct timespec a, struct timespec b) {
    return (double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec);
}

static int cmp_d(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

typedef struct { double median, mean, stddev, p95, p99; } stats_t;

static stats_t summarize(double *xs, size_t n) {
    qsort(xs, n, sizeof(double), cmp_d);
    double s = 0;
    for (size_t i = 0; i < n; i++) s += xs[i];
    double mean = s / (double)n;
    double var = 0;
    for (size_t i = 0; i < n; i++) { double d = xs[i] - mean; var += d * d; }
    var /= (double)n;
    stats_t r = {
        .median = xs[n / 2],
        .mean = mean,
        .stddev = sqrt(var),
        .p95 = xs[(size_t)(0.95 * (double)n)],
        .p99 = xs[(size_t)(0.99 * (double)n)],
    };
    return r;
}

static void emit_raw(FILE *raw, const char *backend, const char *op,
                     int iter, double ns) {
    fprintf(raw, "%s,%s,%d,%.0f\n", backend, op, iter, ns);
}

static void emit_summary(FILE *sum, const char *backend, const char *op, stats_t s) {
    fprintf(sum, "%s,%s,%.0f,%.0f,%.0f,%.0f,%.0f\n",
            backend, op, s.median, s.mean, s.stddev, s.p95, s.p99);
}

static void emit_size(FILE *size_f, const char *backend, const char *kind, size_t bytes) {
    fprintf(size_f, "%s,%s,%zu\n", backend, kind, bytes);
}

/* AEAD round-trip on a 1 KiB payload (used to benchmark the symmetric leg). */
static int aead_roundtrip(const uint8_t *key, const uint8_t *pt, size_t pt_len, int do_open) {
    uint8_t nonce[12]; RAND_bytes(nonce, 12);
    uint8_t aad[9] = {0};
    uint8_t *ct = (uint8_t *)malloc(pt_len + 16);
    if (!ct) return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, total = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_EncryptUpdate(ctx, NULL, &len, aad, sizeof aad);
    EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len);
    total = len;
    EVP_EncryptFinal_ex(ctx, ct + total, &len);
    total += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct + total);
    EVP_CIPHER_CTX_free(ctx);

    if (do_open) {
        uint8_t *out = (uint8_t *)malloc(pt_len);
        ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
        EVP_DecryptUpdate(ctx, NULL, &len, aad, sizeof aad);
        EVP_DecryptUpdate(ctx, out, &len, ct, (int)pt_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ct + pt_len);
        EVP_DecryptFinal_ex(ctx, out + len, &len);
        EVP_CIPHER_CTX_free(ctx);
        free(out);
    }
    free(ct);
    return 0;
}

static void bench_backend(const pq_backend_t *bk, FILE *raw, FILE *sum, FILE *size_f) {
    fprintf(stderr, "==> benchmarking backend %s (%s + %s)\n", bk->name, bk->kem_name, bk->sig_name);

    uint8_t *kem_pk = malloc(bk->kem_pk_len), *kem_sk = malloc(bk->kem_sk_len);
    uint8_t *kem_ct = malloc(bk->kem_ct_len), *kem_ss = malloc(bk->kem_ss_len);
    uint8_t *sig_pk = malloc(bk->sig_pk_len), *sig_sk = malloc(bk->sig_sk_len);
    uint8_t *sig    = malloc(bk->sig_max_len);
    uint8_t msg[1024]; RAND_bytes(msg, sizeof msg);
    uint8_t aead_key[32]; RAND_bytes(aead_key, 32);

    double *xs = malloc(sizeof(double) * ITERS);
    struct timespec t0, t1;

    /* kem_keygen */
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->kem_keypair(kem_pk, kem_sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "kem_keygen", i, xs[i]);
    }
    emit_summary(sum, bk->name, "kem_keygen", summarize(xs, ITERS));

    /* kem_encaps / decaps */
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->kem_encaps(kem_ct, kem_ss, kem_pk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "kem_encaps", i, xs[i]);
    }
    emit_summary(sum, bk->name, "kem_encaps", summarize(xs, ITERS));

    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->kem_decaps(kem_ss, kem_ct, kem_sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "kem_decaps", i, xs[i]);
    }
    emit_summary(sum, bk->name, "kem_decaps", summarize(xs, ITERS));

    /* sig_keygen */
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->sig_keypair(sig_pk, sig_sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "sig_keygen", i, xs[i]);
    }
    emit_summary(sum, bk->name, "sig_keygen", summarize(xs, ITERS));

    /* sig_sign / verify (single fresh keypair to keep things simple) */
    bk->sig_keypair(sig_pk, sig_sk);
    size_t sig_len = bk->sig_max_len;
    for (int i = 0; i < ITERS; i++) {
        sig_len = bk->sig_max_len;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->sig_sign(sig, &sig_len, msg, sizeof msg, sig_sk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "sig_sign", i, xs[i]);
    }
    emit_summary(sum, bk->name, "sig_sign", summarize(xs, ITERS));

    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->sig_verify(sig, sig_len, msg, sizeof msg, sig_pk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "sig_verify", i, xs[i]);
    }
    emit_summary(sum, bk->name, "sig_verify", summarize(xs, ITERS));

    /* AEAD encrypt / decrypt 1 KiB */
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        aead_roundtrip(aead_key, msg, sizeof msg, 0);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "aead_encrypt_1k", i, xs[i]);
    }
    emit_summary(sum, bk->name, "aead_encrypt_1k", summarize(xs, ITERS));

    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        aead_roundtrip(aead_key, msg, sizeof msg, 1);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "aead_decrypt_1k", i, xs[i]);
    }
    emit_summary(sum, bk->name, "aead_decrypt_1k", summarize(xs, ITERS));

    /* synthetic "handshake": kem keygen + encaps + decaps + 2 signs + 2 verifies */
    for (int i = 0; i < ITERS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        bk->kem_keypair(kem_pk, kem_sk);
        bk->kem_encaps(kem_ct, kem_ss, kem_pk);
        bk->kem_decaps(kem_ss, kem_ct, kem_sk);
        sig_len = bk->sig_max_len; bk->sig_sign(sig, &sig_len, msg, 64, sig_sk);
        bk->sig_verify(sig, sig_len, msg, 64, sig_pk);
        sig_len = bk->sig_max_len; bk->sig_sign(sig, &sig_len, msg, 64, sig_sk);
        bk->sig_verify(sig, sig_len, msg, 64, sig_pk);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        xs[i] = ts_diff_ns(t0, t1);
        emit_raw(raw, bk->name, "handshake_synth", i, xs[i]);
    }
    emit_summary(sum, bk->name, "handshake_synth", summarize(xs, ITERS));

    /* artifact sizes */
    emit_size(size_f, bk->name, "kem_pk", bk->kem_pk_len);
    emit_size(size_f, bk->name, "kem_sk", bk->kem_sk_len);
    emit_size(size_f, bk->name, "kem_ct", bk->kem_ct_len);
    emit_size(size_f, bk->name, "sig_pk", bk->sig_pk_len);
    emit_size(size_f, bk->name, "sig_sk", bk->sig_sk_len);
    emit_size(size_f, bk->name, "sig_max", bk->sig_max_len);
    /* worst-case handshake bytes (initiator + responder traffic on the wire) */
    size_t hs_bytes =
        /* HELLO */     PQ_FRAME_HEADER_LEN + bk->sig_pk_len + 16 +
        /* HELLO_ACK */ PQ_FRAME_HEADER_LEN + bk->sig_pk_len + bk->kem_pk_len + 16 + bk->sig_max_len +
        /* KEM_CT */    PQ_FRAME_HEADER_LEN + bk->kem_ct_len + bk->sig_max_len;
    emit_size(size_f, bk->name, "handshake_total", hs_bytes);

    free(xs);
    free(kem_pk); free(kem_sk); free(kem_ct); free(kem_ss);
    free(sig_pk); free(sig_sk); free(sig);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    const char *out_dir = "/results";
    char raw_path[256], sum_path[256], size_path[256];
    snprintf(raw_path,  sizeof raw_path,  "%s/bench_raw.csv", out_dir);
    snprintf(sum_path,  sizeof sum_path,  "%s/bench_summary.csv", out_dir);
    snprintf(size_path, sizeof size_path, "%s/bench_sizes.csv", out_dir);

    FILE *raw = fopen(raw_path, "w");
    FILE *sum = fopen(sum_path, "w");
    FILE *sz  = fopen(size_path, "w");
    if (!raw || !sum || !sz) {
        fprintf(stderr, "could not open output CSVs in %s\n", out_dir);
        return 1;
    }
    fprintf(raw, "backend,operation,iteration,nanoseconds\n");
    fprintf(sum, "backend,operation,median_ns,mean_ns,stddev_ns,p95_ns,p99_ns\n");
    fprintf(sz,  "backend,artifact,bytes\n");

    bench_backend(&PQ_BACKEND_A, raw, sum, sz);
    bench_backend(&PQ_BACKEND_B, raw, sum, sz);

    fclose(raw); fclose(sum); fclose(sz);
    fprintf(stderr, "benchmark complete: results in %s\n", out_dir);
    return 0;
}
