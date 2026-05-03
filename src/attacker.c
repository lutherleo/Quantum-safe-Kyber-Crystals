/* MITM proxy: passthrough / flip / replay modes. Implemented in Step 7. */

#include "net.h"
#include "protocol.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

typedef enum { MODE_PASSTHROUGH, MODE_FLIP, MODE_REPLAY } mode_t_;

typedef struct {
    int from_fd;
    int to_fd;
    mode_t_ mode;
    int target_frame;       /* 1-indexed DATA frame to attack */
    int target_byte;        /* byte offset within payload (FLIP) */
    int *data_seen;         /* shared counter for DATA frames in this direction */
    pthread_mutex_t *lock;
    /* For replay mode: captured bytes (raw frame) to resend. */
    uint8_t *captured;
    size_t captured_len;
    int *replay_done;
    const char *tag;
} relay_ctx_t;

static int read_one_frame_raw(int fd, uint8_t **out, size_t *out_len,
                              uint8_t *msg_type, uint64_t *seq) {
    uint8_t *payload = NULL; size_t plen = 0;
    if (pq_read_frame(fd, msg_type, seq, &payload, &plen) != 0) return -1;
    *out_len = PQ_FRAME_HEADER_LEN + plen;
    *out = (uint8_t *)malloc(*out_len);
    if (!*out) { free(payload); return -1; }
    pq_store_be32(*out, (uint32_t)(1 + 8 + plen));
    (*out)[4] = *msg_type;
    pq_store_be64(*out + 5, *seq);
    if (plen > 0) memcpy(*out + PQ_FRAME_HEADER_LEN, payload, plen);
    free(payload);
    return 0;
}

static int write_full_buf(int fd, const uint8_t *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static void *relay_thread(void *arg) {
    relay_ctx_t *c = (relay_ctx_t *)arg;
    for (;;) {
        uint8_t *frame = NULL; size_t frame_len = 0;
        uint8_t mt = 0; uint64_t seq = 0;
        if (read_one_frame_raw(c->from_fd, &frame, &frame_len, &mt, &seq) != 0) break;

        int data_idx = 0;
        if (mt == PQ_MSG_DATA) {
            pthread_mutex_lock(c->lock);
            *c->data_seen += 1;
            data_idx = *c->data_seen;
            pthread_mutex_unlock(c->lock);
        }

        /* FLIP: corrupt byte in target DATA frame's encrypted payload. */
        if (c->mode == MODE_FLIP && mt == PQ_MSG_DATA && data_idx == c->target_frame) {
            size_t plen = frame_len - PQ_FRAME_HEADER_LEN;
            int off = c->target_byte;
            if (off < 0 || (size_t)off >= plen) off = 0;
            frame[PQ_FRAME_HEADER_LEN + off] ^= 0x01;
            fprintf(stderr, "[attacker:%s] FLIPPED bit in DATA frame #%d (byte %d)\n",
                    c->tag, data_idx, off);
        }

        /* REPLAY: forward, then capture and resend duplicate. */
        int captured_now = 0;
        if (c->mode == MODE_REPLAY && mt == PQ_MSG_DATA && data_idx == c->target_frame) {
            c->captured = (uint8_t *)malloc(frame_len);
            if (c->captured) {
                memcpy(c->captured, frame, frame_len);
                c->captured_len = frame_len;
                captured_now = 1;
            }
        }

        if (write_full_buf(c->to_fd, frame, frame_len) != 0) { free(frame); break; }

        if (captured_now && c->captured_len > 0) {
            fprintf(stderr, "[attacker:%s] REPLAYING DATA frame #%d\n", c->tag, c->target_frame);
            (void)write_full_buf(c->to_fd, c->captured, c->captured_len);
            *c->replay_done = 1;
        }
        free(frame);
    }
    shutdown(c->to_fd, SHUT_WR);
    return NULL;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --mode passthrough|flip|replay --listen-port P --upstream-host H --upstream-port P2\n"
        "          [--target-frame N] [--target-byte B]\n", prog);
}

int main(int argc, char **argv) {
    const char *mode_s = "passthrough";
    int listen_port = 5555;
    const char *upstream_host = "bob";
    int upstream_port = 5556;
    int target_frame = 3, target_byte = 20;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) { printf("attacker 0.1\n"); return 0; }
        else if (!strcmp(argv[i], "--mode") && i+1<argc) mode_s = argv[++i];
        else if (!strcmp(argv[i], "--listen-port") && i+1<argc) listen_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--upstream-host") && i+1<argc) upstream_host = argv[++i];
        else if (!strcmp(argv[i], "--upstream-port") && i+1<argc) upstream_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--target-frame") && i+1<argc) target_frame = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--target-byte") && i+1<argc) target_byte = atoi(argv[++i]);
        else { usage(argv[0]); return 2; }
    }

    mode_t_ mode = MODE_PASSTHROUGH;
    if (!strcmp(mode_s, "flip")) mode = MODE_FLIP;
    else if (!strcmp(mode_s, "replay")) mode = MODE_REPLAY;

    fprintf(stderr, "[attacker] mode=%s listen=:%d upstream=%s:%d target=#%d\n",
            mode_s, listen_port, upstream_host, upstream_port, target_frame);

    int lsock = pq_tcp_listen("0.0.0.0", (uint16_t)listen_port);
    if (lsock < 0) return 1;
    int alice_fd = pq_tcp_accept(lsock);
    close(lsock);
    if (alice_fd < 0) return 1;

    int bob_fd = pq_tcp_connect(upstream_host, (uint16_t)upstream_port);
    if (bob_fd < 0) { close(alice_fd); return 1; }

    int data_a2b = 0, data_b2a = 0, replay_done = 0;
    pthread_mutex_t lock_a, lock_b;
    pthread_mutex_init(&lock_a, NULL);
    pthread_mutex_init(&lock_b, NULL);

    relay_ctx_t a2b = { alice_fd, bob_fd, mode, target_frame, target_byte,
                        &data_a2b, &lock_a, NULL, 0, &replay_done, "a->b" };
    relay_ctx_t b2a = { bob_fd, alice_fd, MODE_PASSTHROUGH, 0, 0,
                        &data_b2a, &lock_b, NULL, 0, &replay_done, "b->a" };

    pthread_t t1, t2;
    pthread_create(&t1, NULL, relay_thread, &a2b);
    pthread_create(&t2, NULL, relay_thread, &b2a);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    free(a2b.captured);
    close(alice_fd); close(bob_fd);
    return 0;
}
