#include "protocol.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

void pq_store_be32(uint8_t *out, uint32_t v) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

void pq_store_be64(uint8_t *out, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(v >> (56 - 8 * i));
    }
}

uint32_t pq_load_be32(const uint8_t *in) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  |  (uint32_t)in[3];
}

uint64_t pq_load_be64(const uint8_t *in) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | in[i];
    }
    return v;
}

void pq_replay_init(pq_replay_window_t *w) {
    w->highest = 0;
    w->bitmap = 0;
    w->initialized = false;
}

bool pq_replay_check_and_update(pq_replay_window_t *w, uint64_t seq) {
    /* First-ever packet seeds the window. */
    if (!w->initialized) {
        w->initialized = true;
        w->highest = seq;
        w->bitmap = 1ULL;  /* mark current */
        return true;
    }

    if (seq > w->highest) {
        uint64_t shift = seq - w->highest;
        if (shift >= 64) {
            w->bitmap = 1ULL;
        } else {
            w->bitmap = (w->bitmap << shift) | 1ULL;
        }
        w->highest = seq;
        return true;
    }

    uint64_t diff = w->highest - seq;
    if (diff >= 64) {
        return false;  /* too old */
    }
    uint64_t mask = 1ULL << diff;
    if (w->bitmap & mask) {
        return false;  /* duplicate */
    }
    w->bitmap |= mask;
    return true;
}

/* read exactly n bytes, retry on partial reads. */
static int read_full(int sock, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(sock, p + got, n - got, 0);
        if (r == 0) return -1;          /* peer closed */
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int sock, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(sock, p + sent, n - sent, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

int pq_write_frame(int sock, uint8_t msg_type, uint64_t seq,
                   const uint8_t *payload, size_t payload_len) {
    if (payload_len > PQ_MAX_PAYLOAD_LEN) return -1;

    /* length covers msg_type + seq + payload */
    uint32_t length = (uint32_t)(1 + 8 + payload_len);
    uint8_t header[PQ_FRAME_HEADER_LEN];
    pq_store_be32(header, length);
    header[4] = msg_type;
    pq_store_be64(header + 5, seq);

    if (write_full(sock, header, sizeof header) < 0) return -1;
    if (payload_len > 0 && write_full(sock, payload, payload_len) < 0) return -1;
    return 0;
}

int pq_read_frame(int sock, uint8_t *msg_type, uint64_t *seq,
                  uint8_t **payload, size_t *payload_len) {
    uint8_t header[PQ_FRAME_HEADER_LEN];
    if (read_full(sock, header, sizeof header) < 0) return -1;

    uint32_t length = pq_load_be32(header);
    if (length < 9) return -1;                                 /* must include type+seq */
    if (length - 9 > PQ_MAX_PAYLOAD_LEN) return -1;

    *msg_type = header[4];
    *seq = pq_load_be64(header + 5);
    *payload_len = length - 9;

    if (*payload_len == 0) {
        *payload = NULL;
        return 0;
    }
    *payload = (uint8_t *)malloc(*payload_len);
    if (!*payload) return -1;
    if (read_full(sock, *payload, *payload_len) < 0) {
        free(*payload);
        *payload = NULL;
        return -1;
    }
    return 0;
}
