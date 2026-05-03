/* Alice — initiator. */

#include "crypto_backend.h"
#include "net.h"
#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --backend A|B --host HOST --port PORT [--message MSG] [--repeat N]\n"
        "       %s --version\n",
        prog, prog);
}

int main(int argc, char **argv) {
    const char *backend_name = "A";
    const char *host = "127.0.0.1";
    int port = 5555;
    const char *message = "hello from alice";
    int repeat = 3;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("alice (pq-secure-comm) 0.1\n");
            return 0;
        } else if (!strcmp(argv[i], "--backend") && i + 1 < argc) {
            backend_name = argv[++i];
        } else if (!strcmp(argv[i], "--host") && i + 1 < argc) {
            host = argv[++i];
        } else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--message") && i + 1 < argc) {
            message = argv[++i];
        } else if (!strcmp(argv[i], "--repeat") && i + 1 < argc) {
            repeat = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    const pq_backend_t *bk = pq_backend_by_name(backend_name);
    if (!bk) { fprintf(stderr, "unknown backend: %s\n", backend_name); return 2; }
    fprintf(stderr, "alice: backend=%s (%s + %s)\n", bk->name, bk->kem_name, bk->sig_name);

    int sock = pq_tcp_connect(host, (uint16_t)port);
    if (sock < 0) return 1;

    pq_session_t s;
    if (pq_session_init(&s, bk, PQ_ROLE_INITIATOR) != 0) {
        fprintf(stderr, "session_init failed\n"); close(sock); return 1;
    }
    if (pq_session_handshake_initiator(&s, sock) != 0) {
        fprintf(stderr, "handshake failed\n"); pq_session_free(&s); close(sock); return 1;
    }
    fprintf(stderr, "alice: handshake OK (handshake_bytes=%llu)\n",
            (unsigned long long)s.handshake_bytes);

    for (int i = 0; i < repeat; i++) {
        char buf[512];
        snprintf(buf, sizeof buf, "%s [#%d]", message, i + 1);
        if (pq_session_send(&s, sock, (const uint8_t *)buf, strlen(buf)) != 0) {
            fprintf(stderr, "send failed\n"); break;
        }
        fprintf(stderr, "alice -> bob: %s\n", buf);

        uint8_t reply[1024]; size_t reply_len = 0;
        int r = pq_session_recv(&s, sock, reply, sizeof reply, &reply_len);
        if (r < 0) { fprintf(stderr, "recv failed\n"); break; }
        if (r == 1) { fprintf(stderr, "alice: peer closed\n"); break; }
        fwrite("alice <- bob: ", 1, 14, stderr);
        fwrite(reply, 1, reply_len, stderr);
        fputc('\n', stderr);
    }

    pq_session_close(&s, sock);
    pq_session_free(&s);
    close(sock);
    return 0;
}
