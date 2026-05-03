/* Bob — responder. */

#include "crypto_backend.h"
#include "net.h"
#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --backend A|B --port PORT\n"
        "       %s --version\n", prog, prog);
}

int main(int argc, char **argv) {
    const char *backend_name = "A";
    int port = 5555;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--version")) {
            printf("bob (pq-secure-comm) 0.1\n");
            return 0;
        } else if (!strcmp(argv[i], "--backend") && i + 1 < argc) {
            backend_name = argv[++i];
        } else if (!strcmp(argv[i], "--port") && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else {
            usage(argv[0]);
            return 2;
        }
    }

    const pq_backend_t *bk = pq_backend_by_name(backend_name);
    if (!bk) { fprintf(stderr, "unknown backend: %s\n", backend_name); return 2; }
    fprintf(stderr, "bob: backend=%s (%s + %s)\n", bk->name, bk->kem_name, bk->sig_name);

    int lsock = pq_tcp_listen("0.0.0.0", (uint16_t)port);
    if (lsock < 0) return 1;
    fprintf(stderr, "bob: listening on :%d\n", port);

    int csock = pq_tcp_accept(lsock);
    close(lsock);
    if (csock < 0) return 1;
    fprintf(stderr, "bob: accepted connection\n");

    pq_session_t s;
    if (pq_session_init(&s, bk, PQ_ROLE_RESPONDER) != 0) {
        fprintf(stderr, "session_init failed\n"); close(csock); return 1;
    }
    if (pq_session_handshake_responder(&s, csock) != 0) {
        fprintf(stderr, "handshake failed\n"); pq_session_free(&s); close(csock); return 1;
    }
    fprintf(stderr, "bob: handshake OK\n");

    for (;;) {
        uint8_t buf[1024]; size_t n = 0;
        int r = pq_session_recv(&s, csock, buf, sizeof buf, &n);
        if (r < 0) {
            fprintf(stderr, "bob: recv error, terminating\n");
            pq_session_free(&s); close(csock); return 1;
        }
        if (r == 1) {
            fprintf(stderr, "bob: CLOSE received, exiting cleanly\n");
            break;
        }
        fwrite("bob <- alice: ", 1, 14, stderr);
        fwrite(buf, 1, n, stderr); fputc('\n', stderr);

        char reply[1024];
        int rlen = snprintf(reply, sizeof reply, "ack: %.*s", (int)n, buf);
        if (pq_session_send(&s, csock, (const uint8_t *)reply, (size_t)rlen) != 0) {
            fprintf(stderr, "bob: send error\n"); break;
        }
    }

    pq_session_free(&s);
    close(csock);
    return 0;
}
