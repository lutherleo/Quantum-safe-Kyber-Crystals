#include "net.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

int pq_tcp_listen(const char *bind_host, uint16_t port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)port);

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(bind_host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { perror("socket"); freeaddrinfo(res); return -1; }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("bind"); close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

    if (listen(sock, 4) < 0) { perror("listen"); close(sock); return -1; }
    return sock;
}

int pq_tcp_accept(int listen_sock) {
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    int s = accept(listen_sock, (struct sockaddr *)&peer, &plen);
    if (s < 0) { perror("accept"); return -1; }
    return s;
}

int pq_tcp_connect(const char *host, uint16_t port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)port);

    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(rc));
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *r = res; r != NULL; r = r->ai_next) {
        sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, r->ai_addr, r->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) {
        fprintf(stderr, "connect to %s:%u failed: %s\n", host, port, strerror(errno));
    }
    return sock;
}
