#ifndef PQ_NET_H
#define PQ_NET_H

#include <stdint.h>

int pq_tcp_listen(const char *bind_host, uint16_t port);
int pq_tcp_accept(int listen_sock);
int pq_tcp_connect(const char *host, uint16_t port);

#endif
