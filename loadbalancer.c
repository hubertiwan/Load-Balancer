#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#define MAX_BACKENDS 32
#define MAX_EVENTS   64

struct backend {
    struct in_addr ip;
    uint16_t tcp_port;
    uint16_t sctp_port;
    uint16_t services[MAX_SERVICES];
    size_t   n_services;
    uint32_t load;       /* z ostatniego MSG_HEALTH_RESP  */
    int      fail_count; /* kolejne nieudane health-checki */
    bool     alive;
};

/* Wspoldzielony rejestr wezlow; mutex dojdzie wraz z watkiem
 * health-check - na razie modyfikuje go tylko watek glowny. */
static struct backend backends[MAX_BACKENDS];
static size_t backend_count;

/* Polaczenie klienckie w epoll; dla gniazd nasluchujacych uzywamy
 * statycznych instancji rozpoznawanych po adresie (data.ptr). */
struct conn {
    int fd;
    struct conn_buf cb;
};

static struct conn mcast_conn, listen_conn;

static void die(const char *msg)
{
    syslog(LOG_ERR, "%s: %s", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

static int mcast_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(MCAST_PORT),
    };
    struct ip_mreq mreq = { .imr_interface.s_addr = htonl(INADDR_ANY) };

    if (inet_pton(AF_INET, MCAST_GROUP, &mreq.imr_multiaddr) != 1 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tcp_listen_socket(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, SOMAXCONN) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void handle_announce(int fd)
{
    char buf[sizeof(struct tlv_hdr) + TLV_MAX_PAYLOAD];
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);

    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                         (struct sockaddr *)&src, &slen);
    if (n < (ssize_t)sizeof(struct tlv_hdr))
        return;

    struct tlv_hdr hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    uint16_t len = ntohs(hdr.length);

    if (ntohs(hdr.type) != MSG_ANNOUNCE ||
        (size_t)n != sizeof(hdr) + len ||
        len < sizeof(struct msg_announce) ||
        (len - sizeof(struct msg_announce)) % sizeof(uint16_t) != 0)
        return;

    size_t n_services = (len - sizeof(struct msg_announce)) / sizeof(uint16_t);
    if (n_services == 0 || n_services > MAX_SERVICES)
        return;

    const struct msg_announce *ann = (const void *)(buf + sizeof(hdr));
    uint16_t tcp_port = ntohs(ann->tcp_port);

    for (size_t i = 0; i < backend_count; i++) {
        struct backend *b = &backends[i];
        if (b->ip.s_addr == src.sin_addr.s_addr && b->tcp_port == tcp_port) {
            b->alive = true; /* znany wezel: announce jako keep-alive */
            return;
        }
    }

    if (backend_count == MAX_BACKENDS) {
        syslog(LOG_WARNING, "backend pool full, ignoring %s:%u",
               inet_ntoa(src.sin_addr), tcp_port);
        return;
    }

    struct backend *b = &backends[backend_count++];
    *b = (struct backend){
        .ip = src.sin_addr,
        .tcp_port = tcp_port,
        .sctp_port = ntohs(ann->sctp_port),
        .n_services = n_services,
        .alive = true,
    };

    char svc[MAX_SERVICES * 7];
    size_t off = 0;
    for (size_t i = 0; i < n_services; i++) {
        b->services[i] = ntohs(ann->services[i]);
        off += (size_t)snprintf(svc + off, sizeof(svc) - off, "%s%u",
                                i ? "," : "", b->services[i]);
    }
    syslog(LOG_INFO, "node joined: %s tcp=%u sctp=%u services=%s",
           inet_ntoa(src.sin_addr), tcp_port, b->sctp_port, svc);
}

static void accept_client(int epfd, int listen_fd)
{
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0)
        return;

    struct conn *c = calloc(1, sizeof(*c));
    if (!c) {
        close(fd);
        return;
    }
    c->fd = fd;

    fcntl(fd, F_SETFL, O_NONBLOCK);
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = c };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        free(c);
    }
}

static void drop_client(int epfd, struct conn *c)
{
    epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    free(c);
}

/* Placeholder routingu - wybor zywego backendu o najmniejszym
 * load, ktorego services[] zawiera service_type; nawiazanie polaczenia
 * TCP i zalozenie sticky sesji klient<->backend. Do czasu implementacji
 * kazde zadanie konczy sie MSG_ERROR. */
static struct backend *route_request(uint16_t service_type)
{
    (void)service_type;
    return NULL;
}

static void handle_client(int epfd, struct conn *c)
{
    ssize_t n = conn_buf_fill(c->fd, &c->cb);
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        drop_client(epfd, c);
        return;
    }

    uint16_t type, len;
    char payload[TLV_MAX_PAYLOAD];
    int rc;

    while ((rc = tlv_extract(&c->cb, &type, payload, &len)) == 1) {
        if (type != MSG_REQ || len < sizeof(uint16_t)) {
            drop_client(epfd, c);
            return;
        }

        uint16_t service_type;
        memcpy(&service_type, payload, sizeof(service_type));
        service_type = ntohs(service_type);

        struct backend *b = route_request(service_type);
        if (!b) {
            uint16_t err = htons(ERR_NO_BACKEND);
            syslog(LOG_WARNING, "no backend for service %u", service_type);
            if (tlv_send(c->fd, MSG_ERROR, &err, sizeof(err)) < 0) {
                drop_client(epfd, c);
                return;
            }
            continue;
        }
        /* TODO: forward MSG_REQ do backendu, MSG_RESP z powrotem */
    }
    if (rc < 0)
        drop_client(epfd, c);
}

int main(void)
{
    openlog("loadbalancer", LOG_PID | LOG_PERROR, LOG_DAEMON);

    mcast_conn.fd = mcast_socket();
    if (mcast_conn.fd < 0)
        die("multicast socket");
    listen_conn.fd = tcp_listen_socket(BALANCER_PORT);
    if (listen_conn.fd < 0)
        die("tcp listen");

    int epfd = epoll_create1(0);
    if (epfd < 0)
        die("epoll_create1");

    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &mcast_conn };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, mcast_conn.fd, &ev) < 0)
        die("epoll_ctl mcast");
    ev.data.ptr = &listen_conn;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_conn.fd, &ev) < 0)
        die("epoll_ctl listen");

    syslog(LOG_INFO, "started: mcast %s:%u, tcp :%u",
           MCAST_GROUP, MCAST_PORT, BALANCER_PORT);

    for (;;) {
        struct epoll_event events[MAX_EVENTS];
        int n = epoll_wait(epfd, events, MAX_EVENTS, -1);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("epoll_wait");
        }
        for (int i = 0; i < n; i++) {
            struct conn *c = events[i].data.ptr;
            if (c == &mcast_conn)
                handle_announce(c->fd);
            else if (c == &listen_conn)
                accept_client(epfd, c->fd);
            else
                handle_client(epfd, c);
        }
    }
}
