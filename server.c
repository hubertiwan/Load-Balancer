#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_CONNS 64

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static uint16_t parse_u16(const char *s)
{
    char *end;
    long v = strtol(s, &end, 10);

    if (*end != '\0' || v < 1 || v > UINT16_MAX) {
        fprintf(stderr, "invalid value: %s\n", s);
        exit(EXIT_FAILURE);
    }
    return (uint16_t)v;
}

static time_t mono_sec(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static int listen_socket(int protocol, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, protocol);
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

static void send_announce(int fd, const struct sockaddr_in *group,
                          const struct msg_announce *ann, uint16_t ann_len)
{
    char pkt[sizeof(struct tlv_hdr) + sizeof(struct msg_announce) +
             MAX_SERVICES * sizeof(uint16_t)];
    struct tlv_hdr hdr = { htons(MSG_ANNOUNCE), htons(ann_len) };

    memcpy(pkt, &hdr, sizeof(hdr));
    memcpy(pkt + sizeof(hdr), ann, ann_len);

    if (sendto(fd, pkt, sizeof(hdr) + ann_len, 0,
               (const struct sockaddr *)group, sizeof(*group)) < 0)
        perror("sendto announce");
}

/* Health-check: jedna wymiana req/resp na polaczenie SCTP, potem zamkniecie. */
static void handle_health(int listen_fd, uint32_t active_sessions)
{
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0)
        return;

    struct timeval tv = { HEALTHCHECK_TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint16_t type, len;
    char payload[TLV_MAX_PAYLOAD];

    if (tlv_recv(fd, &type, payload, &len) == 1 && type == MSG_HEALTH_REQ) {
        struct msg_health_resp resp = { HEALTH_OK, htonl(active_sessions) };
        tlv_send(fd, MSG_HEALTH_RESP, &resp, sizeof(resp));
    }
    close(fd);
}

/* Usluga echo: MSG_RESP = dane z MSG_REQ bez prefiksu service_type. */
static int handle_request(int fd)
{
    uint16_t type, len;
    char payload[TLV_MAX_PAYLOAD];

    if (tlv_recv(fd, &type, payload, &len) != 1)
        return -1;
    if (type != MSG_REQ || len < sizeof(uint16_t))
        return -1;
    return tlv_send(fd, MSG_RESP, payload + sizeof(uint16_t),
                    len - sizeof(uint16_t));
}

int main(int argc, char **argv)
{
    if (argc < 4 || argc > 3 + MAX_SERVICES) {
        fprintf(stderr, "usage: %s <tcp_port> <sctp_port> <service>... (max %d uslug)\n",
                argv[0], MAX_SERVICES);
        return EXIT_FAILURE;
    }
    uint16_t tcp_port = parse_u16(argv[1]);
    uint16_t sctp_port = parse_u16(argv[2]);
    int n_services = argc - 3;

    int sctp_fd = listen_socket(IPPROTO_SCTP, sctp_port);
    if (sctp_fd < 0)
        die("sctp listen");
    int tcp_fd = listen_socket(0, tcp_port);
    if (tcp_fd < 0)
        die("tcp listen");
    int ann_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ann_fd < 0)
        die("udp socket");

    struct sockaddr_in group = {
        .sin_family = AF_INET,
        .sin_port = htons(MCAST_PORT),
    };
    if (inet_pton(AF_INET, MCAST_GROUP, &group.sin_addr) != 1)
        die("inet_pton");

    char ann_buf[sizeof(struct msg_announce) + MAX_SERVICES * sizeof(uint16_t)];
    struct msg_announce *ann = (struct msg_announce *)ann_buf;
    ann->tcp_port = htons(tcp_port);
    ann->sctp_port = htons(sctp_port);
    for (int i = 0; i < n_services; i++)
        ann->services[i] = htons(parse_u16(argv[3 + i]));
    uint16_t ann_len = (uint16_t)(sizeof(*ann) + n_services * sizeof(uint16_t));

    int conns[MAX_CONNS];
    int nconns = 0;
    time_t next_announce = 0;

    printf("server: tcp=%u sctp=%u services=", tcp_port, sctp_port);
    for (int i = 0; i < n_services; i++)
        printf("%s%u", i ? "," : "", ntohs(ann->services[i]));
    putchar('\n');

    for (;;) {
        time_t now = mono_sec();
        if (now >= next_announce) {
            send_announce(ann_fd, &group, ann, ann_len);
            next_announce = now + ANNOUNCE_INTERVAL_S;
        }

        struct pollfd pfds[2 + MAX_CONNS];
        pfds[0] = (struct pollfd){ sctp_fd, POLLIN, 0 };
        pfds[1] = (struct pollfd){ tcp_fd, POLLIN, 0 };
        for (int i = 0; i < nconns; i++)
            pfds[2 + i] = (struct pollfd){ conns[i], POLLIN, 0 };

        int rc = poll(pfds, (nfds_t)(2 + nconns),
                      (int)(next_announce - now) * 1000);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            die("poll");
        }

        if (pfds[0].revents & POLLIN)
            handle_health(sctp_fd, (uint32_t)nconns);

        if (pfds[1].revents & POLLIN) {
            int fd = accept(tcp_fd, NULL, NULL);
            if (fd >= 0) {
                if (nconns == MAX_CONNS)
                    close(fd);
                else
                    conns[nconns++] = fd;
            }
        }

        /* Od tylu: swap-remove nie psuje indeksow jeszcze nieobsluzonych. */
        for (int i = nconns - 1; i >= 0; i--) {
            if (!(pfds[2 + i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            if (handle_request(conns[i]) < 0) {
                close(conns[i]);
                conns[i] = conns[--nconns];
            }
        }
    }
}
