#include "protocol.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* Laczy sie z balancerem po nazwie/adresie (DNS przez getaddrinfo). */
static int connect_balancer(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0)
        perror("connect");
    return fd;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s <host> <port> <service_type>\n", argv[0]);
        return EXIT_FAILURE;
    }
    uint16_t service_type = parse_u16(argv[3]);

    int fd = connect_balancer(argv[1], argv[2]);
    if (fd < 0)
        return EXIT_FAILURE;

    setvbuf(stdout, NULL, _IOLBF, 0); /* logi widoczne tez bez terminala */
    printf("connected to %s:%s, service=%u\n", argv[1], argv[2], service_type);

    char line[TLV_MAX_PAYLOAD - sizeof(uint16_t)];
    char payload[TLV_MAX_PAYLOAD];

    while (fgets(line, sizeof(line), stdin)) {
        size_t n = strcspn(line, "\n");
        uint16_t st = htons(service_type);

        memcpy(payload, &st, sizeof(st));
        memcpy(payload + sizeof(st), line, n);
        if (tlv_send(fd, MSG_REQ, payload, (uint16_t)(sizeof(st) + n)) < 0) {
            perror("send");
            break;
        }

        uint16_t type, len;
        if (tlv_recv(fd, &type, payload, &len) != 1) {
            fprintf(stderr, "balancer closed connection\n");
            break;
        }
        if (type == MSG_RESP) {
            printf("%.*s\n", (int)len, payload);
        } else if (type == MSG_ERROR) {
            uint16_t code = 0;
            if (len >= sizeof(code)) {
                memcpy(&code, payload, sizeof(code));
                code = ntohs(code);
            }
            fprintf(stderr, "balancer error %u (service %u)\n", code, service_type);
        } else {
            fprintf(stderr, "unexpected message type %u\n", type);
            break;
        }
    }

    close(fd);
    return EXIT_SUCCESS;
}
