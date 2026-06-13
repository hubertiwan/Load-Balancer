#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define MCAST_GROUP   "239.255.0.1"
#define MCAST_PORT    5500
#define BALANCER_PORT 8080

#define ANNOUNCE_INTERVAL_S    10
#define HEALTHCHECK_INTERVAL_S 5
#define HEALTHCHECK_TIMEOUT_S  2
#define MAX_HEALTH_FAILS       3

#define TLV_MAX_PAYLOAD 4096
#define MAX_SERVICES    8

enum msg_type {
    MSG_ANNOUNCE    = 1, /* backend -> multicast UDP */
    MSG_HEALTH_REQ  = 2, /* balancer -> backend (SCTP) */
    MSG_HEALTH_RESP = 3, /* backend -> balancer (SCTP) */
    MSG_REQ         = 4, /* klient -> balancer -> backend (TCP) */
    MSG_RESP        = 5, /* backend -> balancer -> klient (TCP) */
    MSG_ERROR       = 6, /* balancer -> klient */
};

#define HEALTH_OK      0
#define ERR_NO_BACKEND 1


struct tlv_hdr {
    uint16_t type;
    uint16_t length; /* liczba bajtow payloadu */
} __attribute__((packed));

struct msg_announce {
    uint16_t tcp_port;
    uint16_t sctp_port;
    uint16_t services[]; // lista uslug; 
} __attribute__((packed));

struct msg_health_resp {
    uint8_t  status;
    uint32_t active_sessions;
} __attribute__((packed));

/* MSG_REQ payload: uint16_t service_type + dane; MSG_RESP payload: dane.
 * MSG_HEALTH_REQ i MSG_ANNOUNCE bez dodatkowych pol poza ladunkiem TLV. */

/* Bufor odbiorczy dla nieblokujacego gniazda TCP: ramki TLV moga przyjsc
 * we fragmentach albo po kilka w jednym recv(). */
struct conn_buf {
    char   buf[sizeof(struct tlv_hdr) + TLV_MAX_PAYLOAD];
    size_t used;
};

ssize_t send_all(int fd, const void *buf, size_t len);

/* Wysyla pelna ramke TLV. Zwraca 0, przy bledzie -1. */
int tlv_send(int fd, uint16_t type, const void *payload, uint16_t length);

/* Blokujaco odbiera pelna ramke: 1 = ramka, 0 = peer zamknal, -1 = blad.
 * payload musi miec TLV_MAX_PAYLOAD bajtow. */
int tlv_recv(int fd, uint16_t *type, void *payload, uint16_t *length);

/* Dolewa dane z gniazda do bufora; zwraca wynik recv(). */
ssize_t conn_buf_fill(int fd, struct conn_buf *cb);

/* Wyjmuje kompletna ramke z bufora: 1 = ramka, 0 = za malo danych,
 * -1 = blad protokolu. payload musi miec TLV_MAX_PAYLOAD bajtow. */
int tlv_extract(struct conn_buf *cb, uint16_t *type, void *payload, uint16_t *length);

#endif
