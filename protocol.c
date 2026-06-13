#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

ssize_t send_all(int fd, const void *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, (const char *)buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}

/* 1 = odebrano len bajtow, 0 = peer zamknal przed pierwszym bajtem, -1 = blad */
static int recv_exact(int fd, void *buf, size_t len)
{
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, (char *)buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return got == 0 ? 0 : -1; /* EOF w srodku ramki = blad */
        got += (size_t)n;
    }
    return 1;
}

int tlv_send(int fd, uint16_t type, const void *payload, uint16_t length)
{
    struct tlv_hdr hdr = { htons(type), htons(length) };

    if (send_all(fd, &hdr, sizeof(hdr)) < 0)
        return -1;
    if (length > 0 && send_all(fd, payload, length) < 0)
        return -1;
    return 0;
}

int tlv_recv(int fd, uint16_t *type, void *payload, uint16_t *length)
{
    struct tlv_hdr hdr;
    int rc = recv_exact(fd, &hdr, sizeof(hdr));

    if (rc <= 0)
        return rc;

    uint16_t len = ntohs(hdr.length);
    if (len > TLV_MAX_PAYLOAD) {
        errno = EPROTO;
        return -1;
    }
    if (len > 0 && recv_exact(fd, payload, len) != 1)
        return -1;

    *type = ntohs(hdr.type);
    *length = len;
    return 1;
}

ssize_t conn_buf_fill(int fd, struct conn_buf *cb)
{
    if (cb->used == sizeof(cb->buf)) {
        errno = ENOBUFS;
        return -1;
    }

    ssize_t n = recv(fd, cb->buf + cb->used, sizeof(cb->buf) - cb->used, 0);
    if (n > 0)
        cb->used += (size_t)n;
    return n;
}

int tlv_extract(struct conn_buf *cb, uint16_t *type, void *payload, uint16_t *length)
{
    struct tlv_hdr hdr;

    if (cb->used < sizeof(hdr))
        return 0;
    memcpy(&hdr, cb->buf, sizeof(hdr));

    uint16_t len = ntohs(hdr.length);
    if (len > TLV_MAX_PAYLOAD) {
        errno = EPROTO;
        return -1;
    }

    size_t frame = sizeof(hdr) + len;
    if (cb->used < frame)
        return 0;

    memcpy(payload, cb->buf + sizeof(hdr), len);
    memmove(cb->buf, cb->buf + frame, cb->used - frame);
    cb->used -= frame;

    *type = ntohs(hdr.type);
    *length = len;
    return 1;
}
