#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

/* Wspoldzielony rejestr wezlow; chroniony mutexem, modyfikowany
 * przez watek glowny (announce) i watek health-check. */
static struct backend backends[MAX_BACKENDS];
static size_t backend_count;
static pthread_mutex_t backend_lock = PTHREAD_MUTEX_INITIALIZER;

/* Flaga zakonczenia ustawiana przez handler sygnalow. */
static volatile sig_atomic_t running = 1;

/* Polaczenie klienckie w epoll; dla gniazd nasluchujacych uzywamy
 * statycznych instancji rozpoznawanych po adresie (data.ptr). */
struct conn {
    int fd;
    struct conn_buf cb;
};

static struct conn mcast_conn, listen_conn;

/* ------------------------------------------------------------------ */
/*  Obsluga sygnalow                                                  */
/* ------------------------------------------------------------------ */

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        running = 0;
    /* SIGHUP: w przyszlosci mozna dodac przeladowanie konfiguracji */
}

static void setup_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* bez SA_RESTART - epoll_wait zwroci EINTR */

    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* SIGPIPE ignorowany - bledy wysylki obslugiwane przez errno */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* ------------------------------------------------------------------ */
/*  Tryb demona                                                       */
/* ------------------------------------------------------------------ */

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        _exit(EXIT_SUCCESS); /* rodzic konczy */

    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    /* Drugi fork zapobiega ponownemu przydzieleniu terminala. */
    pid = fork();
    if (pid < 0) {
        perror("fork2");
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        _exit(EXIT_SUCCESS);

    umask(0);
    if (chdir("/") < 0) {
        perror("chdir");
        exit(EXIT_FAILURE);
    }

    /* Przekierowanie stdio do /dev/null */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY); /* fd 0 */
    open("/dev/null", O_WRONLY); /* fd 1 */
    open("/dev/null", O_WRONLY); /* fd 2 */
}

/* ------------------------------------------------------------------ */
/*  Gniazda: multicast i TCP listener                                 */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Multicast announce                                                */
/* ------------------------------------------------------------------ */

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

    pthread_mutex_lock(&backend_lock);

    for (size_t i = 0; i < backend_count; i++) {
        struct backend *b = &backends[i];
        if (b->ip.s_addr == src.sin_addr.s_addr && b->tcp_port == tcp_port) {
            b->alive = true; /* znany wezel: announce jako keep-alive */
            pthread_mutex_unlock(&backend_lock);
            return;
        }
    }

    if (backend_count == MAX_BACKENDS) {
        pthread_mutex_unlock(&backend_lock);
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

    pthread_mutex_unlock(&backend_lock);

    syslog(LOG_INFO, "node joined: %s tcp=%u sctp=%u services=%s",
           inet_ntoa(src.sin_addr), tcp_port, b->sctp_port, svc);
}

/* ------------------------------------------------------------------ */
/*  Klienci: accept / drop / routing / forwarding                     */
/* ------------------------------------------------------------------ */

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

/* Wybor zywego backendu o najmniejszym load, ktorego services[]
 * zawiera service_type.  Zwraca wskaznik lub NULL. */
static struct backend *route_request(uint16_t service_type)
{
    struct backend *best = NULL;

    pthread_mutex_lock(&backend_lock);

    for (size_t i = 0; i < backend_count; i++) {
        struct backend *b = &backends[i];
        if (!b->alive)
            continue;

        bool has_svc = false;
        for (size_t j = 0; j < b->n_services; j++) {
            if (b->services[j] == service_type) {
                has_svc = true;
                break;
            }
        }
        if (!has_svc)
            continue;

        if (!best || b->load < best->load)
            best = b;
    }

    pthread_mutex_unlock(&backend_lock);
    return best;
}

/* Nawiazuje polaczenie TCP z backendem, przekazuje pelny payload
 * MSG_REQ (service_type + dane) i odbiera MSG_RESP.
 * Zwraca 0 przy sukcesie, -1 przy bledzie. */
static int forward_to_backend(struct backend *b,
                              const void *req_payload, uint16_t req_len,
                              void *resp_payload, uint16_t *resp_len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    struct timeval tv = { HEALTHCHECK_TIMEOUT_S, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr   = b->ip,
        .sin_port   = htons(b->tcp_port),
    };

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (tlv_send(fd, MSG_REQ, req_payload, req_len) < 0) {
        close(fd);
        return -1;
    }

    uint16_t type;
    int rc = tlv_recv(fd, &type, resp_payload, resp_len);
    close(fd);

    if (rc != 1 || type != MSG_RESP)
        return -1;
    return 0;
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

        syslog(LOG_DEBUG, "routing svc=%u -> %s:%u (load=%u)",
               service_type, inet_ntoa(b->ip), b->tcp_port, b->load);

        char resp[TLV_MAX_PAYLOAD];
        uint16_t resp_len;

        if (forward_to_backend(b, payload, len, resp, &resp_len) < 0) {
            syslog(LOG_WARNING, "forward failed for svc=%u -> %s:%u",
                   service_type, inet_ntoa(b->ip), b->tcp_port);
            uint16_t err = htons(ERR_NO_BACKEND);
            if (tlv_send(c->fd, MSG_ERROR, &err, sizeof(err)) < 0) {
                drop_client(epfd, c);
                return;
            }
            continue;
        }

        if (tlv_send(c->fd, MSG_RESP, resp, resp_len) < 0) {
            drop_client(epfd, c);
            return;
        }
    }
    if (rc < 0)
        drop_client(epfd, c);
}

/* ------------------------------------------------------------------ */
/*  Watek health-check (SCTP)                                         */
/* ------------------------------------------------------------------ */

static void *health_thread(void *arg)
{
    (void)arg;

    while (running) {
        sleep(HEALTHCHECK_INTERVAL_S);
        if (!running)
            break;

        /* Kopia potrzebnych danych pod lockiem, probe juz bez niego. */
        struct {
            struct in_addr ip;
            uint16_t sctp_port;
            size_t   idx;
        } targets[MAX_BACKENDS];
        size_t count;

        pthread_mutex_lock(&backend_lock);
        count = backend_count;
        for (size_t i = 0; i < count; i++) {
            targets[i].ip        = backends[i].ip;
            targets[i].sctp_port = backends[i].sctp_port;
            targets[i].idx       = i;
        }
        pthread_mutex_unlock(&backend_lock);

        for (size_t i = 0; i < count; i++) {
            int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
            if (fd < 0)
                continue;

            struct timeval tv = { HEALTHCHECK_TIMEOUT_S, 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

            struct sockaddr_in addr = {
                .sin_family = AF_INET,
                .sin_addr   = targets[i].ip,
                .sin_port   = htons(targets[i].sctp_port),
            };

            bool ok = false;

            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                if (tlv_send(fd, MSG_HEALTH_REQ, NULL, 0) == 0) {
                    uint16_t rtype, rlen;
                    char rpay[TLV_MAX_PAYLOAD];

                    if (tlv_recv(fd, &rtype, rpay, &rlen) == 1 &&
                        rtype == MSG_HEALTH_RESP &&
                        rlen >= sizeof(struct msg_health_resp)) {

                        struct msg_health_resp resp;
                        memcpy(&resp, rpay, sizeof(resp));

                        if (resp.status == HEALTH_OK) {
                            ok = true;
                            pthread_mutex_lock(&backend_lock);
                            size_t idx = targets[i].idx;
                            if (idx < backend_count) {
                                backends[idx].load = ntohl(resp.active_sessions);
                                backends[idx].fail_count = 0;
                                if (!backends[idx].alive) {
                                    backends[idx].alive = true;
                                    syslog(LOG_INFO, "node restored: %s:%u",
                                           inet_ntoa(backends[idx].ip),
                                           backends[idx].sctp_port);
                                }
                            }
                            pthread_mutex_unlock(&backend_lock);
                        }
                    }
                }
            }
            close(fd);

            if (!ok) {
                pthread_mutex_lock(&backend_lock);
                size_t idx = targets[i].idx;
                if (idx < backend_count) {
                    backends[idx].fail_count++;
                    if (backends[idx].fail_count >= MAX_HEALTH_FAILS &&
                        backends[idx].alive) {
                        backends[idx].alive = false;
                        syslog(LOG_WARNING, "node dead: %s:%u (fails=%d)",
                               inet_ntoa(backends[idx].ip),
                               backends[idx].sctp_port,
                               backends[idx].fail_count);
                    }
                }
                pthread_mutex_unlock(&backend_lock);
            }
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Graceful shutdown: zamykanie gniazd i polaczen klienckich         */
/* ------------------------------------------------------------------ */

static void cleanup(int epfd, int mcast_fd, int listen_fd)
{
    close(mcast_fd);
    close(listen_fd);
    close(epfd);
    syslog(LOG_INFO, "shutting down");
    closelog();
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    bool daemon_mode = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--daemon") == 0)
            daemon_mode = true;
        else {
            fprintf(stderr, "usage: %s [-d|--daemon]\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (daemon_mode)
        daemonize();

    openlog("loadbalancer", LOG_PID | (daemon_mode ? 0 : LOG_PERROR),
            LOG_DAEMON);
    setup_signals();

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

    /* Watek health-check */
    pthread_t hc_tid;
    if (pthread_create(&hc_tid, NULL, health_thread, NULL) != 0)
        die("pthread_create health");
    pthread_detach(hc_tid);

    syslog(LOG_INFO, "started: mcast %s:%u, tcp :%u%s",
           MCAST_GROUP, MCAST_PORT, BALANCER_PORT,
           daemon_mode ? " (daemon)" : "");

    while (running) {
        struct epoll_event events[MAX_EVENTS];
        int n = epoll_wait(epfd, events, MAX_EVENTS, 1000);

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

    cleanup(epfd, mcast_conn.fd, listen_conn.fd);
    return EXIT_SUCCESS;
}
