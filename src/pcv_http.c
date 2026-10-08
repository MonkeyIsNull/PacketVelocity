/* PacketVelocity minimal hermetic HTTP server for `--serve`.
 *
 * libc BSD sockets + pthread only. See include/pcv_http.h for the contract.
 * THE invariant - loopback-only bind - is ENFORCED, not asserted: the bind is
 * pinned to INADDR_LOOPBACK, validated pre-bind on the candidate and post-bind
 * on the real getsockname() address, and no routine anywhere accepts a bind
 * address from the caller, so a LAN-exposure path does not exist.
 */

#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include "pcv_http.h"
#include "pcv_dashboard.h"
#include "pcv_dashboard_html.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Bounded request buffer (request line + headers). */
#define PCV_HTTP_REQ_MAX   8192
/* Per-connection socket timeouts (seconds). */
#define PCV_HTTP_RCV_TIMEO 5
#define PCV_HTTP_SND_TIMEO 5
/* Response body buffer for /stats.json. */
#define PCV_HTTP_JSON_MAX  (256 * 1024)
/* How many ports to try when auto-advancing past EADDRINUSE. */
#define PCV_HTTP_MAX_PORT_TRIES 64

/* ---- Pure predicates ----------------------------------------------------- */

int pcv_http_validate_bind_addr(const char* ip) {
    if (!ip || ip[0] == '\0') {
        return -1;
    }
    struct in_addr v4;
    if (inet_pton(AF_INET, ip, &v4) == 1) {
        /* 127.0.0.0/8 only. s_addr is network byte order; first octet is the
         * low byte of the host-order value. */
        uint32_t host = ntohl(v4.s_addr);
        if (((host >> 24) & 0xFFu) == 127u) {
            return 0;
        }
        return -1;
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        if (IN6_IS_ADDR_LOOPBACK(&v6)) {
            return 0;
        }
        return -1;
    }
    /* Not an IP literal (e.g. "localhost", "127.0.0.1.evil.com") => reject. */
    return -1;
}

int pcv_http_host_allowed(const char* host_header) {
    if (!host_header) {
        return 0;
    }

    char host[256];
    size_t hlen = strlen(host_header);
    if (hlen >= sizeof(host)) {
        return 0;
    }
    memcpy(host, host_header, hlen + 1);

    /* Strip a trailing :port. Handle a bracketed IPv6 literal "[::1]:port". */
    if (host[0] == '[') {
        char* rb = strchr(host, ']');
        if (!rb) {
            return 0;
        }
        /* host literal is between '[' and ']' */
        size_t inner = (size_t)(rb - (host + 1));
        memmove(host, host + 1, inner);
        host[inner] = '\0';
    } else {
        /* A single ':' separates host:port; an IPv6 literal without brackets
         * has multiple ':' and no port, so only strip when exactly one ':'. */
        char* first = strchr(host, ':');
        if (first && strchr(first + 1, ':') == NULL) {
            *first = '\0';
        }
    }

    if (strcmp(host, "127.0.0.1") == 0 ||
        strcmp(host, "localhost") == 0 ||
        strcmp(host, "::1") == 0) {
        return 1;
    }
    return 0;
}

/* ---- Listener ------------------------------------------------------------ */

int pcv_http_listen_local(uint16_t port, int* out_fd,
                          char* bound_ip, size_t bound_ip_len,
                          uint16_t* out_port) {
    if (!out_fd) {
        return -1;
    }

    int tries = (port == 0) ? 1 : PCV_HTTP_MAX_PORT_TRIES;
    for (int i = 0; i < tries; i++) {
        uint16_t p = (uint16_t)(port + i);

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return -1;
        }

        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(p);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 ONLY */

        /* PRE-bind validation on the candidate IP. */
        char cand[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, cand, sizeof(cand));
        if (pcv_http_validate_bind_addr(cand) != 0) {
            close(fd);
            return -1;
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            int e = errno;
            close(fd);
            if (e == EADDRINUSE && port != 0) {
                continue; /* advance to the next port */
            }
            return -1;
        }

        /* POST-bind re-check on the ACTUAL bound address. */
        struct sockaddr_in bound;
        socklen_t blen = sizeof(bound);
        if (getsockname(fd, (struct sockaddr*)&bound, &blen) < 0) {
            close(fd);
            return -1;
        }
        char bip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &bound.sin_addr, bip, sizeof(bip));
        if (pcv_http_validate_bind_addr(bip) != 0 ||
            bound.sin_addr.s_addr == htonl(INADDR_ANY)) {
            close(fd);
            return -1;
        }

        if (listen(fd, 16) < 0) {
            close(fd);
            return -1;
        }

        *out_fd = fd;
        if (bound_ip && bound_ip_len > 0) {
            strncpy(bound_ip, bip, bound_ip_len - 1);
            bound_ip[bound_ip_len - 1] = '\0';
        }
        if (out_port) {
            *out_port = ntohs(bound.sin_port);
        }
        return 0;
    }
    return -1;
}

/* ---- Response helpers ---------------------------------------------------- */

static void send_all(int fd, const char* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) {
            /* A slow/dead client (send timeout) or reset: give up on this
             * connection; never spin. */
            return;
        }
        sent += (size_t)n;
    }
}

/* Emit a complete, buffered response. content_type is pinned; NO CORS header is
 * ever added; Cache-Control: no-store on every route. */
static void send_response(int fd, const char* status, const char* content_type,
                          const char* body, size_t body_len) {
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.1 %s\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Cache-Control: no-store\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, content_type, body_len);
    if (n < 0) {
        return;
    }
    send_all(fd, hdr, (size_t)n);
    if (body_len > 0 && body) {
        send_all(fd, body, body_len);
    }
}

static void send_simple(int fd, const char* status, const char* content_type,
                        const char* body) {
    send_response(fd, status, content_type, body, body ? strlen(body) : 0);
}

/* ---- Request handling ---------------------------------------------------- */

/* Parse "GET <path> HTTP/1.x" from the first line; copy method and path into
 * caller buffers. Returns 0 on success, -1 on a malformed line. */
static int parse_request_line(const char* line, char* method, size_t mlen,
                              char* path, size_t plen) {
    const char* sp1 = strchr(line, ' ');
    if (!sp1) {
        return -1;
    }
    size_t ml = (size_t)(sp1 - line);
    if (ml == 0 || ml >= mlen) {
        return -1;
    }
    memcpy(method, line, ml);
    method[ml] = '\0';

    const char* path_start = sp1 + 1;
    const char* sp2 = strchr(path_start, ' ');
    if (!sp2) {
        return -1;
    }
    size_t pl = (size_t)(sp2 - path_start);
    if (pl == 0 || pl >= plen) {
        return -1;
    }
    memcpy(path, path_start, pl);
    path[pl] = '\0';
    return 0;
}

/* Extract the Host header value (case-insensitive) into out. Returns 1 if found.
 * headers points at the start of the header block (after the request line). */
static int find_host_header(const char* headers, char* out, size_t out_len) {
    const char* p = headers;
    while (p && *p) {
        /* One header line at a time. */
        const char* eol = strstr(p, "\r\n");
        size_t line_len = eol ? (size_t)(eol - p) : strlen(p);
        if (line_len == 0) {
            break; /* end of headers */
        }
        if (line_len > 5 && strncasecmp(p, "Host:", 5) == 0) {
            const char* v = p + 5;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            size_t vlen = line_len - (size_t)(v - p);
            if (vlen >= out_len) {
                vlen = out_len - 1;
            }
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return 1;
        }
        if (!eol) {
            break;
        }
        p = eol + 2;
    }
    return 0;
}

static void handle_connection(pcv_http_server* s, int cfd) {
    /* Bounded read of the request line + headers. */
    char req[PCV_HTTP_REQ_MAX];
    size_t total = 0;
    int have_headers = 0;
    while (total < sizeof(req) - 1) {
        ssize_t n = recv(cfd, req + total, sizeof(req) - 1 - total, 0);
        if (n <= 0) {
            break; /* client closed, timed out, or error */
        }
        total += (size_t)n;
        req[total] = '\0';
        if (strstr(req, "\r\n\r\n") != NULL) {
            have_headers = 1;
            break;
        }
    }
    if (!have_headers) {
        send_simple(cfd, "400 Bad Request", "text/plain; charset=utf-8",
                    "bad request\n");
        return;
    }

    char method[16];
    char path[1024];
    if (parse_request_line(req, method, sizeof(method), path, sizeof(path)) != 0) {
        send_simple(cfd, "400 Bad Request", "text/plain; charset=utf-8",
                    "bad request\n");
        return;
    }

    /* DNS-rebinding defense: check Host before routing. */
    const char* hdr_start = strstr(req, "\r\n");
    char host[256] = {0};
    int have_host = hdr_start ? find_host_header(hdr_start + 2, host, sizeof(host)) : 0;
    if (!have_host || !pcv_http_host_allowed(host)) {
        send_simple(cfd, "403 Forbidden", "text/plain; charset=utf-8",
                    "forbidden host\n");
        return;
    }

    /* Only GET is served. */
    if (strcmp(method, "GET") != 0) {
        send_simple(cfd, "405 Method Not Allowed", "text/plain; charset=utf-8",
                    "method not allowed\n");
        return;
    }

    /* Strip any query string for exact-match routing. */
    char* q = strchr(path, '?');
    if (q) {
        *q = '\0';
    }

    /* Exact-match routes (not prefix: "/" must be exactly "/"). */
    if (strcmp(path, "/") == 0) {
        send_response(cfd, "200 OK", "text/html; charset=utf-8",
                      PCV_DASHBOARD_HTML, strlen(PCV_DASHBOARD_HTML));
        return;
    }
    if (strcmp(path, "/stats.json") == 0) {
        char* body = malloc(PCV_HTTP_JSON_MAX);
        if (!body) {
            send_simple(cfd, "500 Internal Server Error",
                        "text/plain; charset=utf-8", "oom\n");
            return;
        }
        size_t len = pcv_dash_snapshot_json(s->agg, body, PCV_HTTP_JSON_MAX);
        send_response(cfd, "200 OK", "application/json; charset=utf-8",
                      body, len);
        free(body);
        return;
    }
    if (strcmp(path, "/healthz") == 0) {
        send_simple(cfd, "200 OK", "text/plain; charset=utf-8", "ok");
        return;
    }
    if (strcmp(path, "/favicon.ico") == 0) {
        /* 204 suppresses the per-load favicon 404. */
        send_response(cfd, "204 No Content", "text/plain; charset=utf-8", "", 0);
        return;
    }

    send_simple(cfd, "404 Not Found", "text/plain; charset=utf-8",
                "not found\n");
}

/* ---- Server lifecycle ---------------------------------------------------- */

void pcv_http_server_init(pcv_http_server* s, int listen_fd, pcv_dash_agg* agg) {
    s->listen_fd = listen_fd;
    s->agg = agg;
    atomic_store(&s->running, 1);
    atomic_store(&s->conn_fd, -1);
}

void* pcv_http_thread(void* arg) {
    pcv_http_server* s = (pcv_http_server*)arg;

    while (atomic_load(&s->running)) {
        int cfd = accept(s->listen_fd, NULL, NULL);
        if (cfd < 0) {
            if (!atomic_load(&s->running)) {
                break; /* stop() broke accept() */
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        /* Per-connection timeouts: SO_RCVTIMEO guards slow-loris reads,
         * SO_SNDTIMEO guards a slow-reading client blocking the thread in
         * send() (shutdown of the listen fd does NOT interrupt that). */
        struct timeval rto = { PCV_HTTP_RCV_TIMEO, 0 };
        struct timeval sto = { PCV_HTTP_SND_TIMEO, 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &sto, sizeof(sto));

        atomic_store(&s->conn_fd, cfd);
        handle_connection(s, cfd);
        atomic_store(&s->conn_fd, -1);
        close(cfd);
    }
    return NULL;
}

void pcv_http_stop(pcv_http_server* s) {
    if (!s) {
        return;
    }
    atomic_store(&s->running, 0);

    /* Break a blocked accept(). */
    if (s->listen_fd >= 0) {
        shutdown(s->listen_fd, SHUT_RDWR);
        close(s->listen_fd);
        s->listen_fd = -1;
    }

    /* Break a blocked send() to a slow client on the in-flight connection. */
    int cfd = atomic_load(&s->conn_fd);
    if (cfd >= 0) {
        shutdown(cfd, SHUT_RDWR);
    }
}
