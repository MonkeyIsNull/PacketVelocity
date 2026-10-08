#ifndef PCV_HTTP_H
#define PCV_HTTP_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include "pcv_dashboard.h"

#ifdef __cplusplus
extern "C" {
#endif

/* PacketVelocity minimal, hermetic HTTP server for `--serve`.
 *
 * libc BSD sockets + pthread only (zero new dependencies). It mirrors the
 * loopback-only posture of the sibling netdebug Go dashboard (serve.go): the
 * bind is 127.0.0.1 EXCLUSIVELY, validated BOTH before and after bind, and
 * there is NO flag anywhere to expose it on a LAN - that code path does not
 * exist. A DNS-rebinding Host check and a zero-CORS response posture round out
 * the defenses.
 */

/* ---- Pure, testable predicates (exposed for the guard tests) ------------- */

/* Returns 0 iff ip is a LOOPBACK IP LITERAL: 127.0.0.0/8 (inet_pton AF_INET
 * with first octet 127) or ::1 (inet_pton AF_INET6 + IN6_IS_ADDR_LOOPBACK).
 * REJECTS 0.0.0.0, "::", any routable IP, and non-literals like "localhost" and
 * "127.0.0.1.evil.com" (inet_pton fails => reject). Analogue of netdebug's
 * validateBindAddr. Returns -1 on reject. */
int pcv_http_validate_bind_addr(const char* ip);

/* DNS-rebinding defense for the Host header. Strips any :port and accepts only
 * host in {127.0.0.1, localhost, ::1} (port-independent). NOTE the deliberate
 * asymmetry vs. validate_bind_addr: "localhost" is ACCEPTED here (Host header)
 * but REJECTED for binding. Returns 1 if allowed, 0 otherwise. */
int pcv_http_host_allowed(const char* host_header);

/* ---- Listener -----------------------------------------------------------
 * Bind a TCP socket to loopback ONLY (sin_addr = htonl(INADDR_LOOPBACK), never
 * INADDR_ANY). Validates the chosen IP PRE-bind, binds, then getsockname and
 * re-validates the ACTUAL bound address POST-bind (catching a wildcard mistake
 * at the socket, not just a unit test). Auto-advances the port on EADDRINUSE.
 * port == 0 lets the OS pick a free loopback port. On success writes the socket
 * fd to *out_fd, the dotted bound IP to bound_ip, and the bound port to
 * *out_port (if non-NULL); returns 0. Returns -1 on failure. */
int pcv_http_listen_local(uint16_t port, int* out_fd,
                          char* bound_ip, size_t bound_ip_len,
                          uint16_t* out_port);

/* ---- Server thread ------------------------------------------------------- */

/* Server state. Allocated by the caller (e.g. on main's stack) and initialized
 * with pcv_http_server_init before pthread_create(&tid, NULL, pcv_http_thread,
 * server). */
typedef struct pcv_http_server {
    int               listen_fd;   /* from pcv_http_listen_local */
    pcv_dash_agg*     agg;         /* snapshot source (read-only to the server) */
    _Atomic int       running;     /* cleared by pcv_http_stop */
    _Atomic int       conn_fd;     /* in-flight connection fd (-1 when idle) */
} pcv_http_server;

/* Initialize a server struct around an already-bound listen fd + aggregator. */
void pcv_http_server_init(pcv_http_server* s, int listen_fd, pcv_dash_agg* agg);

/* pthread entry point. arg is a pcv_http_server*. Runs the accept loop until
 * pcv_http_stop clears running (and breaks accept() via shutdown). Returns NULL.
 */
void* pcv_http_thread(void* arg);

/* Stop the server: clears running, and shutdown(2)+close the listen fd to break
 * a blocked accept(), AND shutdown() any tracked in-flight connection fd (a
 * blocked send() to a slow client - shutdown of the listen fd does NOT interrupt
 * an in-flight send on an accepted fd). Idempotent. Call BEFORE pthread_join. */
void pcv_http_stop(pcv_http_server* s);

#ifdef __cplusplus
}
#endif

#endif /* PCV_HTTP_H */
