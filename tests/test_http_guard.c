/* HTTP server guard tests (no root): the loopback-only bind posture and the
 * served-HTML no-external-URL guarantee, mirroring netdebug's
 * TestValidateBindAddr / TestListenLocal* / TestDashboardHTMLHasNoExternalURLs.
 */
#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include "pcv_http.h"
#include "pcv_dashboard.h"
#include "pcv_dashboard_html.h"
#include "pcv_test.h"

/* ---- 1. validate_bind_addr table ---------------------------------------- */

static void test_validate_bind_addr(void) {
    fprintf(stdout, "validate_bind_addr\n");
    struct { const char* ip; int want_ok; } cases[] = {
        {"127.0.0.1", 1}, {"127.0.0.2", 1}, {"127.1.2.3", 1}, {"::1", 1},
        {"0.0.0.0", 0}, {"::", 0},
        {"10.0.0.5", 0}, {"192.168.1.1", 0}, {"8.8.8.8", 0},
        {"localhost", 0}, {"127.0.0.1.evil.com", 0}, {"", 0}, {"notanip", 0},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int ok = (pcv_http_validate_bind_addr(cases[i].ip) == 0);
        char msg[128];
        snprintf(msg, sizeof(msg), "validate_bind_addr(%s) %s",
                 cases[i].ip, cases[i].want_ok ? "accepted" : "rejected");
        CHECK(ok == cases[i].want_ok, msg);
    }
}

/* ---- 2. host_allowed table (with the deliberate localhost asymmetry) ---- */

static void test_host_allowed(void) {
    fprintf(stdout, "host_allowed\n");
    struct { const char* host; int want_ok; } cases[] = {
        {"127.0.0.1", 1}, {"127.0.0.1:8080", 1},
        {"localhost", 1}, {"localhost:9999", 1},   /* accepted for Host header */
        {"::1", 1}, {"[::1]:8080", 1},
        {"evil.example", 0}, {"evil.example:80", 0},
        {"10.0.0.5", 0}, {"example.com", 0},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        int ok = pcv_http_host_allowed(cases[i].host);
        char msg[128];
        snprintf(msg, sizeof(msg), "host_allowed(%s) %s",
                 cases[i].host, cases[i].want_ok ? "allowed" : "denied");
        CHECK(ok == cases[i].want_ok, msg);
    }
    /* Asymmetry assertion: localhost is OK as a Host but NOT as a bind target. */
    CHECK(pcv_http_host_allowed("localhost") == 1 &&
          pcv_http_validate_bind_addr("localhost") != 0,
          "localhost: allowed as Host, rejected for binding");
}

/* ---- 3. listen_local(0) binds a concrete loopback address --------------- */

static int try_connect(const char* ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return 0; }

    int rc = connect(fd, (struct sockaddr*)&a, sizeof(a));
    if (rc == 0) { close(fd); return 1; }             /* immediate connect */
    if (errno != EINPROGRESS) { close(fd); return 0; } /* refused */

    fd_set ws;
    FD_ZERO(&ws);
    FD_SET(fd, &ws);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    rc = select(fd + 1, NULL, &ws, NULL, &tv);
    int connected = 0;
    if (rc > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        connected = (err == 0);
    }
    close(fd);
    return connected;
}

static void test_listen_local(uint16_t* out_port) {
    fprintf(stdout, "listen_local loopback-only\n");
    int fd = -1;
    char bip[64] = {0};
    uint16_t port = 0;
    int rc = pcv_http_listen_local(0, &fd, bip, sizeof(bip), &port);
    CHECK(rc == 0 && fd >= 0, "listen_local(0) binds a port");
    CHECK(port != 0, "a concrete port was chosen");
    CHECK(pcv_http_validate_bind_addr(bip) == 0, "bound IP is loopback");
    CHECK(strcmp(bip, "0.0.0.0") != 0, "bound IP is not the wildcard");

    /* Off-loopback dial: every non-loopback IPv4 interface must REFUSE the port. */
    struct ifaddrs* ifs = NULL;
    int tried = 0;
    if (getifaddrs(&ifs) == 0) {
        for (struct ifaddrs* ia = ifs; ia; ia = ia->ifa_next) {
            if (!ia->ifa_addr || ia->ifa_addr->sa_family != AF_INET) continue;
            struct sockaddr_in* sin = (struct sockaddr_in*)ia->ifa_addr;
            uint32_t h = ntohl(sin->sin_addr.s_addr);
            if (((h >> 24) & 0xFF) == 127) continue;           /* skip loopback */
            if ((h & 0xFFFF0000u) == 0xA9FE0000u) continue;    /* skip link-local */
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            tried++;
            char msg[128];
            snprintf(msg, sizeof(msg), "port refused on non-loopback %s", ip);
            CHECK(try_connect(ip, port, 300) == 0, msg);
        }
        freeifaddrs(ifs);
    }
    if (tried == 0) {
        fprintf(stdout, "  ok:   no non-loopback IPv4 IFs to probe (isolated host)\n");
    }

    /* Hand the live fd + port to the request-level test. */
    *out_port = port;
    /* leave fd open; caller's server adopts it */
    extern int g_shared_listen_fd;
    g_shared_listen_fd = fd;
}

int g_shared_listen_fd = -1;

/* ---- 4. request-level: no CORS on /stats.json, 403 on a bad Host -------- */

static int http_get(uint16_t port, const char* host, const char* path,
                    char* resp, size_t resp_size) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) { close(fd); return -1; }

    char req[512];
    int n = snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                     path, host);
    if (send(fd, req, (size_t)n, 0) != n) { close(fd); return -1; }

    size_t total = 0;
    while (total < resp_size - 1) {
        ssize_t r = recv(fd, resp + total, resp_size - 1 - total, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    resp[total] = '\0';
    close(fd);
    return (int)total;
}

static void lower_inplace(char* s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static void test_requests(uint16_t port, int listen_fd) {
    fprintf(stdout, "request-level posture\n");
    pcv_dash_agg* agg = pcv_dash_create(0, 0, 0);
    CHECK(agg != NULL, "create agg for server");

    pcv_http_server srv;
    pcv_http_server_init(&srv, listen_fd, agg);
    pthread_t tid;
    CHECK(pthread_create(&tid, NULL, pcv_http_thread, &srv) == 0, "start server thread");

    static char resp[262144];

    /* Allowed Host -> 200, valid JSON, and crucially NO CORS header. */
    int len = http_get(port, "127.0.0.1", "/stats.json", resp, sizeof(resp));
    CHECK(len > 0, "GET /stats.json returned a response");
    CHECK(strstr(resp, "200 OK") != NULL, "/stats.json -> 200 OK");
    CHECK(strstr(resp, "application/json") != NULL, "/stats.json pinned JSON content-type");
    {
        char low[4096];
        size_t hl = (size_t)len < sizeof(low) - 1 ? (size_t)len : sizeof(low) - 1;
        memcpy(low, resp, hl);
        low[hl] = '\0';
        lower_inplace(low);
        CHECK(strstr(low, "access-control-allow-origin") == NULL,
              "NO Access-Control-Allow-Origin ever emitted (zero CORS)");
    }
    CHECK(strstr(resp, "\"proto\"") != NULL, "/stats.json body has the proto panel data");

    /* Bad Host -> 403 (DNS-rebinding defense). */
    len = http_get(port, "evil.example", "/stats.json", resp, sizeof(resp));
    CHECK(len > 0 && strstr(resp, "403") != NULL, "Host: evil.example -> 403 Forbidden");

    /* Dashboard page + health + favicon-204 + unknown-404. */
    len = http_get(port, "127.0.0.1", "/", resp, sizeof(resp));
    CHECK(strstr(resp, "200 OK") != NULL && strstr(resp, "text/html") != NULL,
          "GET / -> 200 text/html");
    len = http_get(port, "127.0.0.1", "/healthz", resp, sizeof(resp));
    CHECK(strstr(resp, "200 OK") != NULL && strstr(resp, "ok") != NULL, "/healthz -> ok");
    len = http_get(port, "127.0.0.1", "/favicon.ico", resp, sizeof(resp));
    CHECK(strstr(resp, "204") != NULL, "/favicon.ico -> 204");
    len = http_get(port, "127.0.0.1", "/nope", resp, sizeof(resp));
    CHECK(strstr(resp, "404") != NULL, "unknown path -> 404");
    (void)len;

    pcv_http_stop(&srv);
    pthread_join(tid, NULL);
    pcv_dash_destroy(agg);
}

/* ---- 5. served-HTML guards (negative + positive) ------------------------ */

static void test_html_no_external_urls(void) {
    fprintf(stdout, "dashboard HTML: no external URLs\n");
    size_t n = sizeof(PCV_DASHBOARD_HTML);
    char* low = malloc(n);
    CHECK(low != NULL, "alloc html copy");
    if (!low) return;
    memcpy(low, PCV_DASHBOARD_HTML, n);
    lower_inplace(low);

    const char* banned[] = {
        "http://", "https://",
        "src=\"//", "src='//", "href=\"//", "href='//",
        "url(",
        "@import", "@font-face", "@font",
        "<link", "<iframe", "<img", "<image", "<source",
        "srcset", "poster=",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        "<script src", ".innerhtml",
    };
    for (size_t i = 0; i < sizeof(banned)/sizeof(banned[0]); i++) {
        char msg[96];
        snprintf(msg, sizeof(msg), "no forbidden token: %s", banned[i]);
        CHECK(strstr(low, banned[i]) == NULL, msg);
    }
    free(low);
}

static void test_html_positive(void) {
    fprintf(stdout, "dashboard HTML: required pieces present\n");
    const char* html = PCV_DASHBOARD_HTML;
    const char* required[] = {
        "<!doctype", "charset",
        "panel-capture", "panel-proto", "panel-flows",
        "panel-hosts", "hosts-body",
        "drop-rate",
        "fetch('/stats.json'",
        "textContent",
    };
    for (size_t i = 0; i < sizeof(required)/sizeof(required[0]); i++) {
        char msg[96];
        snprintf(msg, sizeof(msg), "html contains: %s", required[i]);
        /* <!doctype is case-sensitive lowercase in our source; others exact. */
        CHECK(strstr(html, required[i]) != NULL, msg);
    }
}

int main(void) {
    test_validate_bind_addr();
    test_host_allowed();
    uint16_t port = 0;
    test_listen_local(&port);
    if (g_shared_listen_fd >= 0) {
        test_requests(port, g_shared_listen_fd);
    }
    test_html_no_external_urls();
    test_html_positive();
    return pcv_test_summary("test_http_guard");
}
