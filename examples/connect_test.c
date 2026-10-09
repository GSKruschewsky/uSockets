/* Exercises us_socket_context_connect with host names: the name lookup must run off the loop
 * thread, the loop must stay responsive meanwhile, and the socket must be cancellable, able to time
 * out and able to fail (unresolvable name, refused port) while its lookup is in flight.
 *
 * On POSIX this binary interposes getaddrinfo so that it can delay non-numeric lookups and record
 * the thread they ran on; every assertion about asynchrony relies on that. On Windows the test still
 * runs every scenario but cannot delay lookups, so it only checks the outcomes. */

#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include <libusockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET refused_socket_t;
#define REFUSED_SOCKET_INVALID INVALID_SOCKET
#else
#include <dlfcn.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
typedef int refused_socket_t;
#define REFUSED_SOCKET_INVALID -1
#endif

/* 1 runs the client side through an SSL context (set CONNECT_TEST_SSL=1; needs an SSL build) */
static int SSL = 0;

/* ---- getaddrinfo interposition (POSIX only) ---- */

/* Delay applied to the next non-numeric lookups, in milliseconds */
static int gai_delay_ms = 0;
/* Non-numeric lookups seen on / off the loop thread, and the number still running */
static volatile int gai_on_loop_thread = 0, gai_off_loop_thread = 0, gai_in_flight = 0;

#ifndef _WIN32
static pthread_t loop_thread;
static pthread_mutex_t gai_mutex = PTHREAD_MUTEX_INITIALIZER;

static int is_numeric_host(const char *node) {
    unsigned char buf[16];
    return node && (inet_pton(AF_INET, node, buf) == 1 || inet_pton(AF_INET6, node, buf) == 1);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    static int (*real_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
    if (!real_getaddrinfo) {
        real_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **)) dlsym(RTLD_NEXT, "getaddrinfo");
    }

    /* A null node is the wildcard / loopback address, never a name */
    int numeric = !node || is_numeric_host(node) || (hints && (hints->ai_flags & AI_NUMERICHOST));
    int delay = 0;
    if (!numeric) {
        pthread_mutex_lock(&gai_mutex);
        if (pthread_equal(pthread_self(), loop_thread)) {
            gai_on_loop_thread++;
        } else {
            gai_off_loop_thread++;
        }
        gai_in_flight++;
        delay = gai_delay_ms;
        pthread_mutex_unlock(&gai_mutex);

        if (delay) {
            usleep(delay * 1000);
        }
    }

    int ret = real_getaddrinfo(node, service, hints, res);

    if (!numeric) {
        pthread_mutex_lock(&gai_mutex);
        gai_in_flight--;
        pthread_mutex_unlock(&gai_mutex);
    }
    return ret;
}

static void set_lookup_delay(int ms) {
    pthread_mutex_lock(&gai_mutex);
    gai_delay_ms = ms;
    pthread_mutex_unlock(&gai_mutex);
}

static int lookup_delay() {
    pthread_mutex_lock(&gai_mutex);
    int ms = gai_delay_ms;
    pthread_mutex_unlock(&gai_mutex);
    return ms;
}

/* The lookup has returned, but its thread may not have published the result yet; give it a moment
 * (if it has not, cancellation simply takes the other, equally valid path) */
static void settle() {
    usleep(50 * 1000);
}

static void wait_for_lookups() {
    for (int i = 0; i < 2000; i++) {
        pthread_mutex_lock(&gai_mutex);
        int in_flight = gai_in_flight;
        pthread_mutex_unlock(&gai_mutex);
        if (!in_flight) {
            return;
        }
        usleep(10 * 1000);
    }
}

static long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define CAN_DELAY_LOOKUPS 1
#else
static void set_lookup_delay(int ms) {}
static int lookup_delay() { return 0; }
static void settle() {}
static void wait_for_lookups() {}
static long long now_ms() { return 0; }
#define CAN_DELAY_LOOKUPS 0
#endif

/* A port on which every connect is refused. Rather than reasoning about bind semantics (which
 * differ per OS: macOS silently drops SYNs to a bound-but-not-listening socket, and hands a
 * freshly freed ephemeral port to the connecting socket itself, which then self-connects), we
 * probe the property we need: a non-blocking connect to the port on each loopback address must
 * fail with ECONNREFUSED within a second. Candidates lie outside every OS's ephemeral range. */
static int close_probe(refused_socket_t fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
    return 0;
}

/* 1 = refused, 0 = open or undecided, -1 = this address family is unavailable here */
static int probe_port(int family, int port) {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    memset(&addr, 0, sizeof(addr));
    if (family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &addr;
        in6->sin6_family = AF_INET6;
        in6->sin6_addr = in6addr_loopback;
        in6->sin6_port = htons((unsigned short) port);
        addr_len = sizeof(*in6);
    } else {
        struct sockaddr_in *in4 = (struct sockaddr_in *) &addr;
        in4->sin_family = AF_INET;
        in4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        in4->sin_port = htons((unsigned short) port);
        addr_len = sizeof(*in4);
    }

    refused_socket_t fd = socket(family, SOCK_STREAM, 0);
    if (fd == REFUSED_SOCKET_INVALID) {
        return -1;
    }
#ifdef _WIN32
    u_long nonblocking = 1;
    ioctlsocket(fd, FIONBIO, &nonblocking);
#else
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

    int error = 0;
    if (connect(fd, (struct sockaddr *) &addr, addr_len) == 0) {
        /* Connected right away (self-connect or a listener) */
        return close_probe(fd);
    }
#ifdef _WIN32
    error = WSAGetLastError();
    if (error != WSAEWOULDBLOCK) {
        close_probe(fd);
        return error == WSAECONNREFUSED ? 1 : (error == WSAEADDRNOTAVAIL || error == WSAEAFNOSUPPORT ? -1 : 0);
    }
#else
    error = errno;
    if (error != EINPROGRESS) {
        close_probe(fd);
        return error == ECONNREFUSED ? 1 : (error == EADDRNOTAVAIL || error == ENETUNREACH || error == EAFNOSUPPORT ? -1 : 0);
    }
#endif

    /* A finished non-blocking connect shows up as writable; Windows reports a failed one in the
     * exception set instead, so watch both */
    fd_set writable, failed;
    FD_ZERO(&writable);
    FD_ZERO(&failed);
    FD_SET(fd, &writable);
    FD_SET(fd, &failed);
    /* Windows retries a SYN that was answered with RST, so a refusal takes about a second there */
    struct timeval timeout = {3, 0};
    if (select((int) fd + 1, NULL, &writable, &failed, &timeout) <= 0) {
        return close_probe(fd);
    }

    socklen_t error_len = sizeof(error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &error, &error_len);
    close_probe(fd);
#ifdef _WIN32
    return error == WSAECONNREFUSED ? 1 : 0;
#else
    return error == ECONNREFUSED ? 1 : 0;
#endif
}

static int find_refused_port() {
    /* Bounded, so that a platform where nothing is ever refused skips step 6 instead of
     * spending the CI job's time on probes */
    for (int port = 10000; port < 10016; port++) {
        int v4 = probe_port(AF_INET, port);
        int v6 = probe_port(AF_INET6, port);
        printf("Probed port %d: IPv4 %s, IPv6 %s\n", port, v4 == 1 ? "refused" : v4 == 0 ? "undecided" : "unavailable", v6 == 1 ? "refused" : v6 == 0 ? "undecided" : "unavailable");
        /* Refused on every family that exists here (and at least one exists) */
        if (v4 != 0 && v6 != 0 && (v4 == 1 || v6 == 1)) {
            return port;
        }
    }
    return -1;
}

/* ---- test harness ---- */

static struct us_loop_t *loop;
static struct us_socket_context_t *server_context, *client_context;
static struct us_listen_socket_t *listen_socket;
static struct us_timer_t *step_timer, *tick_timer, *watchdog_timer;
static int listen_port, refused_port;

static int step = 0;
static int opened = 0, closed = 0, connect_errors = 0, timeouts = 0, last_error_code = 0, ticks = 0;
static int expected_count = 1;
static long long step_started_ms = 0;

struct client_socket {
    int step;
};

#define FAIL(...) do { printf("FAIL (step %d): ", step); printf(__VA_ARGS__); printf("\n"); exit(1); } while (0)
#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)

static void run_step(struct us_timer_t *t);

static void schedule_next_step(int delay_ms) {
    us_timer_set(step_timer, run_step, delay_ms, 0);
}

static void reset_counters() {
    opened = closed = connect_errors = timeouts = last_error_code = ticks = 0;
    expected_count = 1;
}

static struct us_socket_t *dial(const char *host, int port) {
    long long before = now_ms();
    struct us_socket_t *s = us_socket_context_connect(SSL, client_context, host, port, NULL, 0, sizeof(struct client_socket));
    long long took = now_ms() - before;
    CHECK(s != NULL, "us_socket_context_connect(%s:%d) returned null", host, port);
    CHECK(!us_socket_is_established(SSL, s), "a freshly dialed socket must not be established");
    int delay = lookup_delay();
    if (CAN_DELAY_LOOKUPS && delay) {
        CHECK(took < delay / 2, "connect(%s) blocked for %lld ms with a %d ms lookup", host, took, delay);
    }
    ((struct client_socket *) us_socket_ext(SSL, s))->step = step;
    return s;
}

/* ---- server side: accept and sit there ---- */

static struct us_socket_t *on_server_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    return s;
}

static struct us_socket_t *on_server_data(struct us_socket_t *s, char *data, int length) {
    return s;
}

static struct us_socket_t *on_server_close(struct us_socket_t *s, int code, void *reason) {
    return s;
}

static struct us_socket_t *on_server_end(struct us_socket_t *s) {
    return us_socket_close(0, s, 0, NULL);
}

static struct us_socket_t *on_noop(struct us_socket_t *s) {
    return s;
}

/* ---- client side ---- */

static struct us_socket_t *on_client_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    CHECK(is_client, "client socket opened as server");
    CHECK(((struct client_socket *) us_socket_ext(SSL, s))->step == step, "on_open from a stale step");
    CHECK(us_socket_is_established(SSL, s), "opened socket must be established");
    CHECK(us_socket_remote_port(SSL, s) == listen_port, "remote port mismatch: remote %d local %d, listening on %d, refused port %d",
        us_socket_remote_port(SSL, s), us_socket_local_port(SSL, s), listen_port, refused_port);
    opened++;
    return us_socket_close(SSL, s, 0, NULL);
}

static struct us_socket_t *on_client_close(struct us_socket_t *s, int code, void *reason) {
    CHECK(((struct client_socket *) us_socket_ext(SSL, s))->step == step, "on_close from a stale step");
    closed++;
    if (closed == expected_count) {
        schedule_next_step(1);
    }
    return s;
}

static struct us_socket_t *on_client_connect_error(struct us_socket_t *s, int code) {
    CHECK(((struct client_socket *) us_socket_ext(SSL, s))->step == step, "on_connect_error from a stale step");
    CHECK(!us_socket_is_established(SSL, s), "errored socket must not be established");
    connect_errors++;
    last_error_code = code;
    schedule_next_step(1);
    return s;
}

static struct us_socket_t *on_client_timeout(struct us_socket_t *s) {
    CHECK(((struct client_socket *) us_socket_ext(SSL, s))->step == step, "on_timeout from a stale step");
    CHECK(!us_socket_is_established(SSL, s), "timed out socket must not be established");
    timeouts++;
    /* Exactly what a real client does: give up on a connect that takes too long */
    us_socket_close_connecting(SSL, s);
    schedule_next_step(1);
    return s;
}

static void on_tick(struct us_timer_t *t) {
    ticks++;
}

static void on_watchdog(struct us_timer_t *t) {
    FAIL("timed out waiting for step to complete");
}

static void on_wakeup(struct us_loop_t *loop) {}
static void on_pre(struct us_loop_t *loop) {}
static void on_post(struct us_loop_t *loop) {}

/* ---- the scenarios ---- */

static void run_step(struct us_timer_t *t) {
    /* Verify the previous step first */
    switch (step) {
        case 0:
            break;
        case 1:
            CHECK(opened == 1 && closed == 1, "numeric connect did not open");
            CHECK(gai_on_loop_thread == 0 && gai_off_loop_thread == 0, "numeric host must not be looked up");
            break;
        case 2:
            CHECK(opened == 1 && closed == 1, "localhost connect did not open");
            if (CAN_DELAY_LOOKUPS) {
                CHECK(gai_off_loop_thread == 1 && gai_on_loop_thread == 0, "lookup ran on the loop thread (%d on, %d off)", gai_on_loop_thread, gai_off_loop_thread);
            }
            break;
        case 3:
            CHECK(opened == 1 && closed == 1, "delayed localhost connect did not open");
            us_timer_set(tick_timer, on_tick, 0, 0);
            if (CAN_DELAY_LOOKUPS) {
                CHECK(ticks >= 5, "loop was blocked during the lookup: only %d 10 ms ticks in %d ms", ticks, lookup_delay());
            }
            break;
        case 4:
            CHECK(opened == 40 && closed == 40, "concurrent connects: %d opened, %d closed", opened, closed);
            break;
        case 5:
            CHECK(connect_errors == 1 && opened == 0 && closed == 0, "unresolvable name must emit on_connect_error only");
            CHECK(LIBUS_CONNECT_ERROR_IS_RESOLVE(last_error_code), "unresolvable name must report a resolve code, got %d", last_error_code);
            CHECK(LIBUS_CONNECT_ERROR_RESOLVE_CODE(last_error_code) > 0, "resolve code must carry the getaddrinfo error");
            break;
        case 6:
            if (refused_port <= 0) {
                break;
            }
            CHECK(connect_errors == 1 && opened == 0 && closed == 0, "refused port must emit on_connect_error only");
#ifndef _WIN32
            CHECK(last_error_code == ECONNREFUSED, "refused port reported %d, expected ECONNREFUSED", last_error_code);
#endif
            break;
        case 7:
            CHECK(opened == 0 && closed == 0 && connect_errors == 0, "cancelled (close_connecting) socket emitted an event");
            break;
        case 8:
            CHECK(opened == 0 && closed == 1 && connect_errors == 0, "cancelled (close) socket must emit on_close exactly once");
            break;
        case 9:
            CHECK(timeouts == 1 && opened == 0 && connect_errors == 0, "timeout during lookup: %d timeouts, %d opened, %d errors", timeouts, opened, connect_errors);
            break;
        case 10:
            CHECK(opened == 1 && closed == 1 && connect_errors == 0, "queued dial after cancelling all running ones: %d opened, %d closed, %d errors", opened, closed, connect_errors);
            break;
    }

    reset_counters();
    step++;
    step_started_ms = now_ms();
    us_timer_set(watchdog_timer, on_watchdog, 30000, 0);

    switch (step) {
        case 1:
            printf("Step 1: numeric host connects synchronously\n");
            set_lookup_delay(0);
            dial("127.0.0.1", listen_port);
            break;
        case 2:
            printf("Step 2: host name is resolved off the loop thread\n");
            set_lookup_delay(0);
            dial("localhost", listen_port);
            break;
        case 3:
            printf("Step 3: loop stays responsive during a slow lookup\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 300 : 0);
            us_timer_set(tick_timer, on_tick, 10, 10);
            dial("localhost", listen_port);
            break;
        case 4:
            printf("Step 4: forty concurrent dials (more than there are resolver threads)\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 100 : 0);
            expected_count = 40;
            for (int i = 0; i < 40; i++) {
                dial("localhost", listen_port);
            }
            break;
        case 5:
            printf("Step 5: unresolvable name emits on_connect_error\n");
            set_lookup_delay(0);
            dial("nonexistent.invalid", listen_port);
            break;
        case 6:
            if (refused_port <= 0) {
                printf("Step 6: (skipped, no refused port available)\n");
                schedule_next_step(1);
                break;
            }
            printf("Step 6: resolvable name with refused port emits on_connect_error\n");
            set_lookup_delay(0);
            dial("localhost", refused_port);
            break;
        case 7: {
            printf("Step 7: us_socket_close_connecting during the lookup\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 300 : 0);
            struct us_socket_t *s = dial("localhost", listen_port);
            us_socket_close_connecting(SSL, s);
            CHECK(us_socket_is_closed(SSL, s), "cancelled socket must read as closed");

            /* And the other ordering: the lookup has already finished (but the loop has not
             * picked up its result yet) when the socket is cancelled */
            set_lookup_delay(0);
            s = dial("localhost", listen_port);
            wait_for_lookups();
            settle();
            us_socket_close_connecting(SSL, s);
            CHECK(us_socket_is_closed(SSL, s), "cancelled socket must read as closed");

            /* Give the first lookup time to complete; nothing may happen for either socket */
            schedule_next_step(600);
            break;
        }
        case 8: {
            printf("Step 8: us_socket_close during the lookup\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 300 : 0);
            struct us_socket_t *s = dial("localhost", listen_port);
            /* Writes and shutdowns on a resolving socket are no-ops, not crashes */
            CHECK(us_socket_write(SSL, s, "x", 1, 0) == 0, "write on a resolving socket must write nothing");
            us_socket_shutdown(SSL, s);
            us_socket_flush(SSL, s);
            CHECK(us_socket_remote_port(SSL, s) == -1, "resolving socket has no remote port");
            us_socket_close(SSL, s, 0, NULL);
            CHECK(us_socket_is_closed(SSL, s), "closed socket must read as closed");
            schedule_next_step(600);
            break;
        }
        case 9: {
            if (!CAN_DELAY_LOOKUPS) {
                printf("Step 9: (skipped, cannot delay lookups here)\n");
                timeouts = 1;
                schedule_next_step(1);
                break;
            }
            printf("Step 9: us_socket_timeout covers the lookup (takes a few seconds)\n");
            set_lookup_delay(6000);
            struct us_socket_t *s = dial("localhost", listen_port);
            us_socket_timeout(SSL, s, 1);
            break;
        }
        case 10: {
            printf("Step 10: a queued dial still starts after every running lookup is cancelled\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 300 : 0);
            /* Fill every resolver thread, queue one more, then cancel all the running ones:
             * the queued dial must still get a thread and open */
            struct us_socket_t *running[16];
            for (int i = 0; i < 16; i++) {
                running[i] = dial("localhost", listen_port);
            }
            dial("localhost", listen_port);
            for (int i = 0; i < 16; i++) {
                us_socket_close_connecting(SSL, running[i]);
            }
            break;
        }
        case 11: {
            printf("Step 11: context freed while a lookup is in flight\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 500 : 0);
            dial("localhost", listen_port);
            dial("localhost", listen_port);

            /* Tear everything down from inside the loop; the resolving client sockets are cancelled
             * by the client context free and the loop exits once the closed sockets have been freed.
             * The server side may still hold sockets whose FIN from the previous step is yet to be
             * processed, and a context must only be freed once its sockets are closed, so close
             * them (and the listen socket) first. The (fallthrough) timers are closed after the
             * loop has exited, as closing a poll from inside the loop counts against its poll count. */
            us_socket_context_close(0, server_context);
            us_socket_context_free(SSL, client_context);
            us_socket_context_free(0, server_context);
            break;
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("connect_test: name resolution for us_socket_context_connect\n");
    if (getenv("CONNECT_TEST_SSL")) {
        SSL = 1;
        printf("Client context is SSL\n");
    }

#ifndef _WIN32
    loop_thread = pthread_self();
#endif

    loop = us_create_loop(0, on_wakeup, on_pre, on_post, 0);

    struct us_socket_context_options_t options = {0};
    /* The server is always plain TCP: an SSL client still reaches on_open (and can be closed
     * there) before any handshake, which is all these scenarios need */
    server_context = us_create_socket_context(0, loop, 0, options);
    us_socket_context_on_open(0, server_context, on_server_open);
    us_socket_context_on_data(0, server_context, on_server_data);
    us_socket_context_on_writable(0, server_context, on_noop);
    us_socket_context_on_close(0, server_context, on_server_close);
    us_socket_context_on_timeout(0, server_context, on_noop);
    us_socket_context_on_long_timeout(0, server_context, on_noop);
    us_socket_context_on_end(0, server_context, on_server_end);

    client_context = us_create_socket_context(SSL, loop, 0, options);
    if (!client_context) {
        printf("Failed to create client context\n");
        return 1;
    }
    us_socket_context_set_host_name(SSL, client_context, "localhost");
    us_socket_context_on_open(SSL, client_context, on_client_open);
    us_socket_context_on_data(SSL, client_context, on_server_data);
    us_socket_context_on_writable(SSL, client_context, on_noop);
    us_socket_context_on_close(SSL, client_context, on_client_close);
    us_socket_context_on_timeout(SSL, client_context, on_client_timeout);
    us_socket_context_on_long_timeout(SSL, client_context, on_noop);
    us_socket_context_on_end(SSL, client_context, on_noop);
    us_socket_context_on_connect_error(SSL, client_context, on_client_connect_error);

    /* Listen on an ephemeral port, on both address families ("localhost" may resolve to ::1 first) */
    listen_socket = us_socket_context_listen(0, server_context, NULL, 0, 0, 0);
    if (!listen_socket) {
        printf("Failed to listen\n");
        return 1;
    }
    listen_port = us_socket_local_port(0, (struct us_socket_t *) listen_socket);

    refused_port = find_refused_port();
    if (refused_port <= 0) {
        printf("No refused port found, step 6 will be skipped\n");
    }

    step_timer = us_create_timer(loop, 1, 0);
    tick_timer = us_create_timer(loop, 1, 0);
    watchdog_timer = us_create_timer(loop, 1, 0);

    schedule_next_step(1);
    us_loop_run(loop);

    us_timer_close(step_timer);
    us_timer_close(tick_timer);
    us_timer_close(watchdog_timer);
    us_loop_free(loop);

    /* Let the cancelled lookups of the last step finish so that they free their requests
     * before the leak checker looks */
    wait_for_lookups();

    if (step != 11) {
        printf("FAIL: loop exited at step %d\n", step);
        return 1;
    }

    printf("ALL TESTS PASSED (%d lookups off the loop thread, %d on it)\n", gai_off_loop_thread, gai_on_loop_thread);
    return 0;
}
