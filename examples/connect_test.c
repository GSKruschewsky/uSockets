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

#ifndef _WIN32
#include <dlfcn.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#endif

const int SSL = 0;

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
static void wait_for_lookups() {}
static long long now_ms() { return 0; }
#define CAN_DELAY_LOOKUPS 0
#endif

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
    return us_socket_close(SSL, s, 0, NULL);
}

static struct us_socket_t *on_noop(struct us_socket_t *s) {
    return s;
}

/* ---- client side ---- */

static struct us_socket_t *on_client_open(struct us_socket_t *s, int is_client, char *ip, int ip_length) {
    CHECK(is_client, "client socket opened as server");
    CHECK(((struct client_socket *) us_socket_ext(SSL, s))->step == step, "on_open from a stale step");
    CHECK(us_socket_is_established(SSL, s), "opened socket must be established");
    CHECK(us_socket_remote_port(SSL, s) == listen_port, "remote port mismatch");
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
                CHECK(ticks >= 10, "loop was blocked during the lookup: only %d 10 ms ticks in %d ms", ticks, lookup_delay());
            }
            break;
        case 4:
            CHECK(opened == 8 && closed == 8, "concurrent connects: %d opened, %d closed", opened, closed);
            break;
        case 5:
            CHECK(connect_errors == 1 && opened == 0 && closed == 0, "unresolvable name must emit on_connect_error only");
            CHECK(last_error_code != 0, "unresolvable name must report a non-zero code");
            break;
        case 6:
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
            printf("Step 4: eight concurrent dials\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 100 : 0);
            expected_count = 8;
            for (int i = 0; i < 8; i++) {
                dial("localhost", listen_port);
            }
            break;
        case 5:
            printf("Step 5: unresolvable name emits on_connect_error\n");
            set_lookup_delay(0);
            dial("nonexistent.invalid", listen_port);
            break;
        case 6:
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
            printf("Step 10: context freed while a lookup is in flight\n");
            set_lookup_delay(CAN_DELAY_LOOKUPS ? 500 : 0);
            dial("localhost", listen_port);
            dial("localhost", listen_port);

            /* Tear everything down from inside the loop; the resolving sockets are cancelled by the
             * context free and the loop exits once the closed sockets have been freed. The
             * (fallthrough) timers are closed after the loop has exited, as closing a poll
             * from inside the loop counts against its poll count. */
            us_listen_socket_close(SSL, listen_socket);
            us_socket_context_free(SSL, client_context);
            us_socket_context_free(SSL, server_context);
            break;
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
#ifndef _WIN32
    loop_thread = pthread_self();
#endif

    loop = us_create_loop(0, on_wakeup, on_pre, on_post, 0);

    struct us_socket_context_options_t options = {0};
    server_context = us_create_socket_context(SSL, loop, 0, options);
    us_socket_context_on_open(SSL, server_context, on_server_open);
    us_socket_context_on_data(SSL, server_context, on_server_data);
    us_socket_context_on_writable(SSL, server_context, on_noop);
    us_socket_context_on_close(SSL, server_context, on_server_close);
    us_socket_context_on_timeout(SSL, server_context, on_noop);
    us_socket_context_on_long_timeout(SSL, server_context, on_noop);
    us_socket_context_on_end(SSL, server_context, on_server_end);

    client_context = us_create_socket_context(SSL, loop, 0, options);
    us_socket_context_on_open(SSL, client_context, on_client_open);
    us_socket_context_on_data(SSL, client_context, on_server_data);
    us_socket_context_on_writable(SSL, client_context, on_noop);
    us_socket_context_on_close(SSL, client_context, on_client_close);
    us_socket_context_on_timeout(SSL, client_context, on_client_timeout);
    us_socket_context_on_long_timeout(SSL, client_context, on_noop);
    us_socket_context_on_end(SSL, client_context, on_noop);
    us_socket_context_on_connect_error(SSL, client_context, on_client_connect_error);

    /* Listen on an ephemeral port, on both address families ("localhost" may resolve to ::1 first) */
    listen_socket = us_socket_context_listen(SSL, server_context, NULL, 0, 0, 0);
    if (!listen_socket) {
        printf("Failed to listen\n");
        return 1;
    }
    listen_port = us_socket_local_port(SSL, (struct us_socket_t *) listen_socket);

    /* Find a port nobody listens on: take one, then give it back */
    struct us_listen_socket_t *tmp = us_socket_context_listen(SSL, server_context, NULL, 0, 0, 0);
    if (!tmp) {
        printf("Failed to listen\n");
        return 1;
    }
    refused_port = us_socket_local_port(SSL, (struct us_socket_t *) tmp);
    us_listen_socket_close(SSL, tmp);

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

    if (step != 10) {
        printf("FAIL: loop exited at step %d\n", step);
        return 1;
    }

    printf("ALL TESTS PASSED (%d lookups off the loop thread, %d on it)\n", gai_off_loop_thread, gai_on_loop_thread);
    return 0;
}
