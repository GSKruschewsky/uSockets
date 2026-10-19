/* us_socket_context_last_connect_error: when us_socket_context_connect returns null the context
 * keeps the error that stopped the attempt (here EADDRNOTAVAIL / WSAEADDRNOTAVAIL from binding a
 * source address the host does not own, on both the plain and the SSL context when built with
 * one), independent of errno, and a connect that was started clears it back to 0. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../src/libusockets.h"

/* The platform's "address not available" code from bind(): WSAGetLastError on Windows, errno elsewhere */
#ifdef _WIN32
#define BIND_ERROR WSAEADDRNOTAVAIL
#else
#define BIND_ERROR EADDRNOTAVAIL
#endif

/* A cancelled connecting socket is freed by the loop at the end of an iteration, so run one:
 * a one-shot timer keeps the loop alive for exactly that iteration */
static void drain_timer(struct us_timer_t *t) {
    us_timer_close(t);
}

static void drain(struct us_loop_t *loop) {
    struct us_timer_t *t = us_create_timer(loop, 0, 0);
    us_timer_set(t, drain_timer, 1, 0);
    us_loop_run(loop);
}

/* us_loop_run calls these unconditionally */
static void loop_noop(struct us_loop_t *loop) {
    (void) loop;
}

static void check_context(int ssl, struct us_socket_context_t *context) {
    /* Fresh context: nothing failed yet */
    assert(us_socket_context_last_connect_error(ssl, context) == 0);

    /* A numeric host with a source address nobody here owns fails in bind(), synchronously */
    errno = 0;
    struct us_socket_t *s = us_socket_context_connect(ssl, context, "127.0.0.1", 9, "192.0.2.1", 0, 0);
    assert(s == 0);
    assert(us_socket_context_last_connect_error(ssl, context) == BIND_ERROR);

    /* The value survives other library calls that may touch errno */
    errno = 0;
    assert(us_socket_context_last_connect_error(ssl, context) == BIND_ERROR);

    /* A started attempt (numeric host, result arrives later in the loop) clears it */
    s = us_socket_context_connect(ssl, context, "127.0.0.1", 9, 0, 0, 0);
    assert(s != 0);
    assert(us_socket_context_last_connect_error(ssl, context) == 0);
    us_socket_close_connecting(ssl, s);

    /* And a failure after that is reported again */
    s = us_socket_context_connect(ssl, context, "127.0.0.1", 9, "192.0.2.1", 0, 0);
    assert(s == 0);
    assert(us_socket_context_last_connect_error(ssl, context) == BIND_ERROR);
}

int main() {
    struct us_loop_t *loop = us_create_loop(0, loop_noop, loop_noop, loop_noop, 0);
    assert(loop);
    struct us_socket_context_options_t options;
    memset(&options, 0, sizeof(options));

    struct us_socket_context_t *context = us_create_socket_context(0, loop, 0, options);
    assert(context);
    check_context(0, context);
    drain(loop);
    us_socket_context_free(0, context);

#ifndef LIBUS_NO_SSL
    struct us_socket_context_t *ssl_context = us_create_socket_context(1, loop, 0, options);
    if (ssl_context) {
        check_context(1, ssl_context);
        drain(loop);
        us_socket_context_free(1, ssl_context);
    }
#endif

    us_loop_free(loop);
    printf("connect_error_test: ok\n");
    return 0;
}
