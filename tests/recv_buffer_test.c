/* us_loop_recv_buffer / us_loop_recv_buffer_of: the plain receive buffer is reported with its length,
 * a chunk inside it maps to (0, offset), a chunk outside it, running past its end, from another
 * allocation or NULL maps to -1, a zero-length chunk at the very end still lies inside (half-open
 * range), and the TLS buffer is NULL with length 0 before any TLS context exists (always, without SSL). */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/libusockets.h"

int main() {
    struct us_loop_t *loop = us_create_loop(0, 0, 0, 0, 0);
    assert(loop);

    unsigned int len = 0, off = 1234;
    char *buf = us_loop_recv_buffer(loop, 0, &len);
    assert(buf && len > 0);

    assert(us_loop_recv_buffer_of(loop, buf, 1, &off) == 0 && off == 0);
    assert(us_loop_recv_buffer_of(loop, buf + 100, len - 100, &off) == 0 && off == 100);
    assert(us_loop_recv_buffer_of(loop, buf, len, &off) == 0 && off == 0);
    assert(us_loop_recv_buffer_of(loop, buf + len, 0, &off) == 0 && off == len);
    assert(us_loop_recv_buffer_of(loop, buf + len - 1, 2, &off) == -1);
    assert(us_loop_recv_buffer_of(loop, buf + len, 1, &off) == -1);
    assert(us_loop_recv_buffer_of(loop, 0, 0, &off) == -1);
    assert(us_loop_recv_buffer_of(loop, 0, 1, &off) == -1);

    char *other = (char *) malloc(64);
    assert(other);
    assert(us_loop_recv_buffer_of(loop, other, 64, &off) == -1);
    assert(us_loop_recv_buffer_of(loop, other, 0, &off) == -1);
    free(other);

    unsigned int tls_len = 7;
    char *tls = us_loop_recv_buffer(loop, 1, &tls_len);
    assert(tls == 0 && tls_len == 0);

    unsigned int none_len = 7;
    assert(us_loop_recv_buffer(loop, 2, &none_len) == 0 && none_len == 0);
    assert(us_loop_recv_buffer(loop, -1, &none_len) == 0 && none_len == 0);

    us_loop_free(loop);
    printf("recv_buffer_test: ok\n");
    return 0;
}
