# Optimized TCP, TLS, QUIC & HTTP3 transports

µSockets is the non-blocking, thread-per-CPU foundation library used by [µWebSockets](https://github.com/uNetworking/uWebSockets). It provides optimized networking - using the same opaque API (programming interface) across all supported transports, event-loops and platforms (QUIC is work-in-progress, so is io_uring).

<a href="https://github.com/uNetworking/uSockets/releases"><img src="https://img.shields.io/github/v/release/uNetworking/uSockets"></a>

## Write code once
Based on µSockets, apps like µWebSockets can run on many platforms, over many transports and with many event-loops - all without any code changes or special execution paths. Moving data over TCP is just as easy as over QUIC.

Hit `make examples` to get started.

## Lightweight or featureful
In its minimal, TCP-only, configuration µSockets has no dependencies other than the very OS kernel and compiles down to a tiny binary. In its full configuration it depends on BoringSSL, lsquic and potentially some event-loop library.

Here are some configurations; WITH_IO_URING, WITH_LIBUV, WITH_ASIO, WITH_GCD, WITH_ASAN, WITH_QUIC, WITH_BORINGSSL, WITH_OPENSSL, WITH_WOLFSSL.

## Non-blocking client connects
`us_socket_context_connect` never blocks the loop thread: numeric hosts connect right away, while host names are resolved on a short-lived resolver thread and the connect is finished on the loop thread once the lookup completes. The returned socket can be timed out or cancelled while the lookup is in flight, and an unresolvable name is reported through `on_connect_error`. The library therefore links against pthreads on POSIX (`make` adds `-pthread`); embedders linking `uSockets.a` on glibc older than 2.34 need `-pthread` too.

## Fast & stable
µWebSockets itself is known to have run with outstanding performance and stability since 2016. This thanks to, among other factors, the speed and stability of µSockets. We fuzz and randomly "hammer test" the library as part of security & stability testing done in the µWebSockets project.

## Fork additions
This fork adds a few loop and context calls, declared and documented in `src/libusockets.h`; everything is off or inert unless asked for, and the read path is byte-identical otherwise.

- **Kernel receive timestamps** — `us_socket_context_set_rx_timestamps(ssl, context, 1)` enables Linux `SO_TIMESTAMPING` on the context's sockets; inside the `on_data` chain of a read, `us_loop_last_rx_timestamp(loop, &from_kernel)` is the `CLOCK_REALTIME` nanosecond stamp the kernel took when the segment arrived (`from_kernel` is 0 when it is a userspace fallback: other platforms, old kernels, the first packets after enabling). `us_realtime_ns()` reads the same clock now.
- **Receive-buffer views** — `us_loop_recv_buffer(loop, which, &length)` returns the loop's receive buffers (0 = the plain-socket read buffer, 1 = the TLS plaintext buffer, NULL until the first TLS context exists) and `us_loop_recv_buffer_of(loop, data, length, &offset)` tells which one a chunk lies in, or -1 for data that was reassembled or inflated elsewhere. An embedder can keep one persistent view per buffer instead of copying every message. The bytes are valid only while the `on_data` callback that delivered them runs; the next read overwrites them, so a message kept past the callback must be copied.
- **Non-blocking client connects** — see above; a failed lookup reaches `on_connect_error` with a code in the `LIBUS_CONNECT_ERROR_RESOLVE_BASE` range (`LIBUS_CONNECT_ERROR_IS_RESOLVE`, `LIBUS_CONNECT_ERROR_RESOLVE_CODE` give the `getaddrinfo` error). When `us_socket_context_connect` returns null (the attempt could not be started), `us_socket_context_last_connect_error` gives the platform error or the resolver-thread error that stopped it, independent of `errno` (`tests/connect_error_test.c`).

Not implemented on the io_uring backend (work in progress upstream): the calls exist there as stubs that report no stamp and no buffer. `make tests` builds and runs the library tests (`tests/recv_buffer_test.c`) against `uSockets.a`; CI runs them with and without OpenSSL.
