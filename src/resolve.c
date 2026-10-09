/*
 * Authored by Alex Hultman, 2018-2021.
 * Intellectual property of third-party.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *     http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Asynchronous name resolution for us_socket_context_connect.
 *
 * getaddrinfo() blocks for the resolver's round trip, which must never happen on the loop thread.
 * A connect to a non-numeric host therefore returns a socket in a "resolving" state (no fd, poll
 * not started) and hands the lookup to a short-lived resolver thread. When the lookup completes,
 * the thread wakes the loop through an internal async and the loop thread finishes the connect:
 * it creates the socket, binds it to the optional source address, starts the non-blocking
 * connect() and starts the poll, exactly as the numeric fast path does synchronously. From there
 * on the socket is an ordinary connecting socket and reaches on_open or on_connect_error.
 *
 * The number of resolver threads per loop is bounded; further lookups wait in the in-flight list
 * (oldest first) and are started as threads finish, so a reconnect storm never spawns hundreds of
 * threads at once nor stalls the loop thread creating them.
 *
 * Ownership: a request is shared between the loop thread and its resolver thread. The loop thread
 * owns the in-flight list and the socket; the resolver thread owns the results until it has
 * published them. The two flags "done" and "cancelled" are protected by the request's mutex and
 * whoever observes the other side's flag frees the request, so neither side ever touches memory
 * the other may have freed. Cancellation (socket closed, context or loop freed while the lookup
 * is in flight) only flips a flag; the resolver thread drops its result when it finds it. */

#ifndef LIBUS_USE_IO_URING

#include "libusockets.h"
#include "internal/internal.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Lookups beyond this many running at once wait their turn */
#define LIBUS_MAX_RESOLVER_THREADS 16

#ifdef _WIN32
#include <process.h>
typedef CRITICAL_SECTION us_internal_mutex_t;
static void us_internal_mutex_init(us_internal_mutex_t *m) { InitializeCriticalSection(m); }
static void us_internal_mutex_destroy(us_internal_mutex_t *m) { DeleteCriticalSection(m); }
static void us_internal_mutex_lock(us_internal_mutex_t *m) { EnterCriticalSection(m); }
static void us_internal_mutex_unlock(us_internal_mutex_t *m) { LeaveCriticalSection(m); }
#else
#include <pthread.h>
typedef pthread_mutex_t us_internal_mutex_t;
static void us_internal_mutex_init(us_internal_mutex_t *m) { pthread_mutex_init(m, NULL); }
static void us_internal_mutex_destroy(us_internal_mutex_t *m) { pthread_mutex_destroy(m); }
static void us_internal_mutex_lock(us_internal_mutex_t *m) { pthread_mutex_lock(m); }
static void us_internal_mutex_unlock(us_internal_mutex_t *m) { pthread_mutex_unlock(m); }
#endif

struct us_internal_resolve_request_t {
    /* Loop thread only */
    struct us_socket_t *socket;
    struct us_loop_t *loop;
    struct us_internal_resolve_request_t *prev, *next;
    int spawned; /* 0 while waiting for a free resolver thread */

    /* Immutable once the resolver thread has started */
    char *host;
    char *source_host;
    int port;
    int options;

    /* Written by the resolver thread, read by the loop thread once done is set */
    struct addrinfo *result;
    struct addrinfo *source_result;
    int error;

    /* Shared, protected by mutex */
    us_internal_mutex_t mutex;
    int done;
    int cancelled;
};

static char *us_internal_strdup(const char *str) {
    if (!str) {
        return NULL;
    }
    size_t length = strlen(str) + 1;
    char *copy = malloc(length);
    if (copy) {
        memcpy(copy, str, length);
    }
    return copy;
}

static void us_internal_resolve_free_request(struct us_internal_resolve_request_t *r) {
    bsd_free_addrinfo(r->result);
    bsd_free_addrinfo(r->source_result);
    free(r->host);
    free(r->source_host);
    us_internal_mutex_destroy(&r->mutex);
    free(r);
}

/* In-flight list, loop thread only. The loop is kept alive while the list is non-empty. */
static void us_internal_resolve_link(struct us_loop_t *loop, struct us_internal_resolve_request_t *r) {
    if (!loop->data.resolve_head) {
        us_internal_async_ref(loop->data.resolve_async);
    }
    r->prev = NULL;
    r->next = loop->data.resolve_head;
    if (r->next) {
        r->next->prev = r;
    }
    loop->data.resolve_head = r;
}

static void us_internal_resolve_unlink(struct us_loop_t *loop, struct us_internal_resolve_request_t *r) {
    if (r->prev) {
        r->prev->next = r->next;
    } else {
        loop->data.resolve_head = r->next;
    }
    if (r->next) {
        r->next->prev = r->prev;
    }
    r->prev = r->next = NULL;
    if (!loop->data.resolve_head) {
        us_internal_async_unref(loop->data.resolve_async);
    }
}

/* Resolver thread body: the only thing that ever blocks on the resolver */
static void us_internal_resolve_thread(struct us_internal_resolve_request_t *r) {
    r->error = bsd_resolve_connect_addr(r->host, r->port, 0, &r->result);

    /* A source host that does not resolve is ignored, as it always was */
    if (!r->error && r->source_host) {
        if (bsd_resolve_source_addr(r->source_host, 0, &r->source_result) != 0) {
            r->source_result = NULL;
        }
    }

    us_internal_mutex_lock(&r->mutex);
    if (r->cancelled) {
        /* The loop thread has forgotten about us; the request is ours to free */
        us_internal_mutex_unlock(&r->mutex);
        us_internal_resolve_free_request(r);
        return;
    }

    /* Publish the result and wake the loop. Both happen under the mutex so that a concurrent
     * cancellation (which takes the same mutex) either sees done set, or runs before the wakeup
     * and leaves the loop untouched by us */
    r->done = 1;
    us_internal_async_wakeup(r->loop->data.resolve_async);
    us_internal_mutex_unlock(&r->mutex);
}

#ifdef _WIN32
static unsigned __stdcall us_internal_resolve_thread_entry(void *arg) {
    us_internal_resolve_thread((struct us_internal_resolve_request_t *) arg);
    return 0;
}

static int us_internal_resolve_spawn(struct us_internal_resolve_request_t *r) {
    uintptr_t handle = _beginthreadex(NULL, 0, us_internal_resolve_thread_entry, r, 0, NULL);
    if (!handle) {
        return -1;
    }
    CloseHandle((HANDLE) handle);
    return 0;
}
#else
static void *us_internal_resolve_thread_entry(void *arg) {
    us_internal_resolve_thread((struct us_internal_resolve_request_t *) arg);
    return NULL;
}

static int us_internal_resolve_spawn(struct us_internal_resolve_request_t *r) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_t thread;
    int ret = pthread_create(&thread, &attr, us_internal_resolve_thread_entry, r);
    pthread_attr_destroy(&attr);
    return ret ? -1 : 0;
}
#endif

/* Finishes a connect whose lookup has completed (loop thread). The request is already unlinked. */
static void us_internal_resolve_complete(struct us_internal_resolve_request_t *r) {
    struct us_socket_t *s = r->socket;

    /* Cancellation unlinks the request, so the socket is still ours - but stay defensive */
    if (!s || us_socket_is_closed(0, s)) {
        return;
    }

    struct us_socket_context_t *context = s->context;

    /* A failed lookup is reported in its own code range, so it can never be mistaken for a
     * socket error (EAI_* values overlap errno values on some platforms) */
    int error = r->error ? LIBUS_CONNECT_ERROR_RESOLVE_BASE - (r->error < 0 ? -r->error : r->error) : 0;

    if (!error) {
        LIBUS_SOCKET_DESCRIPTOR fd = bsd_create_connect_socket_resolved(r->result, r->source_result, r->options, &error);
        if (fd != LIBUS_SOCKET_ERROR) {
            if (s->rx_timestamps) {
                bsd_socket_enable_rx_timestamps(fd);
            }

            /* Now we are a regular connecting socket, exactly like the synchronous path produces */
            us_poll_init(&s->p, fd, POLL_TYPE_SEMI_SOCKET);
            s->resolving = 0;
            us_poll_start(&s->p, context->loop, LIBUS_SOCKET_WRITABLE);
            return;
        }
    }

    /* Lookup or socket creation failed: emit the error and close without on_close, exactly like
     * a late connect failure. The handler may itself close the socket, which makes our close a no-op. */
    if (context->on_connect_error) {
        context->on_connect_error(s, error);
    }
    us_socket_close_connecting(0, s);
}

/* A lookup that could not even be started fails like any other connect error (loop thread) */
static void us_internal_resolve_fail(struct us_internal_resolve_request_t *r, int error) {
    struct us_socket_t *s = r->socket;
    us_internal_resolve_unlink(r->loop, r);
    us_internal_resolve_free_request(r);

    if (s && !us_socket_is_closed(0, s)) {
        if (s->context->on_connect_error) {
            s->context->on_connect_error(s, error);
        }
        us_socket_close_connecting(0, s);
    }
}

/* Starts queued lookups (oldest first) while there are resolver threads to spare */
static void us_internal_resolve_start_queued(struct us_loop_t *loop) {
    while (loop->data.resolve_running < LIBUS_MAX_RESOLVER_THREADS) {
        struct us_internal_resolve_request_t *oldest = NULL;
        for (struct us_internal_resolve_request_t *r = loop->data.resolve_head; r; r = r->next) {
            if (!r->spawned) {
                oldest = r;
            }
        }
        if (!oldest) {
            return;
        }

        oldest->spawned = 1;
        if (us_internal_resolve_spawn(oldest)) {
            /* Out of threads: the socket fails as a connect error, which the embedder may retry */
            us_internal_resolve_fail(oldest, EAGAIN);
        } else {
            loop->data.resolve_running++;
        }
    }
}

/* Woken by resolver threads; drains every completed lookup. Scanning from the head again after
 * each completion keeps us safe against callbacks closing other resolving sockets (which unlinks
 * and possibly frees their requests). */
static void us_internal_resolve_async_cb(struct us_loop_t *loop) {
    for (;;) {
        struct us_internal_resolve_request_t *completed = NULL;
        for (struct us_internal_resolve_request_t *r = loop->data.resolve_head; r; r = r->next) {
            if (!r->spawned) {
                continue;
            }
            us_internal_mutex_lock(&r->mutex);
            int done = r->done;
            us_internal_mutex_unlock(&r->mutex);
            if (done) {
                completed = r;
                break;
            }
        }

        if (!completed) {
            break;
        }

        /* Once done is set the resolver thread never touches the request again */
        us_internal_resolve_unlink(loop, completed);
        loop->data.resolve_running--;
        us_internal_resolve_complete(completed);
        us_internal_resolve_free_request(completed);
    }

    us_internal_resolve_start_queued(loop);
}

/* Forgets a request. If the resolver thread is still running it will free the request when
 * it finishes; otherwise we free it now. */
static void us_internal_resolve_cancel_request(struct us_loop_t *loop, struct us_internal_resolve_request_t *r) {
    us_internal_resolve_unlink(loop, r);

    /* Still waiting for a thread: nobody else knows about it */
    if (!r->spawned) {
        us_internal_resolve_free_request(r);
        return;
    }

    /* The thread (if still running) finishes on its own; it no longer counts towards the cap */
    loop->data.resolve_running--;

    us_internal_mutex_lock(&r->mutex);
    int done = r->done;
    r->cancelled = 1;
    r->socket = NULL;
    us_internal_mutex_unlock(&r->mutex);

    if (done) {
        us_internal_resolve_free_request(r);
    }

    /* A cancelled thread never wakes the loop, so the freed slot would otherwise go unused by
     * queued lookups until some other lookup completes. Wake the loop to start them on the next
     * iteration rather than here: we may be inside a user callback, and starting a lookup can
     * itself emit on_connect_error. */
    for (struct us_internal_resolve_request_t *queued = loop->data.resolve_head; queued; queued = queued->next) {
        if (!queued->spawned) {
            us_internal_async_wakeup(loop->data.resolve_async);
            break;
        }
    }
}

int us_internal_resolve_connect(struct us_socket_t *s, const char *host, int port, const char *source_host, int options) {
    struct us_loop_t *loop = s->context->loop;

    /* Created on first use, so loops that never connect by name pay nothing */
    if (!loop->data.resolve_async) {
        loop->data.resolve_async = us_internal_create_async(loop, 1, 0);
        if (!loop->data.resolve_async) {
            return -1;
        }
        us_internal_async_set(loop->data.resolve_async, (void (*)(struct us_internal_async *)) us_internal_resolve_async_cb);
    }

    struct us_internal_resolve_request_t *r = malloc(sizeof(struct us_internal_resolve_request_t));
    if (!r) {
        return -1;
    }

    r->socket = s;
    r->loop = loop;
    r->prev = r->next = NULL;
    r->spawned = 0;
    r->host = us_internal_strdup(host);
    r->source_host = us_internal_strdup(source_host);
    r->port = port;
    r->options = options;
    r->result = NULL;
    r->source_result = NULL;
    r->error = 0;
    r->done = 0;
    r->cancelled = 0;
    us_internal_mutex_init(&r->mutex);

    if ((host && !r->host) || (source_host && !r->source_host)) {
        us_internal_resolve_free_request(r);
        return -1;
    }

    us_internal_resolve_link(loop, r);

    /* Start it now if a thread is available, otherwise it waits for one to finish */
    if (loop->data.resolve_running < LIBUS_MAX_RESOLVER_THREADS) {
        r->spawned = 1;
        if (us_internal_resolve_spawn(r)) {
            us_internal_resolve_unlink(loop, r);
            us_internal_resolve_free_request(r);
            return -1;
        }
        loop->data.resolve_running++;
    }

    return 0;
}

/* Called when a resolving socket is closed: drop its lookup (if still in flight) */
void us_internal_resolve_cancel(struct us_socket_t *s) {
    struct us_loop_t *loop = s->context->loop;
    for (struct us_internal_resolve_request_t *r = loop->data.resolve_head; r; r = r->next) {
        if (r->socket == s) {
            us_internal_resolve_cancel_request(loop, r);
            return;
        }
    }
}

/* Called when a resolving socket was reallocated (socket adoption) */
void us_internal_resolve_socket_moved(struct us_socket_t *old_s, struct us_socket_t *new_s) {
    struct us_loop_t *loop = new_s->context->loop;
    for (struct us_internal_resolve_request_t *r = loop->data.resolve_head; r; r = r->next) {
        if (r->socket == old_s) {
            r->socket = new_s;
            return;
        }
    }
}

/* Called when the loop is freed: in-flight lookups are dropped, their sockets are the embedder's
 * (they are treated like any other socket left in a freed loop) */
void us_internal_resolve_loop_free(struct us_loop_t *loop) {
    while (loop->data.resolve_head) {
        us_internal_resolve_cancel_request(loop, loop->data.resolve_head);
    }

    if (loop->data.resolve_async) {
        us_internal_async_close(loop->data.resolve_async);
        loop->data.resolve_async = NULL;
    }
}

#endif
