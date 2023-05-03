#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

// TODO: move these structs into mcmc.h, but only expose them if
// MCMC_EXPOSE_INTERNALS is defined... for tests and this thing.
#include "mcmc.h"

// TODO: if there's a parse error or unknown status code, we likely have a
// protocol desync and need to disconnect.

// NOTE: this _will_ change a bit for adding TLS support.

// A "reasonable" minimum buffer size to work with.
// Callers are allowed to create a buffer of any size larger than this.
// TODO: Put the math/documentation in here.
// This is essentially the largest return value status line possible.
// at least doubled for wiggle room.
#define MIN_BUFFER_SIZE 2048

#define FLAG_BUF_WANTED_READ 0x4

#define STATE_DEFAULT 0 // looking for any kind of response
#define STATE_GET_RESP 1 // processing VALUE's until END
#define STATE_STAT_RESP 2 // processing STAT's until END
#define STATE_STAT_RESP_DONE 3

typedef struct mcmc_ctx {
    int fd;
    int gai_status; // getaddrinfo() last status.
    int last_sys_error; // last syscall error (connect/etc?)
    int sent_bytes_partial; // note for partially sent buffers.
    int fail_code; // recent failure reason.
    int error; // latest error code.
    uint32_t status_flags; // internal only flags.
    int state;

    // FIXME: s/buffer_used/buffer_filled/ ?
    size_t buffer_used; // amount of bytes read into the buffer so far.
    size_t buffer_request_len; // cached endpoint for current request
    char *buffer_head; // buffer pointer currently in use.
} mcmc_ctx_t;

// INTERNAL FUNCTIONS

static int _mcmc_parse_value_line(mcmc_ctx_t *ctx, mcmc_resp_t *r) {
    char *buf = ctx->buffer_head;
    // we know that "VALUE " has matched, so skip that.
    char *p = buf+6;
    size_t l = ctx->buffer_request_len;

    // <key> <flags> <bytes> [<cas unique>]
    char *key = p;
    int keylen;
    p = memchr(p, ' ', l - 6);
    if (p == NULL) {
        return -MCMC_ERR_VALUE;
    }

    keylen = p - key;

    // convert flags into something useful.
    // FIXME: do we need to prevent overruns in strtoul?
    // we know for sure the line will eventually end in a \n.
    char *n = NULL;
    errno = 0;
    uint32_t flags = strtoul(p, &n, 10);
    if ((errno == ERANGE) || (p == n) || (*n != ' ')) {
        return -MCMC_ERR_VALUE;
    }
    p = n;

    errno = 0;
    uint32_t bytes = strtoul(p, &n, 10);
    if ((errno == ERANGE) || (p == n)) {
        return -MCMC_ERR_VALUE;
    }
    p = n;

    // If next byte is a space, we read the optional CAS value.
    uint64_t cas = 0;
    if (*n == ' ') {
        errno = 0;
        cas = strtoull(p, &n, 10);
        if ((errno == ERANGE) || (p == n)) {
            return -MCMC_ERR_VALUE;
        }
    }

    // If we made it this far, we've parsed everything, stuff the details into
    // the context for fetching later.
    r->vlen = bytes + 2; // add in the \r\n
    int buffer_remain = ctx->buffer_used - (r->value - ctx->buffer_head);
    if (buffer_remain >= r->vlen) {
        r->vlen_read = r->vlen;
    } else {
        r->vlen_read = buffer_remain;
    }
    r->key = key;
    r->klen = keylen;
    r->flags = flags;
    r->cas = cas;
    r->type = MCMC_RESP_GET;
    ctx->state = STATE_GET_RESP;

    // NOTE: if value_offset < buffer_used, has part of the value in the
    // buffer already.

    return MCMC_CODE_OK;
}

static int _mcmc_parse_stat_line(mcmc_ctx_t *ctx, mcmc_resp_t *r) {
    char *buf = ctx->buffer_head;
    char *p = buf+5; // pass "STAT "
    size_t l = ctx->buffer_request_len;

    // STAT key value
    char *sname = p;
    p = memchr(p, ' ', l-5);
    if (p == NULL) {
        return -MCMC_ERR_VALUE;
    }

    int snamelen = p - sname;
    while (*p == ' ') {
        p++;
    }
    char *stat = p;
    int statlen = l - (p - ctx->buffer_head) - 2;

    r->sname = sname;
    r->snamelen = snamelen;
    r->stat = stat;
    r->statlen = statlen;

    return MCMC_CODE_OK;
}

// FIXME: This is broken for ASCII multiget.
// if we get VALUE back, we need to stay in ASCII GET read mode until an END
// is seen.
static int _mcmc_parse_response(mcmc_ctx_t *ctx, mcmc_resp_t *r) {
    char *buf = ctx->buffer_head;
    char *cur = buf;
    size_t l = ctx->buffer_request_len;
    int rlen; // response code length.
    int more = 0;
    r->reslen = ctx->buffer_request_len;
    r->type = MCMC_RESP_FAIL;

    // walk until the \r\n
    while (l-- > 2) {
        if (*cur == ' ') {
            more = 1;
            break;
        }
        cur++;
    }
    rlen = cur - buf;

    // incr/decr returns a number with no code :(
    // not checking length first since buf must have at least one char to
    // enter this function.
    if (buf[0] >= '0' && buf[0] <= '9') {
        // TODO: parse it as a number on request.
        // TODO: validate whole thing as digits here?
        r->type = MCMC_RESP_NUMERIC;
        r->code = MCMC_CODE_OK;
        return MCMC_OK;
    }

    if (rlen < 2) {
        r->code = MCMC_ERR_SHORT;
        return MCMC_ERR;
    }

    int code = MCMC_ERR;
    switch (rlen) {
        case 2:
            // meta, "OK"
            // FIXME: adding new return codes would make the client completely
            // fail. The rest of the client is agnostic to requests/flags for
            // meta.
            // can we make it agnostic for return codes outside of "read this
            // data" types?
            // As-is it should fail down to the "send the return code to the
            // user". not sure that's right.
            r->type = MCMC_RESP_META;
            switch (buf[0]) {
            case 'E':
                if (buf[1] == 'N') {
                    code = MCMC_CODE_END;
                } else if (buf[1] == 'X') {
                    code = MCMC_CODE_EXISTS;
                }
                break;
            case 'H':
                if (buf[1] == 'D') {
                    // typical meta response.
                    code = MCMC_CODE_OK;
                }
                break;
            case 'M':
                if (buf[1] == 'N') {
                    // specific return code so user can see pipeline end.
                    code = MCMC_CODE_NOP;
                } else if (buf[1] == 'E') {
                    // ME is the debug output line.
                    // TODO: this just gets returned as an rline?
                    // specific code? specific type?
                    // ME <key> <key=value debug line>
                    code = MCMC_CODE_OK;
                }
                break;
            case 'N':
                if (buf[1] == 'F') {
                    code = MCMC_CODE_NOT_FOUND;
                } else if (buf[1] == 'S') {
                    code = MCMC_CODE_NOT_STORED;
                }
                break;
            case 'O':
                if (buf[1] == 'K') {
                    // Used by many random management commands
                    r->type = MCMC_RESP_GENERIC;
                    code = MCMC_CODE_OK;
                }
                break;
            case 'V':
                if (buf[1] == 'A') {
                    // VA <size> <flags>*\r\n
                    if (more) {
                        errno = 0;
                        char *n = NULL;
                        uint32_t vsize = strtoul(cur, &n, 10);
                        if ((errno == ERANGE) || (cur == n)) {
                            r->type = MCMC_RESP_FAIL;
                            code = -MCMC_ERR_PARSE;
                        } else {
                            r->vlen = vsize + 2; // tag in the \r\n.
                            // FIXME: macro.
                            int buffer_remain = ctx->buffer_used - (r->value - ctx->buffer_head);
                            if (buffer_remain >= r->vlen) {
                                r->vlen_read = r->vlen;
                            } else {
                                r->vlen_read = buffer_remain;
                            }
                            cur = n;
                            if (*cur != ' ') {
                                more = 0;
                            }
                            code = MCMC_CODE_OK;
                        }
                    } else {
                        r->type = MCMC_RESP_FAIL;
                        code = -MCMC_ERR_PARSE;
                    }
                }
                break;
            }
            // maybe: if !rv and !fail, do something special?
            // if (more), there are flags. shove them in the right place.
            if (more) {
                r->rline = cur+1; // eat the space.
                r->rlen = l-1;
            } else {
                r->rline = NULL;
                r->rlen = 0;
            }
            break;
        case 3:
            if (memcmp(buf, "END", 3) == 0) {
                // Either end of STAT results, or end of ascii GET key list.
                ctx->state = STATE_DEFAULT;
                code = MCMC_CODE_END;
                r->type = MCMC_RESP_END;
            }
            break;
        case 4:
            if (memcmp(buf, "STAT", 4) == 0) {
                r->type = MCMC_RESP_STAT;
                ctx->state = STATE_STAT_RESP;
                code = _mcmc_parse_stat_line(ctx, r);
            }
            break;
        case 5:
            if (memcmp(buf, "VALUE", 5) == 0) {
                if (more) {
                    // <key> <flags> <bytes> [<cas unique>]
                    code = _mcmc_parse_value_line(ctx, r);
                } else {
                    code = -MCMC_ERR_PARSE;
                }
            } else if (memcmp(buf, "ERROR", 5) == 0) {
                r->type = MCMC_RESP_ERRMSG;
                code = -MCMC_CODE_ERROR;
            }
            break;
        case 6:
            if (memcmp(buf, "STORED", 6) == 0) {
                r->type = MCMC_RESP_GENERIC;
                code = MCMC_CODE_STORED;
            } else if (memcmp(buf, "EXISTS", 6) == 0) {
                r->type = MCMC_RESP_GENERIC;
                code = MCMC_CODE_EXISTS;
                // TODO: type -> ASCII?
            }
            break;
        case 7:
            if (memcmp(buf, "DELETED", 7) == 0) {
                r->type = MCMC_RESP_GENERIC;
                code = MCMC_CODE_DELETED;
            } else if (memcmp(buf, "TOUCHED", 7) == 0) {
                r->type = MCMC_RESP_GENERIC;
                code = MCMC_CODE_TOUCHED;
            } else if (memcmp(buf, "VERSION", 7) == 0) {
                code = MCMC_CODE_VERSION;
                r->type = MCMC_RESP_VERSION;
                // TODO: prep the version line for return
            }
            break;
        case 9:
            if (memcmp(buf, "NOT_FOUND", 9) == 0) {
                r->type = MCMC_RESP_GENERIC;
                code = MCMC_CODE_NOT_FOUND;
            }
            break;
        case 10:
            if (memcmp(buf, "NOT_STORED", 10) == 0) {
                r->type = MCMC_RESP_GENERIC;
                code = MCMC_CODE_NOT_STORED;
            }
            break;
        default:
            // Unknown code, assume error.
            if (memcmp(buf, "SERVER_ERROR", 12) == 0) {
                r->type = MCMC_RESP_ERRMSG;
                code = -MCMC_CODE_SERVER_ERROR;
            } else if (memcmp(buf, "CLIENT_ERROR", 12) == 0) {
                r->type = MCMC_RESP_ERRMSG;
                code = -MCMC_CODE_CLIENT_ERROR;
            }
            break;
    }

    if (code < MCMC_OK) {
        r->code = -code;
        return MCMC_ERR;
    } else {
        r->code = code;
        return MCMC_OK;
    }
}

// EXTERNAL API

int mcmc_fd(void *c) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;
    return ctx->fd;
}

size_t mcmc_size(int options) {
    return sizeof(mcmc_ctx_t);
}

// Allow returning this dynamically based on options set.
// FIXME: it might be more flexible to call this after mcmc_connect()...
// but this is probably more convenient for the caller if it's less dynamic.
size_t mcmc_min_buffer_size(int options) {
    return MIN_BUFFER_SIZE;
}

// Directly parse a buffer with read data of size len.
// r->reslen + r->vlen_read is the bytes consumed from the buffer read.
// Caller manages how to retry if MCMC_WANT_READ or an error happens.
// FIXME: not sure if to keep this command to a fixed buffer size, or continue
// to use the ctx->buffer_used bits... if we keep the buffer_used stuff caller can
// loop without memmove'ing the buffer?
int mcmc_parse_buf(void *c, char *buf, size_t read, mcmc_resp_t *r) {
    mcmc_ctx_t *ctx = c;
    char *el;

    memset(r, 0, sizeof(*r));
    el = memchr(buf, '\n', read);
    if (el == NULL) {
        r->code = MCMC_WANT_READ;
        return MCMC_ERR;
    }

    // Consume through the newline, note where the value would start if exists
    r->value = el+1;

    ctx->buffer_used = read;
    // FIXME: the server must be stricter in what it sends back. should always
    // have a \r. check for it and fail?
    ctx->buffer_request_len = r->value - buf;
    // leave the \r\n in the line end cache.
    ctx->buffer_head = buf;

    return _mcmc_parse_response(ctx, r);
}

int mcmc_bare_parse_buf(char *buf, size_t read, mcmc_resp_t *r) {
    mcmc_ctx_t ctx;
    return mcmc_parse_buf(&ctx, buf, read, r);
}

/*** Functions wrapping syscalls **/

// TODO: should be able to flip between block and nonblock.

// used for checking on async connections.
int mcmc_check_nonblock_connect(void *c, int *err) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;
    socklen_t errsize = sizeof(*err);
    if (getsockopt(ctx->fd, SOL_SOCKET, SO_ERROR, err, &errsize) == 0) {
        if (*err == 0) {
            return MCMC_OK;
        }
    } else {
        // getsockopt failed. still need to pass up the error.
        *err = errno;
    }

    return MCMC_ERR;
}

// TODO:
// - option for connecting 4 -> 6 or 6 -> 4
// connect_unix()
// connect_bind_tcp()
// ^ fill an internal struct from the stack and call into this central
// connect?
int mcmc_connect(void *c, char *host, char *port, int options) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;

    int s;
    int sock;
    int res = MCMC_CONNECTED;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *next;

    // Since our cx memory was likely malloc'ed, ensure we start clear.
    memset(ctx, 0, sizeof(mcmc_ctx_t));
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    ctx->fd = 0;

    s = getaddrinfo(host, port, &hints, &ai);

    if (s != 0) {
        hints.ai_family = AF_INET6;
        s = getaddrinfo(host, port, &hints, &ai);
        if (s != 0) {
            // TODO: gai_strerror(s)
            ctx->gai_status = s;
            res = MCMC_ERR;
            goto end;
        }
    }

    for (next = ai; next != NULL; next = next->ai_next) {
        sock = socket(next->ai_family, next->ai_socktype,
                next->ai_protocol);
        if (sock == -1)
            continue;

        if (options & MCMC_OPTION_TCP_KEEPALIVE) {
            int optval = 1;
            if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
                res = MCMC_ERR;
                close(sock);
                goto end;
            }
        }

        if (options & MCMC_OPTION_NONBLOCK) {
            int flags = fcntl(sock, F_GETFL);
            if (flags < 0) {
                res = MCMC_ERR;
                close(sock);
                goto end;
            }
            if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                res = MCMC_ERR;
                close(sock);
                goto end;
            }
            res = MCMC_CONNECTING;

            if (connect(sock, next->ai_addr, next->ai_addrlen) != -1) {
                if (errno == EINPROGRESS) {
                    break; // We're good, stop the loop.
                }
            }

            break;
        } else {
            // TODO: BIND local port.
            if (connect(sock, next->ai_addr, next->ai_addrlen) != -1)
                break;
        }

        close(sock);
    }

    // TODO: cache last connect status code?
    if (next == NULL) {
        res = MCMC_ERR;
        goto end;
    }

    ctx->fd = sock;
end:
    if (ai) {
        freeaddrinfo(ai);
    }
    return res;
}

// NOTE: if WANT_WRITE returned, call with same arguments.
// FIXME: len -> size_t?
// TODO: rename to mcmc_request_send
int mcmc_send_request(void *c, const char *request, int len, int count) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;

    // adjust our send buffer by how much has already been sent.
    const char *r = request + ctx->sent_bytes_partial;
    int l = len - ctx->sent_bytes_partial;
    int sent = send(ctx->fd, r, l, 0);
    if (sent == -1) {
        // implicitly handle nonblock mode.
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MCMC_WANT_WRITE;
        } else {
            return MCMC_ERR;
        }
    }

    if (sent < len) {
        // can happen anytime, but mostly in nonblocking mode.
        ctx->sent_bytes_partial += sent;
        return MCMC_WANT_WRITE;
    } else {
        ctx->sent_bytes_partial = 0;
    }

    return MCMC_OK;
}

// TODO: pretty sure I don't want this function chewing on a submitted iov
// stack, but it might make for less client code :(
// so for now, lets not.
int mcmc_request_writev(void *c, const struct iovec *iov, int iovcnt, ssize_t *sent, int count) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;
    // need to track sent vs tosend to know when to update counters.
    ssize_t tosend = 0;
    for (int i = 0; i < iovcnt; i++) {
        tosend += iov[i].iov_len;
    }

    *sent = writev(ctx->fd, iov, iovcnt);
    if (*sent == -1) {
        // implicitly handle nonblock mode.
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MCMC_WANT_WRITE;
        } else {
            return MCMC_ERR;
        }
    }

    if (*sent < tosend) {
        // can happen anytime, but mostly in nonblocking mode.
        return MCMC_WANT_WRITE;
    }

    return MCMC_OK;
}

// TODO: return consumed bytes and end ptr?
// FIXME: mcmc no longer tracks the buffer inbetween commands, which was
// causing issues with the API and bugs.
// This function wraps the recv call, so it needs to understand the buffer a
// little bit. Since memcached doesn't currently use this function I'm
// commenting it out with this note so it can be rewritten in terms of an
// external buffer later.
/*
int mcmc_read(void *c, char *buf, size_t bufsize, mcmc_resp_t *r) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;
    char *el;
    memset(r, 0, sizeof(*r));

    // If there's still data in the buffer try to use it before potentially
    // hanging on the network read.
    // Also skip this check if we specifically wanted more bytes from net.
    if (ctx->buffer_used && !(ctx->status_flags & FLAG_BUF_WANTED_READ)) {
        el = memchr(buf, '\n', ctx->buffer_used);
        if (el) {
            goto parse;
        }
    }

    // adjust buffer by how far we've already consumed.
    char *b = buf + ctx->buffer_used;
    size_t l = bufsize - ctx->buffer_used;

    int read = recv(ctx->fd, b, l, 0);
    if (read == 0) {
        return MCMC_NOT_CONNECTED;
    } else if (read == -1) {
        // implicitly handle nonblocking configurations.
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MCMC_WANT_READ;
        } else {
            return MCMC_ERR;
        }
    }

    ctx->buffer_used += read;

    // Always scan from the start of the original buffer.
    el = memchr(buf, '\n', ctx->buffer_used);
    if (!el) {
        // FIXME: error if buffer is full but no \n is found.
        ctx->status_flags |= FLAG_BUF_WANTED_READ;
        return MCMC_WANT_READ;
    }
parse:
    // Consume through the newline.
    r->value = el+1;

    // FIXME: the server must be stricter in what it sends back. should always
    // have a \r. check for it and fail?
    ctx->buffer_request_len = r->value - buf;
    // leave the \r\n in the line end cache.
    ctx->buffer_head = buf;
    // TODO: handling for nonblock case.

    // We have a result line. Now pass it through the parser.
    // Then we indicate to the user that a response is ready.
    return _mcmc_parse_response(ctx, r);
}
*/

void mcmc_get_error(void *c, char *code, size_t clen, char *msg, size_t mlen) {
    code[0] = '\0';
    msg[0] = '\0';
}

// read into the buffer, up to a max size of vsize.
// will read (vsize-read) into the buffer pointed to by (val+read).
// you are able to stream the value into different buffers, or process the
// value and reuse the same buffer, by adjusting vsize and *read between
// calls.
// vsize must not be larger than the remaining value size pending read.
/* TODO: see notes on mcmc_read()
int mcmc_read_value(void *c, char *val, mcmc_resp_t *r, int *read) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;
    size_t l;

    // If the distance between tail/head is smaller than what we read into the
    // main buffer, we have some value to copy out.
    size_t vsize = r->vlen;
    if (*read < r->vlen_read) {
        memcpy(val + *read, r->value, r->vlen_read);
        *read += r->vlen_read;
        if (r->vlen_read >= r->vlen) {
            return MCMC_OK;
        }
    }

    char *v = val + *read;
    l = vsize - *read;

    int rd = recv(ctx->fd, v, l, 0);
    if (rd == 0) {
        // TODO: some internal disconnect work?
        return MCMC_NOT_CONNECTED;
    }
    // FIXME: EAGAIN || EWOULDBLOCK!
    if (rd == -1) {
        return MCMC_ERR;
    }

    *read += rd;

    if (*read < vsize) {
        return MCMC_WANT_READ;
    } else {
        return MCMC_OK;
    }
}
*/

int mcmc_disconnect(void *c) {
    mcmc_ctx_t *ctx = (mcmc_ctx_t *)c;

    // FIXME: I forget if 0 can be valid.
    if (ctx->fd != 0) {
        close(ctx->fd);
        ctx->fd = 0;
        return MCMC_OK;
    } else {
        return MCMC_NOT_CONNECTED;
    }
}
