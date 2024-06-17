/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"
#include "proxy_tls.h"
#ifdef PROXY_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Notes on ERR_clear_error() and friends:
 * - Errors from SSL calls leave errors on a thread-local "error stack"
 * - If an error is received from an SSL call, the stack needs to be inspected
 *   and cleared.
 * - The error stack _must_ be clear before any SSL_get_error() calls, as it
 *   may return garbage.
 * - There may be _multiple_ errors queued after one SSL call, so just
 *   checking the top level does not clear it.
 * - ERR_clear_error() is not "free", so we would prefer to avoid calling it
 *   before hotpath calls. Thus, we should ensure it's called _after_ any
 *   hotpath call that receives any kind of error.
 * - We should also call it _before_ any non-hotpath SSL calls (such as
 *   SSL_connect()) for defense against bugs in our code or OpenSSL.
 */

int mcp_tls_init(proxy_ctx_t *ctx) {
    if (ctx->tls_ctx) {
        return MCP_TLS_OK;
    }

    // TODO: check for OpenSSL 1.1+ ? should be elsewhere in the code.
    SSL_CTX *tctx = SSL_CTX_new(TLS_client_method());
    if (tctx == NULL) {
        return MCP_TLS_ERR;
    }

    // TODO: make configurable like main cache server
    SSL_CTX_set_min_proto_version(tctx, TLS1_3_VERSION);
    // reduce memory consumption of idle backends.
    SSL_CTX_set_mode(tctx, SSL_MODE_RELEASE_BUFFERS);

    ctx->tls_ctx = tctx;
    return 0;
}

int mcp_tls_backend_init(proxy_ctx_t *ctx, struct mcp_backendconn_s *be) {
    if (!be->be_parent->tunables.use_tls) {
        return MCP_TLS_OK;
    }

    SSL *ssl = SSL_new(ctx->tls_ctx);
    if (ssl == NULL) {
        return MCP_TLS_ERR;
    }

    be->ssl = ssl;
    // SSL_set_fd() will free a pre-existing BIO and allocate a new one
    // so we set any file descriptor at connect time instead.

    return MCP_TLS_OK;
}

int mcp_tls_shutdown(struct mcp_backendconn_s *be) {
    if (!be->ssl) {
        return MCP_TLS_OK;
    }

    // TODO: This may need to be called multiple times to "properly" shutdown
    // a session. However we only ever call this when a backend is dead or not
    // in used anymore. Unclear if checking for WANT_READ|WRITE is worth
    // doing.
    SSL_shutdown(be->ssl);

    return MCP_TLS_OK;
}

int mcp_tls_cleanup(struct mcp_backendconn_s *be) {
    if (!be->ssl) {
        return MCP_TLS_OK;
    }

    SSL_free(be->ssl);
    be->ssl = NULL;
    return MCP_TLS_OK;
}

// Contrary to the name of this function, the underlying tcp socket must
// already be connected.
int mcp_tls_connect(struct mcp_backendconn_s *be) {
    // TODO: check return code. can fail if BIO fails to alloc.
    SSL_set_fd(be->ssl, mcmc_fd(be->client));

    // TODO:
    // if the backend is changing TLS version or some similar issue, we will
    // be unable to reconnect as the SSL object "Caches" some information
    // about the previous request (why doesn't clear work then???)
    // This will normally be fine, but we should detect severe errors here and
    // decide if we should free and re-alloc the SSL object.
    // Allocating the SSL object can be pretty slow, so we should at least
    // attempt to do not do this.
    // Related: https://github.com/openssl/openssl/issues/20286
    SSL_clear(be->ssl);
    ERR_clear_error();
    int n = SSL_connect(be->ssl);
    int ret = MCP_TLS_OK;
    // TODO: complete error handling.
    if (n == 1) {
        // Successfully established and handshake complete.
        return ret;
    }

    int err = SSL_get_error(be->ssl, n);
    if (n == 0) {
        // Not successsful, but shut down normally.
        ERR_clear_error();
        ret = MCP_TLS_ERR;
    } else if (n < 0) {
        // Not successful. Check for temporary error.
        if (err == SSL_ERROR_WANT_READ ||
            err == SSL_ERROR_WANT_WRITE) {
            ret = MCP_TLS_OK;
        } else {
            ret = MCP_TLS_ERR;
        }
        ERR_clear_error();
    }

    return ret;
}

int mcp_tls_handshake(struct mcp_backendconn_s *be) {
    if (SSL_is_init_finished(be->ssl)) {
        return MCP_TLS_OK;
    }

    // Non hot path, so clear errors before running.
    ERR_clear_error();
    int n = SSL_do_handshake(be->ssl);
    if (n == 1) {
        return MCP_TLS_OK;
    }

    int err = SSL_get_error(be->ssl, n);
    // TODO: realistically we'll only ever get WANT_READ here, since OpenSSL
    // is handling the fd and it will have written a small number of bytes.
    // leaving this note just in case.
    if (err == SSL_ERROR_WANT_READ ||
        err == SSL_ERROR_WANT_WRITE) {
        // So far as I can tell there would be an error on the queue here.
        ERR_clear_error();
        return MCP_TLS_NEEDIO;
    } else {
        // TODO: can get the full error message and give to the caller to log
        // to proxyevents?
        ERR_clear_error();
        return MCP_TLS_ERR;
    }
}

int mcp_tls_send_validate(struct mcp_backendconn_s *be) {
    const char *str = "version\r\n";
    const size_t len = strlen(str);

    // Non hot path, clear errors.
    ERR_clear_error();
    int n = SSL_write(be->ssl, str, len);

    // TODO: more detailed error checking.
    if (n < 0 || n != len) {
        ERR_clear_error();
        return MCP_TLS_ERR;
    }

    return MCP_TLS_OK;
}

int mcp_tls_read(struct mcp_backendconn_s *be) {
    int n = SSL_read(be->ssl, be->rbuf + be->rbufused, READ_BUFFER_SIZE - be->rbufused);

    if (n < 0) {
        int err = SSL_get_error(be->ssl, n);
        if (err == SSL_ERROR_WANT_WRITE ||
            err == SSL_ERROR_WANT_READ) {
            ERR_clear_error();
            return MCP_TLS_NEEDIO;
        } else {
            // TODO: log detailed error.
            ERR_clear_error();
            return MCP_TLS_ERR;
        }
    } else {
        be->rbufused += n;
        return n;
    }

    return 0;
}

// TODO: option.
#define TLS_WBUF_SIZE 16 * 1024

// We cache the temporary write buffer on the be's event thread.
// This is actually required when retrying ops (WANT_WRITE/etc) unless
// MOVING_BUFFERS flag is set in OpenSSL.
int mcp_tls_writev(struct mcp_backendconn_s *be, int iovcnt) {
    proxy_event_thread_t *et = be->event_thread;
    // TODO: move this to event thread init to remove branch and move error
    // handling to startup time.
    // Actually we won't know if TLS is in use until a backend shows up and
    // tries to write... so I'm not sure where to move this. TLS compiled in
    // but not used would waste memory.
    // Maybe can at least mark it unlikely()?
    if (et->tls_wbuf_size == 0) {
        et->tls_wbuf_size = TLS_WBUF_SIZE;
        et->tls_wbuf = malloc(et->tls_wbuf_size);
        if (et->tls_wbuf == NULL) {
            return MCP_TLS_ERR;
        }
    }
    size_t remain = et->tls_wbuf_size;
    char *b = et->tls_wbuf;

    // OpenSSL has no writev or TCP_CORK equivalent, so we have to pre-mempcy
    // the iov's here.
    for (int i = 0; i < iovcnt; i++) {
        size_t len = be->write_iovs[i].iov_len;
        size_t to_copy = len < remain ? len : remain;

        memcpy(b, (char *)be->write_iovs[i].iov_base, to_copy);
        remain -= to_copy;
        b += to_copy;
        if (remain == 0)
            break;
    }

    int n = SSL_write(be->ssl, et->tls_wbuf, b - et->tls_wbuf);
    if (n < 0) {
        int err = SSL_get_error(be->ssl, n);
        if (err == SSL_ERROR_WANT_WRITE ||
            err == SSL_ERROR_WANT_READ) {
            ERR_clear_error();
            return MCP_TLS_NEEDIO;
        }
        ERR_clear_error();
        return MCP_TLS_ERR;
    }

    return n;
}

#else // PROXY_TLS

int mcp_tls_writev(struct mcp_backendconn_s *be, int iovcnt) {
    (void)be;
    (void)iovcnt;
    return 0;
}

#endif // PROXY_TLS
