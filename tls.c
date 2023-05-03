#include "memcached.h"

#ifdef TLS

#include "tls.h"
#include <string.h>
#include <sysexits.h>
#include <sys/param.h>
#include <openssl/err.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif

static pthread_mutex_t ssl_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

const unsigned ERROR_MSG_SIZE = 64;
const size_t SSL_ERROR_MSG_SIZE = 256;

void SSL_LOCK() {
    pthread_mutex_lock(&(ssl_ctx_lock));
}

void SSL_UNLOCK(void) {
    pthread_mutex_unlock(&(ssl_ctx_lock));
}

/*
 * Reads decrypted data from the underlying BIO read buffers,
 * which reads from the socket.
 */
ssize_t ssl_read(conn *c, void *buf, size_t count) {
    assert (c != NULL);
    /* TODO : document the state machine interactions for SSL_read with
        non-blocking sockets/ SSL re-negotiations
    */
    return SSL_read(c->ssl, buf, count);
}

/*
 * SSL sendmsg implementation. Perform a SSL_write.
 */
ssize_t ssl_sendmsg(conn *c, struct msghdr *msg, int flags) {
    assert (c != NULL);
    size_t buf_remain = settings.ssl_wbuf_size;
    size_t bytes = 0;
    size_t to_copy;
    int i;

    // ssl_wbuf is pointing to the buffer allocated in the worker thread.
    assert(c->ssl_wbuf);
    // TODO: allocate a fix buffer in crawler/logger if they start using
    // the sendmsg method. Also, set c->ssl_wbuf  when the side thread
    // start owning the connection and reset the pointer in
    // conn_worker_readd.
    // Currently this connection would not be served by a different thread
    // than the one it's assigned.
    assert(pthread_equal(c->thread->thread_id, pthread_self()) != 0);

    char *bp = c->ssl_wbuf;
    for (i = 0; i < msg->msg_iovlen; i++) {
        size_t len = msg->msg_iov[i].iov_len;
        to_copy = len < buf_remain ? len : buf_remain;

        memcpy(bp + bytes, (void*)msg->msg_iov[i].iov_base, to_copy);
        buf_remain -= to_copy;
        bytes += to_copy;
        if (buf_remain == 0)
            break;
    }
    /* TODO : document the state machine interactions for SSL_write with
        non-blocking sockets/ SSL re-negotiations
    */
    return SSL_write(c->ssl, c->ssl_wbuf, bytes);
}

/*
 * Writes data to the underlying BIO write buffers,
 * which encrypt and write them to the socket.
 */
ssize_t ssl_write(conn *c, void *buf, size_t count) {
    assert (c != NULL);
    return SSL_write(c->ssl, buf, count);
}

/*
 * Prints an SSL error into the buff, if there's any.
 */
static void print_ssl_error(char *buff, size_t len) {
    unsigned long err;
    if ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buff, len);
    }
}

/*
 * Loads server certificates to the SSL context and validate them.
 * @return whether certificates are successfully loaded and verified or not.
 * @param error_msg contains the error when unsuccessful.
 */
static bool load_server_certificates(char **errmsg) {
    bool success = false;

    const size_t CRLF_NULLCHAR_LEN = 3;
    char *error_msg = malloc(MAXPATHLEN + ERROR_MSG_SIZE +
        SSL_ERROR_MSG_SIZE);
    size_t errmax = MAXPATHLEN + ERROR_MSG_SIZE + SSL_ERROR_MSG_SIZE -
        CRLF_NULLCHAR_LEN;

    if (error_msg == NULL) {
        *errmsg = NULL;
        return false;
    }

    if (settings.ssl_ctx == NULL) {
        snprintf(error_msg, errmax, "Error TLS not enabled\r\n");
        *errmsg = error_msg;
        return false;
    }

    char *ssl_err_msg = malloc(SSL_ERROR_MSG_SIZE);
    if (ssl_err_msg == NULL) {
        free(error_msg);
        *errmsg = NULL;
        return false;
    }
    bzero(ssl_err_msg, SSL_ERROR_MSG_SIZE);
    size_t err_msg_size = 0;

    SSL_LOCK();
    if (!SSL_CTX_use_certificate_chain_file(settings.ssl_ctx,
        settings.ssl_chain_cert)) {
        print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
        err_msg_size = snprintf(error_msg, errmax, "Error loading the certificate chain: "
            "%s : %s", settings.ssl_chain_cert, ssl_err_msg);
    } else if (!SSL_CTX_use_PrivateKey_file(settings.ssl_ctx, settings.ssl_key,
                                        settings.ssl_keyformat)) {
        print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
        err_msg_size = snprintf(error_msg, errmax, "Error loading the key: %s : %s",
            settings.ssl_key, ssl_err_msg);
    } else if (!SSL_CTX_check_private_key(settings.ssl_ctx)) {
        print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
        err_msg_size = snprintf(error_msg, errmax, "Error validating the certificate: %s",
            ssl_err_msg);
    } else if (settings.ssl_ca_cert) {
        if (!SSL_CTX_load_verify_locations(settings.ssl_ctx,
          settings.ssl_ca_cert, NULL)) {
            print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
            err_msg_size = snprintf(error_msg, errmax,
              "Error loading the CA certificate: %s : %s",
              settings.ssl_ca_cert, ssl_err_msg);
        } else {
            SSL_CTX_set_client_CA_list(settings.ssl_ctx,
              SSL_load_client_CA_file(settings.ssl_ca_cert));
            success = true;
        }
    } else {
        success = true;
    }
    SSL_UNLOCK();
    free(ssl_err_msg);
    if (success) {
        settings.ssl_last_cert_refresh_time = current_time;
        free(error_msg);
    } else {
        *errmsg = error_msg;
        error_msg += (err_msg_size >= errmax ? errmax - 1: err_msg_size);
        snprintf(error_msg, CRLF_NULLCHAR_LEN, "\r\n");
        // Print if there are more errors and drain the queue.
        ERR_print_errors_fp(stderr);
    }
    return success;
}

/*
 * Verify SSL settings and initiates the SSL context.
 */
int ssl_init(void) {
    assert(settings.ssl_enabled);

    // SSL context for the process. All connections will share one
    // process level context.
    settings.ssl_ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_set_min_proto_version(settings.ssl_ctx, settings.ssl_min_version);

    // The server certificate, private key and validations.
    char *error_msg;
    if (!load_server_certificates(&error_msg)) {
        fprintf(stderr, "%s", error_msg);
        free(error_msg);
        exit(EX_USAGE);
    }

    // The verification mode of client certificate, default is SSL_VERIFY_PEER.
    SSL_CTX_set_verify(settings.ssl_ctx, settings.ssl_verify_mode, NULL);
    if (settings.ssl_ciphers && !SSL_CTX_set_cipher_list(settings.ssl_ctx,
                                                    settings.ssl_ciphers)) {
        fprintf(stderr, "Error setting the provided cipher(s): %s\n",
                settings.ssl_ciphers);
        exit(EX_USAGE);
    }

    // Optional session caching; default disabled.
    if (settings.ssl_session_cache) {
        SSL_CTX_sess_set_new_cb(settings.ssl_ctx, ssl_new_session_callback);
        SSL_CTX_set_session_cache_mode(settings.ssl_ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(settings.ssl_ctx,
                                       (const unsigned char *) SESSION_ID_CONTEXT,
                                       strlen(SESSION_ID_CONTEXT));
    } else {
        SSL_CTX_set_session_cache_mode(settings.ssl_ctx, SSL_SESS_CACHE_OFF);
    }

    // Optional kernel TLS offload; default disabled.
    if (settings.ssl_kernel_tls) {
#if defined(SSL_OP_ENABLE_KTLS)
        SSL_CTX_set_options(settings.ssl_ctx, SSL_OP_ENABLE_KTLS);
#else
        fprintf(stderr, "Kernel TLS offload is not available\n");
        exit(EX_USAGE);
#endif
    }

#ifdef SSL_OP_NO_RENEGOTIATION
    // Disable TLS re-negotiation if SSL_OP_NO_RENEGOTIATION is defined for
    // openssl 1.1.0h or above
    SSL_CTX_set_options(settings.ssl_ctx, SSL_OP_NO_RENEGOTIATION);
#endif

    // Release TLS read/write buffers of idle connections
    SSL_CTX_set_mode(settings.ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

    return 0;
}

/*
 * This method is registered with each SSL connection and abort the SSL session
 * if a client initiates a renegotiation for openssl versions before 1.1.0h.
 * For openssl 1.1.0h and above, TLS re-negotiation is disabled by setting the
 * SSL_OP_NO_RENEGOTIATION option in SSL_CTX_set_options.
 */
void ssl_callback(const SSL *s, int where, int ret) {
#ifndef SSL_OP_NO_RENEGOTIATION
    SSL* ssl = (SSL*)s;
    if (SSL_in_before(ssl)) {
        fprintf(stderr, "%d: SSL renegotiation is not supported, "
                "closing the connection\n", SSL_get_fd(ssl));
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        return;
    }
#endif
}

/*
 * This method is invoked with every new successfully negotiated SSL session,
 * when server-side session caching is enabled. Note that this method is not
 * invoked when a session is reused.
 */
int ssl_new_session_callback(SSL *s, SSL_SESSION *sess) {
    STATS_LOCK();
    stats.ssl_new_sessions++;
    STATS_UNLOCK();

    return 0;
}

bool refresh_certs(char **errmsg) {
    return load_server_certificates(errmsg);
}

const char *ssl_proto_text(int version) {
    switch (version) {
        case TLS1_VERSION:
            return "tlsv1.0";
        case TLS1_1_VERSION:
            return "tlsv1.1";
        case TLS1_2_VERSION:
            return "tlsv1.2";
#if defined(TLS1_3_VERSION)
        case TLS1_3_VERSION:
            return "tlsv1.3";
#endif
        default:
            return "unknown";
    }
}
#endif
