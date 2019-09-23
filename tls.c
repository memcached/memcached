#include "memcached.h"

#ifdef TLS

#include "tls.h"
#include <string.h>
#include <sysexits.h>
#include <sys/param.h>

#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif

static pthread_mutex_t ssl_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

const unsigned MAX_ERROR_MSG_SIZE = 128;

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
    // Currntly this connection would not be served by a different thread
    // than the one it's assigned.
    assert(c->thread->thread_id == (unsigned long)pthread_self());

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
 * Loads server certificates to the SSL context and validate them.
 * @return whether certificates are successfully loaded and verified or not.
 * @param error_msg contains the error when unsuccessful.
 */
static bool load_server_certificates(char **errmsg) {
    bool success = true;
    char *error_msg = malloc(MAXPATHLEN + MAX_ERROR_MSG_SIZE);
    size_t errmax = MAXPATHLEN + MAX_ERROR_MSG_SIZE - 1;
    if (error_msg == NULL) {
        *errmsg = NULL;
        return false;
    }
    SSL_LOCK();
    if (!SSL_CTX_use_certificate_chain_file(settings.ssl_ctx,
        settings.ssl_chain_cert)) {
        snprintf(error_msg, errmax, "Error loading the certificate chain: %s\r\n",
            settings.ssl_chain_cert);
        success = false;
    } else if (!SSL_CTX_use_PrivateKey_file(settings.ssl_ctx, settings.ssl_key,
                                        settings.ssl_keyformat)) {
        snprintf(error_msg, errmax, "Error loading the key: %s\r\n", settings.ssl_key);
        success = false;
    } else if (!SSL_CTX_check_private_key(settings.ssl_ctx)) {
        snprintf(error_msg, errmax, "Error validating the certificate\r\n");
        success = false;
    } else {
        settings.ssl_last_cert_refresh_time = current_time;
    }
    SSL_UNLOCK();
    if (success) {
        free(error_msg);
    } else {
        *errmsg = error_msg;
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
    // Clients should use at least TLSv1.2
    int flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                SSL_OP_NO_TLSv1 |SSL_OP_NO_TLSv1_1;
    SSL_CTX_set_options(settings.ssl_ctx, flags);

    // The server certificate, private key and validations.
    char *error_msg;
    if (!load_server_certificates(&error_msg)) {
        if (settings.verbose) {
            fprintf(stderr, "%s", error_msg);
        }
        free(error_msg);
        exit(EX_USAGE);
    }

    // The verification mode of client certificate, default is SSL_VERIFY_PEER.
    SSL_CTX_set_verify(settings.ssl_ctx, settings.ssl_verify_mode, NULL);
    if (settings.ssl_ciphers && !SSL_CTX_set_cipher_list(settings.ssl_ctx,
                                                    settings.ssl_ciphers)) {
        if (settings.verbose) {
            fprintf(stderr, "Error setting the provided cipher(s): %s\n",
                    settings.ssl_ciphers);
        }
        exit(EX_USAGE);
    }
    // List of acceptable CAs for client certificates.
    if (settings.ssl_ca_cert)
    {
        SSL_CTX_set_client_CA_list(settings.ssl_ctx,
            SSL_load_client_CA_file(settings.ssl_ca_cert));
        if (!SSL_CTX_load_verify_locations(settings.ssl_ctx,
                            settings.ssl_ca_cert, NULL)) {
            if (settings.verbose) {
                fprintf(stderr, "Error loading the client CA cert (%s)\n",
                        settings.ssl_ca_cert);
            }
            exit(EX_USAGE);
        }
    }
    settings.ssl_last_cert_refresh_time = current_time;
    return 0;
}

/*
 * This method is registered with each SSL connection and abort the SSL session
 * if a client initiates a renegotiation.
 * TODO : Proper way to do this is to set SSL_OP_NO_RENEGOTIATION
 *       using the SSL_CTX_set_options but that option only available in
 *       openssl 1.1.0h or above.
 */
void ssl_callback(const SSL *s, int where, int ret) {
    SSL* ssl = (SSL*)s;
    if (SSL_in_before(ssl)) {
        if (settings.verbose) {
            fprintf(stderr, "%d: SSL renegotiation is not supported, "
                    "closing the connection\n", SSL_get_fd(ssl));
        }
        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        return;
    }
}

bool refresh_certs(char **errmsg) {
    return load_server_certificates(errmsg);
}
#endif
