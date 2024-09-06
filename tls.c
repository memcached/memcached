#include "memcached.h"

#ifdef TLS

#include "tls.h"
#include <string.h>
#include <sysexits.h>
#include <sys/param.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* constant session ID context for application-level SSL session scoping.
 * used in server-side SSL session caching, when enabled. */
#define SESSION_ID_CONTEXT "memcached"

#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif

static ssize_t ssl_read(conn *c, void *buf, size_t count);
static ssize_t ssl_sendmsg(conn *c, struct msghdr *msg, int flags);
static ssize_t ssl_write(conn *c, void *buf, size_t count);
static void print_ssl_error(char *buff, size_t len);
static void ssl_callback(const SSL *s, int where, int ret);
static int ssl_new_session_callback(SSL *s, SSL_SESSION *sess);

static pthread_mutex_t ssl_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

const unsigned ERROR_MSG_SIZE = 64;
const size_t SSL_ERROR_MSG_SIZE = 256;

static void SSL_LOCK(void) {
    pthread_mutex_lock(&(ssl_ctx_lock));
}

static void SSL_UNLOCK(void) {
    pthread_mutex_unlock(&(ssl_ctx_lock));
}

void *ssl_accept(conn *c, int sfd, bool *fail) {
    SSL *ssl = NULL;
    if (c->ssl_enabled) {
        assert(IS_TCP(c->transport) && settings.ssl_enabled);

        if (settings.ssl_ctx == NULL) {
            if (settings.verbose) {
                fprintf(stderr, "SSL context is not initialized\n");
            }
            *fail = true;
            return NULL;
        }
        SSL_LOCK();
        ssl = SSL_new(settings.ssl_ctx);
        SSL_UNLOCK();
        if (ssl == NULL) {
            if (settings.verbose) {
                fprintf(stderr, "Failed to created the SSL object\n");
            }
            *fail = true;
            ERR_clear_error();
            return NULL;
        }
        SSL_set_fd(ssl, sfd);

        if (c->ssl_enabled == MC_SSL_ENABLED_NOPEER) {
            // Don't enforce peer certs for this socket.
            SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        } else if (c->ssl_enabled == MC_SSL_ENABLED_PEER) {
            // Force peer validation for this socket.
            SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }

        ERR_clear_error();
        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                // we're actually fine, let the worker thread continue.
                ERR_clear_error();
            } else {
                // TODO: ship full error to log stream? conn events?
                // SYSCALL specifically means we need to check errno/strerror.
                // Else we need to look at the main error stack.
                if (err == SSL_ERROR_SYSCALL) {
                    LOGGER_LOG(NULL, LOG_CONNEVENTS, LOGGER_CONNECTION_TLSERROR,
                            NULL, c->sfd, strerror(errno));
                } else {
                    char ssl_err[SSL_ERROR_MSG_SIZE];
                    // OpenSSL internal error. One or more, but lets only care about
                    // the top error for now.
                    print_ssl_error(ssl_err, SSL_ERROR_MSG_SIZE);
                    LOGGER_LOG(NULL, LOG_CONNEVENTS, LOGGER_CONNECTION_TLSERROR,
                            NULL, c->sfd, ssl_err);
                }
                ERR_clear_error();
                SSL_free(ssl);
                STATS_LOCK();
                stats.ssl_handshake_errors++;
                STATS_UNLOCK();
                *fail = true;
                return NULL;
            }
        }
    }

    return ssl;
}

/*
 * Note on setting errno in the follow functions:
 * We either have to refactor callers of read/write/sendmsg to take an error
 * flag to find out if we're in an EAGAIN state, or we ensure the errno is set
 * properly before returning from our TLS call. We do this because it's
 * _possible_ for OpenSSL to do something weird and land with an errno that
 * doesn't match the WANT_READ|WRITE state.
 *
 * Also: we _might_ have to communicate from these calls if we need to wait on
 * reads or write. Since I haven't yet proved that's even possible I'll save
 * that for a future refactor.
 */

// TODO: add int offset, and find the nth NID here.
// or different function that accepts a string, then does etc?
// Caller _must immediately_ use the string and not store the pointer.
const unsigned char *ssl_get_peer_cn(conn *c, int *len) {
    if (!c->ssl) {
        return NULL;
    }

    // can't use get0 to avoid getting a reference since that requires 3.0.0+
    X509 *cert = SSL_get_peer_certificate(c->ssl);
    if (cert == NULL) {
        return NULL;
    }
    X509_NAME *name = X509_get_subject_name(cert);
    if (name == NULL) {
        X509_free(cert);
        return NULL;
    }

    int r = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (r == -1) {
        X509_free(cert);
        return NULL;
    }
    ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, r));

    if (asn1 == NULL) {
        X509_free(cert);
        return NULL;
    }
    *len = ASN1_STRING_length(asn1);
    X509_free(cert);
    return ASN1_STRING_get0_data(asn1);
}

/*
 * Reads decrypted data from the underlying BIO read buffers,
 * which reads from the socket.
 */
static ssize_t ssl_read(conn *c, void *buf, size_t count) {
    assert (c != NULL);
    /* TODO : document the state machine interactions for SSL_read with
        non-blocking sockets/ SSL re-negotiations
    */

    ssize_t ret = SSL_read(c->ssl, buf, count);
    if (ret <= 0) {
        int err = SSL_get_error(c->ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            errno = EAGAIN;
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            // TLS session is closed... let the caller move this along.
            return 0;
        } else if (err == SSL_ERROR_SYSCALL) {
            // need to rely on errno to find out what happened
            LOGGER_LOG(c->thread->l, LOG_CONNEVENTS, LOGGER_CONNECTION_TLSERROR,
                    NULL, c->sfd, strerror(errno));
        } else if (ret != 0) {
            char ssl_err[SSL_ERROR_MSG_SIZE];
            // OpenSSL internal error. One or more, but lets only care about
            // the top error for now.
            print_ssl_error(ssl_err, SSL_ERROR_MSG_SIZE);
            LOGGER_LOG(c->thread->l, LOG_CONNEVENTS, LOGGER_CONNECTION_TLSERROR,
                    NULL, c->sfd, ssl_err);
            STATS_LOCK();
            stats.ssl_proto_errors++;
            STATS_UNLOCK();
        }
        ERR_clear_error();
    }

    return ret;
}

/*
 * Writes data to the underlying BIO write buffers,
 * which encrypt and write them to the socket.
 */
static ssize_t ssl_write(conn *c, void *buf, size_t count) {
    assert (c != NULL);

    ssize_t ret = SSL_write(c->ssl, buf, count);
    if (ret <= 0) {
        int err = SSL_get_error(c->ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            errno = EAGAIN;
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            // TLS session is closed... let the caller move this along.
            return 0;
        } else if (err == SSL_ERROR_SYSCALL) {
            // need to rely on errno to find out what happened
            LOGGER_LOG(c->thread->l, LOG_CONNEVENTS, LOGGER_CONNECTION_TLSERROR,
                    NULL, c->sfd, strerror(errno));
        } else if (ret != 0) {
            char ssl_err[SSL_ERROR_MSG_SIZE];
            // OpenSSL internal error. One or more, but lets only care about
            // the top error for now.
            print_ssl_error(ssl_err, SSL_ERROR_MSG_SIZE);
            LOGGER_LOG(c->thread->l, LOG_CONNEVENTS, LOGGER_CONNECTION_TLSERROR,
                    NULL, c->sfd, ssl_err);
            STATS_LOCK();
            stats.ssl_proto_errors++;
            STATS_UNLOCK();
        }
        ERR_clear_error();
    }
    return ret;
}

/*
 * SSL sendmsg implementation. Perform a SSL_write.
 */
static ssize_t ssl_sendmsg(conn *c, struct msghdr *msg, int flags) {
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
    return ssl_write(c, c->ssl_wbuf, bytes);
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

void ssl_conn_close(void *ssl_in) {
    SSL *ssl = ssl_in;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void ssl_init_conn(conn *c, void *ssl_in) {
    if (ssl_in) {
        SSL *ssl = ssl_in;
        c->ssl = (SSL*)ssl;
        c->read = ssl_read;
        c->sendmsg = ssl_sendmsg;
        c->write = ssl_write;
        SSL_set_info_callback(c->ssl, ssl_callback);
    }
}

void ssl_init_settings(void) {
    settings.ssl_enabled = false;
    settings.ssl_ctx = NULL;
    settings.ssl_chain_cert = NULL;
    settings.ssl_key = NULL;
    settings.ssl_verify_mode = SSL_VERIFY_NONE;
    settings.ssl_keyformat = SSL_FILETYPE_PEM;
    settings.ssl_ciphers = NULL;
    settings.ssl_ca_cert = NULL;
    settings.ssl_last_cert_refresh_time = current_time;
    settings.ssl_wbuf_size = 16 * 1024; // default is 16KB (SSL max frame size is 17KB)
    settings.ssl_session_cache = false;
    settings.ssl_kernel_tls = false;
    settings.ssl_min_version = TLS1_2_VERSION;
}

/*
 * Verify SSL settings and initiates the SSL context.
 */
int ssl_init(void) {
    assert(settings.ssl_enabled);

    OPENSSL_init_ssl(0, NULL);

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
    // useful for debugging.
    // fprintf(stderr, "WHERE: %d RET: %d CODE: %s LONG: %s\n", where, ret, SSL_state_string(s), SSL_state_string_long(s));
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

void ssl_help(void) {
    printf("   - ssl_chain_cert:      certificate chain file in PEM format\n"
           "   - ssl_key:             private key, if not part of the -ssl_chain_cert\n"
           "   - ssl_keyformat:       private key format (PEM, DER or ENGINE) (default: PEM)\n");
    printf("   - ssl_verify_mode:     peer certificate verification mode, default is 0(None).\n"
           "                          valid values are 0(None), 1(Request), 2(Require)\n"
           "                          or 3(Once)\n");
    printf("   - ssl_ciphers:         specify cipher list to be used\n"
           "   - ssl_ca_cert:         PEM format file of acceptable client CA's\n"
           "   - ssl_wbuf_size:       size in kilobytes of per-connection SSL output buffer\n"
           "                          (default: %u)\n", settings.ssl_wbuf_size / (1 << 10));
    printf("   - ssl_session_cache:   enable server-side SSL session cache, to support session\n"
           "                          resumption\n"
           "   - ssl_kernel_tls:      enable kernel TLS offload\n"
           "   - ssl_min_version:     minimum protocol version to accept (default: %s)\n",
           ssl_proto_text(settings.ssl_min_version));
#if defined(TLS1_3_VERSION)
    printf("                          valid values are 0(%s), 1(%s), 2(%s), or 3(%s).\n",
           ssl_proto_text(TLS1_VERSION), ssl_proto_text(TLS1_1_VERSION),
           ssl_proto_text(TLS1_2_VERSION), ssl_proto_text(TLS1_3_VERSION));
#else
    printf("                          valid values are 0(%s), 1(%s), or 2(%s).\n",
           ssl_proto_text(TLS1_VERSION), ssl_proto_text(TLS1_1_VERSION),
           ssl_proto_text(TLS1_2_VERSION));
#endif
    verify_default("ssl_keyformat", settings.ssl_keyformat == SSL_FILETYPE_PEM);
    verify_default("ssl_verify_mode", settings.ssl_verify_mode == SSL_VERIFY_NONE);
    verify_default("ssl_min_version", settings.ssl_min_version == TLS1_2_VERSION);
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

// TODO: would be nice to pull the entire set of startup option parsing into
// here like we do with extstore. To save time I'm only pulling subsection
// that require openssl headers to start.
bool ssl_set_verify_mode(int verify) {
    switch(verify) {
        case 0:
            settings.ssl_verify_mode = SSL_VERIFY_NONE;
            break;
        case 1:
            settings.ssl_verify_mode = SSL_VERIFY_PEER;
            break;
        case 2:
            settings.ssl_verify_mode = SSL_VERIFY_PEER |
                                        SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            break;
        case 3:
            settings.ssl_verify_mode = SSL_VERIFY_PEER |
                                        SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
                                        SSL_VERIFY_CLIENT_ONCE;
            break;
        default:
            return false;
    }
    return true;
}

bool ssl_set_min_version(int version) {
    switch (version) {
        case 0:
            settings.ssl_min_version = TLS1_VERSION;
            break;
        case 1:
            settings.ssl_min_version = TLS1_1_VERSION;
            break;
        case 2:
            settings.ssl_min_version = TLS1_2_VERSION;
            break;
#if defined(TLS1_3_VERSION)
        case 3:
            settings.ssl_min_version = TLS1_3_VERSION;
            break;
#endif
        default:
            return false;
    }
    return true;
}

#endif // ifdef TLS
