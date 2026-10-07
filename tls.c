#include "memcached.h"

#ifdef TLS

#include "tls.h"
#include <string.h>
#include <sysexits.h>
#include <sys/param.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
#include <openssl/x509v3.h>
#endif

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

int ssl_data_index = -1;

static pthread_mutex_t ssl_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

const unsigned ERROR_MSG_SIZE = 64;
const size_t SSL_ERROR_MSG_SIZE = 256;

static void SSL_LOCK(void) {
    pthread_mutex_lock(&(ssl_ctx_lock));
}

static void SSL_UNLOCK(void) {
    pthread_mutex_unlock(&(ssl_ctx_lock));
}

static char *x509_name_to_string(X509_NAME *name) {
    BIO *bio = BIO_new(BIO_s_mem());
    if(!bio) {
        if (settings.verbose > 3) {
            fprintf(stderr, "BIO_new() failed\n");
        }
        return NULL;
    }

    if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
        BIO_free(bio);
        if (settings.verbose > 3) {
            fprintf(stderr, "X509_NAME_print_ex() failed\n");
        }
    }

    char *data, *ret;
    size_t len = BIO_get_mem_data(bio, &data);

    ret = strndup(data, len);
    BIO_free(bio);

    return ret;
}

bool ssl_check_CA_cert(struct tls_settings *tls_settings) {
    char *type = ssl_is_client(tls_settings) ? "server" : "client";

    if(!tls_settings->ssl_ca_cert) {
        fprintf (stderr, "ssl_check_CA_cert(): CA cert not defined\n");
        return false;
    }

    STACK_OF(X509_NAME) *ca_stack = SSL_load_client_CA_file(tls_settings->ssl_ca_cert);

    if(!sk_X509_NAME_num(ca_stack)) {
        if (settings.verbose > 3) {
            fprintf(stderr, "CERT(ssl_check_CA_cert): %s list not found\n", type);
        }
        sk_X509_NAME_pop_free(ca_stack, X509_NAME_free);
        return false;
    }

    int i, num = sk_X509_NAME_num(ca_stack);
    if(num == 0) {
        if (settings.verbose > 3) {
            fprintf(stderr, "CERT(ssl_check_CA_cert): %s list is empty\n", type);
        }
        sk_X509_NAME_pop_free(ca_stack, X509_NAME_free);
        return false;
    }

    for(i=0; i<num; ++i) {
        char *ca_name=x509_name_to_string(sk_X509_NAME_value(ca_stack, i));
        if (settings.verbose > 3) {
            fprintf(stderr, "CERT(ssl_check_CA_cert): %s: %s\n", type, ca_name);
        }
        free(ca_name);
    }

    sk_X509_NAME_pop_free(ca_stack, X509_NAME_free);
    return true;
}

static bool ssl_X509_check_host(struct tls_settings *tls_settings, X509_STORE_CTX *callback_ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    int cnt = 0;
    X509 *certificate = X509_STORE_CTX_get_current_cert(callback_ctx);

    char *peername = NULL;
    for(LIST_STR *ptr = tls_settings->ssl_verify_name; ptr; ptr = ptr->next, cnt++) {
        if(X509_check_host(certificate, ptr->str, 0, 0, &peername)>0) {
            if (settings.verbose > 3) {
                fprintf(stderr, "CERT(cert_check_subject): Host name '%s' matched with '%s'\n", ptr->str, peername);
            }
            OPENSSL_free(peername);
            return true;
        }
    }

    if (!cnt) {
        return true;
    }

    if (settings.verbose > 3) {
        char *subject = x509_name_to_string(X509_get_subject_name(certificate));
        char *list = name_list_to_string(tls_settings->ssl_verify_name, ":");
        fprintf(stderr, "CERT(cert_check_subject): Not found '%s' in certificate: %s\n", list, subject);
        safe_free(subject);
        safe_free(list);
    }

    return false;
#else
    return true;
#endif
}

int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
    SSL *ssl;
    struct tls_settings *tls_settings;

    ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    // Get tls settings from openssl data
    tls_settings = (struct tls_settings *) SSL_get_ex_data(ssl, ssl_data_index);

    if(tls_settings->ssl_enabled != MC_SSL_VERIFY_PEER) {
        if (settings.verbose > 3) {
            fprintf(stderr, "CERT(ssl_verify_callback): Certificate verification disabled\n");
        }
        return 1; // OK
    }

    if(preverify_ok) {
        if (settings.verbose > 3) {
            fprintf(stderr, "CERT(ssl_verify_callback): Pre verification succeeded\n");
        }
    }

    int x509_error = X509_STORE_CTX_get_error(x509_ctx);
    int x509_depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    X509 *certificate = X509_STORE_CTX_get_current_cert(x509_ctx);
    char *subject_name = x509_name_to_string(X509_get_subject_name(certificate));

    if (settings.verbose > 3) {
        fprintf(stderr, "CERT(ssl_verify_callback): Verification started at depth '%d': '%s'\n", x509_depth, subject_name);
    }

    if (!preverify_ok && x509_depth == 0
        && x509_error != X509_V_ERR_CERT_UNTRUSTED
        && x509_error != X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
        && x509_error != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
        if (settings.verbose > 3) {
            fprintf(stderr, "CERT(ssl_verify_callback): Certificate verification error '%d' at depth '%d': %s %s\n",
                    x509_error, x509_depth,
                    x509_error == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
                        x509_error == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ?
                        "certificate not present in the local trust store" : "",
                    X509_verify_cert_error_string(x509_error));
        }
        safe_free(subject_name);
        return 0;   // Fail
    }

    if (settings.verbose > 3) {
        fprintf(stderr, "CERT(ssl_verify_callback): Certificate verified at depth '%d': '%s'\n", x509_depth, subject_name);
    }
    safe_free(subject_name);

    if(x509_depth == 0) {
        if(!ssl_X509_check_host(tls_settings, x509_ctx)) {
            return 0;   // Fail
        }
        // ToDo: should be good also implement X509_check_email or X509_check_ip_asc
    }

    return 1;   // OK
}

void *ssl_accept(conn *c, int sfd, bool *fail) {
    SSL *ssl = NULL;
    if (c->ssl_enabled) {
        assert(IS_TCP(c->transport) && settings.ssl_enabled);

        if (c->tls_settings.ssl_ctx == NULL) {
            if (settings.verbose) {
                fprintf(stderr, "SSL context is not initialized\n");
            }
            *fail = true;
            return NULL;
        }
        SSL_LOCK();
        ssl = SSL_new(c->tls_settings.ssl_ctx);
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

        if (settings.verbose > 2) {
            fprintf(stderr, "Setup SSL connection type %d\n", c->ssl_enabled);
        }
        if (c->ssl_enabled == MC_SSL_ENABLED_NOPEER) {
            // Don't enforce peer certs for this socket.
            SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        } else if (c->ssl_enabled == MC_SSL_ENABLED_PEER) {
            // Force peer validation for this socket.
            SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        } else if (c->ssl_enabled == MC_SSL_VERIFY_PEER) {
            // Force peer validation for this socket with validation
            c->tls_settings.ssl_enabled = c->ssl_enabled;

            // Check main CA certificate
            if (!ssl_check_CA_cert(&c->tls_settings)) {
                fprintf(stderr, "Not exist trusted certificate\n");
                *fail = true;
                ERR_clear_error();
                SSL_free(ssl);
                return NULL;
            }

            SSL_LOCK();
            // Add tls settings for SSL functionality as OpenSSL data
            SSL_set_ex_data(ssl, ssl_data_index, &c->tls_settings);
            // Setup own verify callback function
            SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_callback);
            SSL_UNLOCK();
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
                    ssl_err[0] = '\0';
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
    size_t buf_remain = settings.tls_settings.ssl_wbuf_size;
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
 * @param tls_settings  TLS setting of connections.
 * @param error_msg contains the error when unsuccessful.
 */
static bool load_server_certificates(struct tls_settings *tls_settings, char **errmsg) {
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

    if (tls_settings->ssl_ctx == NULL) {
        snprintf(error_msg, errmax, "Error TLS not enabled\r\n");
        *errmsg = error_msg;
        return false;
    }

    // Not checking certificates when is client and no certificate is setup
    if (ssl_is_client(tls_settings)) {
        if (tls_settings->ssl_enabled != MC_SSL_VERIFY_PEER
            && tls_settings->ssl_chain_cert == NULL
            && tls_settings->ssl_key == NULL
            && tls_settings->ssl_ca_cert == NULL) {
            return true;
        }
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
    if (!SSL_CTX_use_certificate_chain_file(tls_settings->ssl_ctx,
                                            tls_settings->ssl_chain_cert)) {
        print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
        err_msg_size = snprintf(error_msg, errmax, "Error loading the certificate chain: "
                                "%s : %s", tls_settings->ssl_chain_cert, ssl_err_msg);
    } else if (!SSL_CTX_use_PrivateKey_file(tls_settings->ssl_ctx, tls_settings->ssl_key,
                                            tls_settings->ssl_keyformat)) {
        print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
        err_msg_size = snprintf(error_msg, errmax, "Error loading the key: %s : %s",
                                tls_settings->ssl_key, ssl_err_msg);
    } else if (!SSL_CTX_check_private_key(tls_settings->ssl_ctx)) {
        print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
        err_msg_size = snprintf(error_msg, errmax, "Error validating the certificate: %s",
                                ssl_err_msg);
    } else if (tls_settings->ssl_ca_cert) {
        if (!SSL_CTX_load_verify_locations(tls_settings->ssl_ctx,
                                           tls_settings->ssl_ca_cert, NULL)) {
            print_ssl_error(ssl_err_msg, SSL_ERROR_MSG_SIZE);
            err_msg_size = snprintf(error_msg, errmax,
                                    "Error loading the CA certificate: %s : %s",
                                    tls_settings->ssl_ca_cert, ssl_err_msg);
        } else {
            SSL_CTX_set_client_CA_list(tls_settings->ssl_ctx,
                                       SSL_load_client_CA_file(tls_settings->ssl_ca_cert));
            success = true;
        }
    } else {
        success = true;
    }
    SSL_UNLOCK();
    free(ssl_err_msg);
    if (success) {
        tls_settings->ssl_last_cert_refresh_time = current_time;
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

int ssl_pending(void *ssl_in) {
    SSL *ssl = ssl_in;
    return SSL_pending(ssl);
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

struct tls_settings ssl_init_settings(void) {
    struct tls_settings tls;

    tls.ssl_ctx = NULL;
    tls.ssl_chain_cert = NULL;
    tls.ssl_key = NULL;
    tls.ssl_verify_mode = SSL_VERIFY_NONE;
    tls.ssl_keyformat = SSL_FILETYPE_PEM;
    tls.ssl_ciphers = NULL;
    tls.ssl_ca_cert = NULL;
    tls.ssl_last_cert_refresh_time = current_time;
    tls.ssl_wbuf_size = 16 * 1024; // default is 16KB (SSL max frame size is 17KB)
    tls.ssl_session_cache = false;
    tls.ssl_kernel_tls = false;
    tls.ssl_min_version = TLS1_2_VERSION;
    tls.ssl_enabled = true;
    tls.ssl_verify_name = NULL;

    tls.TLS_method = NULL;

    // Index SSL initialization
    if (ssl_data_index < 0) {
        ssl_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    }

    return tls;
}

/*
 * Verify SSL settings and initiates the SSL context.
 */
int ssl_init(bool ssl_enabled, struct tls_settings *tls_settings) {
    assert(ssl_enabled);

    OPENSSL_init_ssl(0, NULL);

    // Index SSL initialization
    if (ssl_data_index < 0) {
        ssl_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    }

    // SSL context for the process. All connections will share one
    // process level context.
    if (tls_settings->ssl_ctx == NULL) {
        tls_settings->ssl_ctx = SSL_CTX_new(tls_settings->TLS_method);
    }

    SSL_CTX_set_min_proto_version(tls_settings->ssl_ctx, tls_settings->ssl_min_version);

    // The server certificate, private key and validations.
    char *error_msg;

    if (!load_server_certificates(tls_settings, &error_msg)) {
        fprintf(stderr, "%s", error_msg);
        free(error_msg);
        return 1;
    }

    // The verification mode of client certificate, default is SSL_VERIFY_PEER.
    SSL_CTX_set_verify(tls_settings->ssl_ctx, tls_settings->ssl_verify_mode, NULL);
    if (tls_settings->ssl_ciphers && !SSL_CTX_set_cipher_list(tls_settings->ssl_ctx,
                                                    tls_settings->ssl_ciphers)) {
        fprintf(stderr, "Error setting the provided cipher(s): %s\n",
                tls_settings->ssl_ciphers);
        return 1;
    }

    // Optional session caching; default disabled.
    if (tls_settings->ssl_session_cache) {
        SSL_CTX_sess_set_new_cb(tls_settings->ssl_ctx, ssl_new_session_callback);
        SSL_CTX_set_session_cache_mode(tls_settings->ssl_ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(tls_settings->ssl_ctx,
                                       (const unsigned char *) SESSION_ID_CONTEXT,
                                       strlen(SESSION_ID_CONTEXT));
    } else {
        SSL_CTX_set_session_cache_mode(tls_settings->ssl_ctx, SSL_SESS_CACHE_OFF);
    }

    // Optional kernel TLS offload; default disabled.
    if (tls_settings->ssl_kernel_tls) {
#if defined(SSL_OP_ENABLE_KTLS)
        SSL_CTX_set_options(tls_settings->ssl_ctx, SSL_OP_ENABLE_KTLS);
#else
        fprintf(stderr, "Kernel TLS offload is not available\n");
        return 1;
#endif
    }

#ifdef SSL_OP_NO_RENEGOTIATION
    // Disable TLS re-negotiation if SSL_OP_NO_RENEGOTIATION is defined for
    // openssl 1.1.0h or above
    SSL_CTX_set_options(tls_settings->ssl_ctx, SSL_OP_NO_RENEGOTIATION);
#endif

    // Release TLS read/write buffers of idle connections
    SSL_CTX_set_mode(tls_settings->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

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
    if (settings.verbose > 4) {
        fprintf(stderr, "WHERE: %d RET: %d CODE: %s LONG: %s\n", where, ret,
                SSL_state_string(s), SSL_state_string_long(s));
    }
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

bool refresh_certs(struct tls_settings *tls_settings, char **errmsg) {
    return load_server_certificates(tls_settings, errmsg);
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
           "                          (default: %u)\n", settings.tls_settings.ssl_wbuf_size / (1 << 10));
    printf("   - ssl_session_cache:   enable server-side SSL session cache, to support session\n"
           "                          resumption\n"
           "   - ssl_kernel_tls:      enable kernel TLS offload\n"
           "   - ssl_verify_name      verification policy host name, multiple hosts are separated by colon\n"
           "   - ssl_min_version:     minimum protocol version to accept (default: %s)\n",
           ssl_proto_text(settings.tls_settings.ssl_min_version));
#if defined(TLS1_3_VERSION)
    printf("                          valid values are 0(%s), 1(%s), 2(%s), or 3(%s).\n",
           ssl_proto_text(TLS1_VERSION), ssl_proto_text(TLS1_1_VERSION),
           ssl_proto_text(TLS1_2_VERSION), ssl_proto_text(TLS1_3_VERSION));
#else
    printf("                          valid values are 0(%s), 1(%s), or 2(%s).\n",
           ssl_proto_text(TLS1_VERSION), ssl_proto_text(TLS1_1_VERSION),
           ssl_proto_text(TLS1_2_VERSION));
#endif
    verify_default("ssl_keyformat", settings.tls_settings.ssl_keyformat == SSL_FILETYPE_PEM);
    verify_default("ssl_verify_mode", settings.tls_settings.ssl_verify_mode == SSL_VERIFY_NONE);
    verify_default("ssl_min_version", settings.tls_settings.ssl_min_version == TLS1_2_VERSION);
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
            settings.tls_settings.ssl_verify_mode = SSL_VERIFY_NONE;
            break;
        case 1:
            settings.tls_settings.ssl_verify_mode = SSL_VERIFY_PEER;
            break;
        case 2:
            settings.tls_settings.ssl_verify_mode = SSL_VERIFY_PEER |
                                        SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            break;
        case 3:
            settings.tls_settings.ssl_verify_mode = SSL_VERIFY_PEER |
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
            settings.tls_settings.ssl_min_version = TLS1_VERSION;
            break;
        case 1:
            settings.tls_settings.ssl_min_version = TLS1_1_VERSION;
            break;
        case 2:
            settings.tls_settings.ssl_min_version = TLS1_2_VERSION;
            break;
#if defined(TLS1_3_VERSION)
        case 3:
            settings.tls_settings.ssl_min_version = TLS1_3_VERSION;
            break;
#endif
        default:
            return false;
    }
    return true;
}

bool ssl_is_client(struct tls_settings *tls_settings) {
    if (!tls_settings->ssl_ctx) {
        return false;
    }

    const SSL_METHOD *method = SSL_CTX_get_ssl_method(tls_settings->ssl_ctx);
    return (method != NULL && method == TLS_client_method()) ? true : false;
}

bool ssl_is_server(struct tls_settings *tls_settings) {
    if (!tls_settings->ssl_ctx) {
        return false;
    }

    const SSL_METHOD *method = SSL_CTX_get_ssl_method(tls_settings->ssl_ctx);
    return (method != NULL && method == TLS_server_method()) ? true : false;
}

#endif // ifdef TLS
