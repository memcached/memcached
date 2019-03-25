#include "memcached.h"

#ifdef TLS

#include "tls.h"
#include <string.h>
#include <sysexits.h>

static pthread_mutex_t ssl_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

#define __MAX_ALLOCA_CUTOFF        65536

#define MIN(a,b) (((a)<(b))?(a):(b))


void SSL_LOCK() {
    pthread_mutex_lock(&(ssl_ctx_lock));
}

void SSL_UNLOCK(void) {
    pthread_mutex_unlock(&(ssl_ctx_lock));
}

static void freebuff(char **ptrp)
{
    free (*ptrp);
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
    size_t bytes, to_copy;
    int i;
    bytes = 0;
    for (i = 0; i < msg->msg_iovlen; ++i)
        bytes += msg->msg_iov[i].iov_len;

    char *buffer;
    char *malloced_buffer __attribute__ ((__cleanup__ (freebuff))) = NULL;
    if (bytes < __MAX_ALLOCA_CUTOFF)
        buffer = (char *) alloca(bytes);
    else
        malloced_buffer = buffer = (char *) malloc (bytes);

    if (buffer == NULL)
        return -1;

    to_copy = bytes;
    char *bp = buffer;
    for (i = 0; i < msg->msg_iovlen; ++i) {
        size_t copy = MIN (to_copy, msg->msg_iov[i].iov_len);
        memcpy((void*)bp, (void*)msg->msg_iov[i].iov_base, copy);
        bp +=  copy;
        to_copy -= copy;
        if (to_copy == 0)
            break;
    }
    /* TODO : document the state machine interactions for SSL_write with
        non-blocking sockets/ SSL re-negotiations
    */
    return SSL_write(c->ssl, buffer, bytes);
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
 * Standard thread-ID functions required by openssl
 */
pthread_mutex_t * ssl_locks;
int ssl_num_locks;

unsigned long get_thread_id_cb(void) {
    return (unsigned long)pthread_self();
}

void thread_lock_cb(int mode, int which, const char * f, int l) {
    if (which < ssl_num_locks) {
        if (mode & CRYPTO_LOCK) {
            pthread_mutex_lock(&(ssl_locks[which]));
        } else {
            pthread_mutex_unlock(&(ssl_locks[which]));
        }
    }
}

/*
 * Verify SSL settings and initiates the SSL context.
 */
int ssl_init(void) {
    assert(settings.ssl_enabled);
    int i;

    ssl_num_locks = CRYPTO_num_locks();
    ssl_locks = malloc(ssl_num_locks * sizeof(pthread_mutex_t));
    if (ssl_locks == NULL)
        return -1;

    for (i = 0; i < ssl_num_locks; i++) {
        pthread_mutex_init(&(ssl_locks[i]), NULL);
    }

    CRYPTO_set_id_callback(get_thread_id_cb);
    CRYPTO_set_locking_callback(thread_lock_cb);

    // SSL context for the process. All connections will share one
    // process level context. We should use TLS_server_method when we
    // start using the version 1.1.0
    settings.ssl_ctx = SSL_CTX_new (SSLv23_server_method());
    // Clients should use at least TLSv1.2
    int flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                SSL_OP_NO_TLSv1 |SSL_OP_NO_TLSv1_1;
    SSL_CTX_set_options(settings.ssl_ctx, flags);

    // The sevrer certificate, private key and validations.
    if (!SSL_CTX_use_certificate_chain_file(settings.ssl_ctx,
        settings.ssl_chain_cert)) {
        fprintf(stderr, "Error loading the certificate chain : %s\n",
            settings.ssl_chain_cert);
        exit(EX_USAGE);
    }
    if (!SSL_CTX_use_PrivateKey_file(settings.ssl_ctx, settings.ssl_key,
                                        settings.ssl_keyform)) {
        fprintf(stderr, "Error loading the key : %s\n", settings.ssl_key);
        exit(EX_USAGE);
    }
    if (!SSL_CTX_check_private_key(settings.ssl_ctx)) {
        fprintf(stderr, "Error validating the certificate\n");
        exit(EX_USAGE);
    }

    // The verification mode of client certificate, default is SSL_VERIFY_PEER.
    SSL_CTX_set_verify(settings.ssl_ctx, settings.ssl_verify_mode, NULL);
    if (settings.ssl_ciphers && !SSL_CTX_set_cipher_list(settings.ssl_ctx,
                                                    settings.ssl_ciphers)) {
        fprintf(stderr, "Error setting the provided cipher(s) : %s\n",
            settings.ssl_ciphers);
        exit(EX_USAGE);
    }
    // List of acceptable CAs for client certificates.
    if (settings.ssl_ca_cert)
    {
        SSL_CTX_set_client_CA_list(settings.ssl_ctx,
            SSL_load_client_CA_file(settings.ssl_ca_cert));
        if (!SSL_CTX_load_verify_locations(settings.ssl_ctx,
                            settings.ssl_ca_cert, NULL)) {
            fprintf(stderr, "Error loading the client CA cert (%s)\n",
                            settings.ssl_ca_cert);
            exit(EX_USAGE);
        }
    }
    settings.ssl_last_cert_refresh_time = current_time;
    return 0;
}

/*
 * Re-load server certificate to the SSL context.
 */
void refresh_certificates(void) {
    if (!settings.ssl_enabled) return;
    const char* not_refreshed = "Certificates are not refreshed";

    SSL_LOCK();
    if (!SSL_CTX_use_certificate_chain_file(settings.ssl_ctx,
        settings.ssl_chain_cert)) {
        fprintf(stderr, "Error loading the certificate chain : %s. %s\n",
            settings.ssl_chain_cert, not_refreshed);
    }
    if (!SSL_CTX_use_PrivateKey_file(settings.ssl_ctx, settings.ssl_key,
                                        settings.ssl_keyform)) {
        fprintf(stderr, "Error loading the key : %s. %s\n", settings.ssl_key,
            not_refreshed);
    }
    if (!SSL_CTX_check_private_key(settings.ssl_ctx)) {
        fprintf(stderr, "Error validating the certificate. %s\n", not_refreshed);
    }
    settings.ssl_last_cert_refresh_time = current_time;
    SSL_UNLOCK();
}

#endif
