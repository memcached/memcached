#include <string.h>
#include <sysexits.h>

#include "memcached.h"
#include "tls.h"

/* Read and write methods when SSL is enbled */
ssize_t ssl_read(void *arg, void *buf, size_t count) {
    conn *c = (conn*)arg;
    /* TODO : check the state machine interactions for SSL_read with
        non-blocking sockets/ SSL re-negotiations
    */
    return SSL_read(c->ssl, buf, count);
}

#define MIN(a,b) (((a)<(b))?(a):(b))
ssize_t ssl_sendmsg(void *arg, struct msghdr *msg, int flags) {
    conn *c = (conn*)arg;
    char *buffer;
    size_t bytes, to_copy;
    int i;
    bytes = 0;
    for (i = 0; i < msg->msg_iovlen; ++i)
        bytes += msg->msg_iov[i].iov_len;
    /* TODO : limit alloca for small allocations and use
        heap allocations for larger ones.
    */
    buffer = (char *) alloca(bytes);
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
    /* TODO : check the state machine interactions for SSL_write with
        non-blocking sockets/ SSL re-negotiations
    */
    return SSL_write(c->ssl, buffer, bytes);
}

ssize_t ssl_write(void *arg, void *buf, size_t count) {
    conn *c = (conn*)arg;
    return SSL_write(c->ssl, buf, count);
}

/* Standard thread-ID functions required by openssl */
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
    pthread_mutex_init(&ssl_ctx_lock, NULL);

    CRYPTO_set_id_callback(get_thread_id_cb);
    CRYPTO_set_locking_callback(thread_lock_cb);

    // SSL context for the process. All connections will share one
    // process level context.
    settings.ssl_ctx = SSL_CTX_new (SSLv23_server_method());
    SSL_CTX_set_options(settings.ssl_ctx, SSL_OP_NO_SSLv2);
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
    if (settings.ssl_cipher && !SSL_CTX_set_cipher_list(settings.ssl_ctx,
                                                    settings.ssl_cipher)) {
        fprintf(stderr, "Error setting the provided cipher(s) : %s\n",
            settings.ssl_cipher);
        exit(EX_USAGE);
    }
    // List of acceptable CAs for client certificates.
    const char* client_ca_cert = settings.ssl_client_ca_cert;
    if (client_ca_cert) {
        FILE* fp;
        if ((fp = fopen(client_ca_cert, "r")) == NULL) {
            fprintf(stderr, "Error opening the client CA cert file %s\n",
                client_ca_cert);
            exit(EX_USAGE);
        }
        X509 *ca_cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!SSL_CTX_add_client_CA(settings.ssl_ctx, ca_cert)) {
            fprintf(stderr, "Error adding the client CAs from cert file %s\n",
                client_ca_cert);
            exit(EX_USAGE);
        }
    }
    return 0;
}

void refresh_certificates(void) {
    if (!settings.ssl_enabled) return;
    const char* not_refreshed = "Certificates are not refreshed";

    pthread_mutex_lock(&(ssl_ctx_lock));
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
    pthread_mutex_unlock(&(ssl_ctx_lock));
}
