//
// Created by rigon on 11.01.24.
//
#include "defs-testcomp.c"
#include <stdbool.h>
#include "protocol_binary.h"
#include <assert.h>
#include "in.h"
#include "errno.h"
//#include "stdint.h"

extern uint __VERIFIER_nondet_uint();
static in_port_t port;
static bool enable_ssl = false;

enum test_return { TEST_SKIP, TEST_PASS, TEST_FAIL };

struct conn {
    int sock;
#ifdef TLS
    SSL_CTX   *ssl_ctx;
    SSL    *ssl;
#endif
    ssize_t (*read)(struct conn  *c, void *buf, size_t count);
    ssize_t (*write)(struct conn *c, const void *buf, size_t count);
};
static struct conn *con = NULL;
static bool allow_closed_read = false;

ssize_t tcp_read(struct conn *c, void *buf, size_t count) {
    assert(c != NULL);
    return read(c->sock, buf, count);
}

ssize_t tcp_write(struct conn *c, const void *buf, size_t count) {
    assert(c != NULL);
    return write(c->sock, buf, count);
}

static struct conn *connect_server(const char *hostname, in_port_t port2,
                                   bool nonblock, const bool ssl)
{
    struct conn *c;
    if (!(c = (struct conn *)calloc(1, sizeof(struct conn)))) {
        fprintf(stderr, "Failed to allocate the client connection: %s\n",
                strerror(errno));
        return NULL;
    }

    //struct addrinfo *ai = lookuphost(hostname, port);
    //int sock = -1;
    /*if (ai != NULL) {
        if ((sock = socket(ai->ai_family, ai->ai_socktype,
                           ai->ai_protocol)) != -1) {
            if (connect(sock, ai->ai_addr, ai->ai_addrlen) == -1) {
                fprintf(stderr, "Failed to connect socket: %s\n",
                        strerror(errno));
                close(sock);
                sock = -1;
            } else if (nonblock) {
                int flags = fcntl(sock, F_GETFL, 0);
                if (flags < 0 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
                    fprintf(stderr, "Failed to enable nonblocking mode: %s\n",
                            strerror(errno));
                    close(sock);
                    sock = -1;
                }
            }
        } else {
            fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        }

        freeaddrinfo(ai);
    } */
    c->sock = -1;
#ifdef TLS
    if (sock > 0 && ssl) {
        c->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        if (c->ssl_ctx == NULL) {
            fprintf(stderr, "Failed to create the SSL context: %s\n",
                strerror(errno));
            close(sock);
            sock = -1;
        }
        c->ssl = SSL_new(c->ssl_ctx);
        if (c->ssl == NULL) {
            fprintf(stderr, "Failed to create the SSL object: %s\n",
                strerror(errno));
            close(sock);
            sock = -1;
        }
        SSL_set_fd (c->ssl, c->sock);
        int ret = SSL_connect(c->ssl);
        if (ret < 0) {
            int err = SSL_get_error(c->ssl, ret);
            if (err == SSL_ERROR_SYSCALL || err == SSL_ERROR_SSL) {
                fprintf(stderr, "SSL connection failed with error code : %s\n",
                    strerror(errno));
                close(sock);
                sock = -1;
            }
        }
        c->read = ssl_read;
        c->write = ssl_write;
    } else
#endif
    {
        c->read = tcp_read;
        c->write = tcp_write;
    }
    return c;
}

static off_t storage_command(char*buf,
                             size_t bufsz,
                             uint8_t cmd,
                             const void* key,
                             size_t keylen,
                             const void* dta,
                             size_t dtalen,
                             uint32_t flags,
                             uint32_t exp) {
    /* all the storage commands use the same command layout */
    protocol_binary_request_set *request = (void*)buf;
    assert(bufsz > sizeof(*request) + keylen + dtalen);

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;
    request->message.header.request.keylen = htons(keylen);
    request->message.header.request.extlen = 8;
    request->message.header.request.bodylen = htonl(keylen + 8 + dtalen);
    request->message.header.request.opaque = 0xdeadbeef;
    request->message.body.flags = flags;
    request->message.body.expiration = exp;

    off_t key_offset = sizeof(protocol_binary_request_no_extras) + 8;

    memcpy(buf + key_offset, key, keylen);
    if (dta != NULL) {
        memcpy(buf + key_offset + keylen, dta, dtalen);
    }

    return key_offset + keylen + dtalen;
}

static void safe_send(const void* buf, size_t len, bool hickup)
{
    printf("The error is in safe_send 2 in the for loop\n");
    off_t offset = 0;
    const char* ptr = buf;
#ifdef MESSAGE_DEBUG
    uint8_t val = *ptr;
    assert(val == (uint8_t)0x80);
    fprintf(stderr, "About to send %lu bytes:", (unsigned long)len);
    for (int ii = 0; ii < len; ++ii) {
        if (ii % 4 == 0) {
            fprintf(stderr, "\n   ");
        }
        val = *(ptr + ii);
        fprintf(stderr, " 0x%02x", val);
    }
    fprintf(stderr, "\n");
    usleep(500);
#endif
    printf("The error is in safe_send before do\n");
    do {
        size_t num_bytes = len - offset;
        printf("The error is in safe_send in do after len - offset\n");
        if (hickup) {
            printf("The error is in safe_send in do after first if cond\n");
            if (num_bytes > 1024) {
                num_bytes = (rand() % 1023) + 1;
            }
        }
        printf("The error is in safe_send in do after first if cond in ssize_t nw\n");
        ssize_t nw = con->write(con, ptr + offset, num_bytes);
        printf("The error is not after first if cond after ssize_t bahh\n");
        if (nw == -1) {
            if (errno != EINTR) {
                printf("The error is because nw = -1\n");
                fprintf(stderr, "Failed to write: %s\n", strerror(errno));
                abort();
            }
        } else {
            if (hickup) {
                usleep(100);
            }
            offset += nw;
            printf("The error is in safe_send, but not in the else condition | offset: %ld \n", offset);
        }
    } while (offset < len);
    printf("The error is no error in safe_send\n");
}

static bool safe_recv(void *buf, size_t len) {
    if (len == 0) {
        return true;
    }
    off_t offset = 0;
    do {
        ssize_t nr = con->read(con, ((char*)buf) + offset, len - offset);
        if (nr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to read: %s\n", strerror(errno));
                abort();
            }
        } else {
            if (nr == 0 && allow_closed_read) {
                return false;
            }
            assert(nr != 0);
            offset += nr;
        }
    } while (offset < len);

    return true;
}

static bool safe_recv_packet(void *buf, size_t size) {
    protocol_binary_response_no_extras *response = buf;
    assert(size > sizeof(*response));
    if (!safe_recv(response, sizeof(*response))) {
        return false;
    }
    response->message.header.response.keylen = ntohs(response->message.header.response.keylen);
    response->message.header.response.status = ntohs(response->message.header.response.status);
    response->message.header.response.bodylen = ntohl(response->message.header.response.bodylen);

    size_t len = sizeof(*response);

    char *ptr = buf;
    ptr += len;
    if (!safe_recv(ptr, response->message.header.response.bodylen)) {
        return false;
    }

#ifdef MESSAGE_DEBUG
    usleep(500);
    ptr = buf;
    len += response->message.header.response.bodylen;
    uint8_t val = *ptr;
    assert(val == (uint8_t)0x81);
    fprintf(stderr, "Received %lu bytes:", (unsigned long)len);
    for (int ii = 0; ii < len; ++ii) {
        if (ii % 4 == 0) {
            fprintf(stderr, "\n   ");
        }
        val = *(ptr + ii);
        fprintf(stderr, " 0x%02x", val);
    }
    fprintf(stderr, "\n");
#endif
    return true;
}

static void validate_response_header(protocol_binary_response_no_extras *response,
                                     uint8_t cmd, uint16_t status)
{
    assert(response->message.header.response.magic == PROTOCOL_BINARY_RES);
    assert(response->message.header.response.opcode == cmd);
    assert(response->message.header.response.datatype == PROTOCOL_BINARY_RAW_BYTES);
    assert(response->message.header.response.status == status);
    assert(response->message.header.response.opaque == 0xdeadbeef);

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        switch (cmd) {
            case PROTOCOL_BINARY_CMD_ADDQ:
            case PROTOCOL_BINARY_CMD_APPENDQ:
            case PROTOCOL_BINARY_CMD_DECREMENTQ:
            case PROTOCOL_BINARY_CMD_DELETEQ:
            case PROTOCOL_BINARY_CMD_FLUSHQ:
            case PROTOCOL_BINARY_CMD_INCREMENTQ:
            case PROTOCOL_BINARY_CMD_PREPENDQ:
            case PROTOCOL_BINARY_CMD_QUITQ:
            case PROTOCOL_BINARY_CMD_REPLACEQ:
            case PROTOCOL_BINARY_CMD_SETQ:
                assert("Quiet command shouldn't return on success" == NULL);
            default:
                break;
        }

        switch (cmd) {
            case PROTOCOL_BINARY_CMD_ADD:
            case PROTOCOL_BINARY_CMD_REPLACE:
            case PROTOCOL_BINARY_CMD_SET:
            case PROTOCOL_BINARY_CMD_APPEND:
            case PROTOCOL_BINARY_CMD_PREPEND:
                assert(response->message.header.response.keylen == 0);
                assert(response->message.header.response.extlen == 0);
                assert(response->message.header.response.bodylen == 0);
                assert(response->message.header.response.cas != 0);
                break;
            case PROTOCOL_BINARY_CMD_FLUSH:
            case PROTOCOL_BINARY_CMD_NOOP:
            case PROTOCOL_BINARY_CMD_QUIT:
            case PROTOCOL_BINARY_CMD_DELETE:
                assert(response->message.header.response.keylen == 0);
                assert(response->message.header.response.extlen == 0);
                assert(response->message.header.response.bodylen == 0);
                assert(response->message.header.response.cas == 0);
                break;

            case PROTOCOL_BINARY_CMD_DECREMENT:
            case PROTOCOL_BINARY_CMD_INCREMENT:
                assert(response->message.header.response.keylen == 0);
                assert(response->message.header.response.extlen == 0);
                assert(response->message.header.response.bodylen == 8);
                assert(response->message.header.response.cas != 0);
                break;

            case PROTOCOL_BINARY_CMD_STAT:
                assert(response->message.header.response.extlen == 0);
                /* key and value exists in all packets except in the terminating */
                assert(response->message.header.response.cas == 0);
                break;

            case PROTOCOL_BINARY_CMD_VERSION:
                assert(response->message.header.response.keylen == 0);
                assert(response->message.header.response.extlen == 0);
                assert(response->message.header.response.bodylen != 0);
                assert(response->message.header.response.cas == 0);
                break;

            case PROTOCOL_BINARY_CMD_GET:
            case PROTOCOL_BINARY_CMD_GETQ:
            case PROTOCOL_BINARY_CMD_GAT:
            case PROTOCOL_BINARY_CMD_GATQ:
                assert(response->message.header.response.keylen == 0);
                assert(response->message.header.response.extlen == 4);
                assert(response->message.header.response.cas != 0);
                break;

            case PROTOCOL_BINARY_CMD_GETK:
            case PROTOCOL_BINARY_CMD_GETKQ:
            case PROTOCOL_BINARY_CMD_GATK:
            case PROTOCOL_BINARY_CMD_GATKQ:
                assert(response->message.header.response.keylen != 0);
                assert(response->message.header.response.extlen == 4);
                assert(response->message.header.response.cas != 0);
                break;

            default:
                /* Undefined command code */
                break;
        }
    } else {
        assert(response->message.header.response.cas == 0);
        assert(response->message.header.response.extlen == 0);
        if (cmd != PROTOCOL_BINARY_CMD_GETK &&
            cmd != PROTOCOL_BINARY_CMD_GATK) {
            assert(response->message.header.response.keylen == 0);
        }
    }
}

static enum test_return test_binary_add_impl(const char *key, uint8_t cmd) {
    uint64_t value = 0xdeadbeefdeadcafe;
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    printf("The error is later than send, receive\n");
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd, key,
                                 strlen(key), &value, sizeof(value),
                                 0, 0);
    printf("The error is not in the storage_command method\n");
    /* Add should only work the first time */
    int ii;
    printf("The error starts in the for loop\n");
    for (ii = 0; ii < 10; ++ii) {
        printf("The error is in safe_send in the for loop\n");
        safe_send(send.bytes, len, false);
        printf("The error is not in safe_send in the for loop\n");
        if (ii == 0) {
            if (cmd == PROTOCOL_BINARY_CMD_ADD) {
                safe_recv_packet(receive.bytes, sizeof(receive.bytes));
                validate_response_header(&receive.response, cmd,
                                         PROTOCOL_BINARY_RESPONSE_SUCCESS);
                printf("The error is not in the if condition PROTOCOL_BINARY_CMD_ADD\n");
            }
        }
        else {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);
        }
    }
    printf("The error does never happen, the harness is the problem\n");
    return TEST_PASS;
}

int main() {
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    //const char *inputkey = __VERIFIER_nondet_pchar();
    //uint8_t inputcmd = __VERIFIER_nondet_char();
    const char *inputkey = "user123";
    uint8_t inputcmd = PROTOCOL_BINARY_CMD_ADD;

    printf("*key: %s cmd: %u\n", inputkey, (unsigned int)inputcmd);

    // Store the return value in a variable
    enum test_return result = test_binary_add_impl(inputkey, inputcmd);

    // should return a number according to the enum:
    // TEST_SKIP = 0
    // TEST_PASS = 1
    // TEST_FAIL = 2
    printf("test return enum: %d\n", result);

    return 1;
}
