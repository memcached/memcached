//
// Created by rigon on 11.01.24.
//
#include "defs-testcomp.c"
#include <stdbool.h>
#include "protocol_binary.h"
#include <assert.h>
#include "in.h"
#include "errno.h"
#include "stdint.h"

extern uint __VERIFIER_nondet_uint();

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

    do {
        size_t num_bytes = len - offset;
        if (hickup) {
            if (num_bytes > 1024) {
                num_bytes = (rand() % 1023) + 1;
            }
        }
        ssize_t nw = con->write(con, ptr + offset, num_bytes);
        if (nw == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to write: %s\n", strerror(errno));
                abort();
            }
        } else {
            if (hickup) {
                usleep(100);
            }
            offset += nw;
        }
    } while (offset < len);
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
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd, key,
                                 strlen(key), &value, sizeof(value),
                                 0, 0);

    /* Add should only work the first time */
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (ii == 0) {
            if (cmd == PROTOCOL_BINARY_CMD_ADD) {
                safe_recv_packet(receive.bytes, sizeof(receive.bytes));
                validate_response_header(&receive.response, cmd,
                                         PROTOCOL_BINARY_RESPONSE_SUCCESS);
            }
        } else {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS);
        }
    }

    return TEST_PASS;
}

int main() {
    const char *inputkey = __VERIFIER_nondet_pchar();
    char inputcmd = __VERIFIER_nondet_char();

    printf("*key: %p cmd: %u\n", inputkey, (int)inputcmd);

    test_binary_add_impl(inputkey, (int)inputcmd);

    return 1;
}