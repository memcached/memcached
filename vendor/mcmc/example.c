#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <poll.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "mcmc.h"

// in this form the socket syscalls are handled externally to the client, so
// we need to parse the protocol out of a buffer directly.
static void show_response_buffer(void *c, char *rbuf, size_t bufsize) {
    int status;
    mcmc_resp_t resp;
    char *val = NULL;

    do {
        int bread = recv(mcmc_fd(c), rbuf, bufsize, 0);

        // need to know how far to advance the buffer.
        // resp->reslen + resp->vlen_read works, but feels awkward.
        status = mcmc_parse_buf(c, rbuf, bread, &resp);
    } while (status == MCMC_WANT_READ);

    if (status != MCMC_OK) {
        printf("bad response\n");
    }

    // now we need to read the value back.
    // resp.reslen + resp.vlen is the total length.
    // resp.reslen + resp.vlen_read is how much of the buffer was used.
    // resp.vlen_read vs resp.vlen is how much was read vs how much still
    // needs to be read from the socket.
    if (resp.vlen != resp.vlen_read) {
        // malloc and recv the rest.
        // can/should add convenience functions for this?
        val = malloc(resp.vlen);
        memcpy(val, resp.value, resp.vlen_read);
        size_t toread = resp.vlen - resp.vlen_read;
        char *buf = val + resp.vlen_read;
        do {
            // TODO: bug: check for read == 0
            int read = recv(mcmc_fd(c), buf, toread, 0);
            toread -= read;
        } while (toread > 0);
    } else {
        val = resp.value;
    }

    // TODO: add the rest of the parser loop.
    printf("read a response: %s\n", rbuf);
}
/*
static void show_response(void *c, char *rbuf, size_t bufsize) {
    int status;
    // buffer shouldn't change until the read is completed.
    mcmc_resp_t resp;
    int go = 1;
    while (go) {
        go = 0;
        // TODO: return flags? VALUE_PARTIAL flag?
        status = mcmc_read(c, rbuf, bufsize, &resp);
        if (status == MCMC_OK) {
            // OK means a response of some kind was read.
            char *val;
            // NOTE: is "it's not a miss, and vlen is 0" enough to indicate that
            // a 0 byte value was returned?
            if (resp.vlen != 0) {
                if (resp.vlen == resp.vlen_read) {
                    val = resp.value;
                } else {
                    val = malloc(resp.vlen);
                    int read = 0;
                    do {
                        status = mcmc_read_value(c, val, &resp, &read);
                    } while (status == MCMC_WANT_READ);
                }
                if (resp.vlen > 0) {
                    val[resp.vlen-1] = '\0';
                    printf("Response value: %s\n", val);
                }
            }
            switch (resp.type) {
                case MCMC_RESP_GET:
                    // GET's need to continue until END is seen.
                    printf("in GET mode\n");
                    go = 1;
                    break;
                case MCMC_RESP_END: // ascii done-with-get's
                    printf("END seen\n");
                    break;
                case MCMC_RESP_META: // any meta command. they all return the same.
                    printf("META response seen\n");
                    if (resp.rlen > 0) {
                        resp.rline[resp.rlen-1] = '\0';
                        printf("META response line: %s\n", resp.rline);
                    }
                    break;
                case MCMC_RESP_STAT:
                    // STAT responses. need to call mcmc_read() in loop until
                    // we get an end signal.
                    go = 1;
                    break;
                default:
                    // TODO: type -> str func.
                    fprintf(stderr, "unknown response type: %d\n", resp.type);
                    break;
            }
        } else {
            // some kind of command specific error code (management commands)
            // or protocol error status.
            char code[MCMC_ERROR_CODE_MAX];
            char msg[MCMC_ERROR_MSG_MAX];
            mcmc_get_error(c, code, MCMC_ERROR_CODE_MAX, msg, MCMC_ERROR_MSG_MAX);
            fprintf(stderr, "Got error from mc: status [%d] code [%s] msg: [%s]\n", status, code, msg);
            // some errors don't have a msg. in this case msg[0] will be \0
        }

        int remain = 0;
        // advance us to the next command in the buffer, or ready for the next
        // mc_read().
        char *newbuf = mcmc_buffer_consume(c, &remain);
        printf("remains in buffer: %d\n", remain);
        if (remain == 0) {
            assert(newbuf == NULL);
            // we're done.
        } else {
            // there're still some bytes unconsumed by the client.
            // ensure the next time we call the client, the buffer has those
            // bytes at the front still.
            // NOTE: this _could_ be an entirely different buffer if we copied
            // the data off. The client is just tracking the # of bytes it
            // didn't gobble.
            // In this case we shuffle the bytes back to the front of our read
            // buffer.
            memmove(rbuf, newbuf, remain);
        }
    }
}
*/
void buffer_mode(void) {
    void *c = malloc(mcmc_size(MCMC_OPTION_BLANK));
    size_t bufsize = mcmc_min_buffer_size(MCMC_OPTION_BLANK) * 2;
    char *rbuf = malloc(bufsize);

    int status = mcmc_connect(c, "127.0.0.1", "11211", MCMC_OPTION_BLANK);

    char *requests[5] = {"get foo\r\n",
        "get foob\r\n",
        "mg foo s t v\r\n",
        "mg doof s t v Omoo k\r\n",
        ""};

    for (int x = 0; strlen(requests[x]) != 0; x++) {
        status = mcmc_send_request(c, requests[x], strlen(requests[x]), 1);

        if (status != MCMC_OK) {
            fprintf(stderr, "Failed to send request to memcached\n");
            return;
        }

        // Regardless of what command we sent, this should print out the response.
        show_response_buffer(c, rbuf, bufsize);
    }

}

int main (int argc, char *agv[]) {
    // TODO: detect if C is pre-C11?
    printf("C version: %ld\n", __STDC_VERSION__);

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        exit(1);
    }
/*
    void *c = malloc(mcmc_size(MCMC_OPTION_BLANK));
    // we only "need" the minimum buf size.
    // buffers large enough to fit return values result in fewer syscalls.
    size_t bufsize = mcmc_min_buffer_size(MCMC_OPTION_BLANK) * 2;
    // buffers are also generally agnostic to clients. The buffer must be
    // held and re-used when required by the API. When the buffer is empty,
    // it may be released to a pool or reused with other connections.
    char *rbuf = malloc(bufsize);

    int status;

    // API is blocking by default.
    status = mcmc_connect(c, "127.0.0.1", "11211", MCMC_OPTION_BLANK);

    if (status != MCMC_CONNECTED) {
        // TODO: mc_strerr(c);
        fprintf(stderr, "Failed to connect to memcached\n");
        return -1;
    }

    char *requests[5] = {"get foo\r\n",
        "get foob\r\n",
        "mg foo s t v\r\n",
        "mg doof s t v Omoo k\r\n",
        ""};

    for (int x = 0; strlen(requests[x]) != 0; x++) {
        // provide a buffer, the buffer length, and the number of responses
        // expected. ie; if pipelining many requests, or using noreply semantics.
        // FIXME: not confident "number of expected responses" is worth tracking
        // internally.
        status = mcmc_send_request(c, requests[x], strlen(requests[x]), 1);
        //printf("sent request: %s\n", requests[x]);

        if (status != MCMC_OK) {
            fprintf(stderr, "Failed to send request to memcached\n");
            return -1;
        }

        // Regardless of what command we sent, this should print out the response.
        // TODO: mcmc_read() and friends need to be remade
        show_response(c, rbuf, bufsize);

    }

    status = mcmc_disconnect(c);
    // The only free'ing needed.
    free(c);
*/
    // TODO: stats example.

    /*
    // nonblocking example.
    c = malloc(mcmc_size(MCMC_OPTION_BLANK));
    // reuse bufsize/rbuf.
    status = mcmc_connect(c, "127.0.0.1", "11211", MCMC_OPTION_NONBLOCK);
    printf("nonblock connecting...\n");
    struct pollfd pfds[1];
    if (status == MCMC_CONNECTING) {
        // need to wait for socket to become writeable.
        pfds[0].fd = mcmc_fd(c);
        pfds[0].events = POLLOUT;
        if (poll(pfds, 1, 1000) != 1) {
            fprintf(stderr, "poll on connect timed out or failed\n");
            return -1;
        }
        int err = 0;
        if (pfds[0].revents & POLLOUT && mcmc_check_nonblock_connect(c, &err) == MCMC_OK) {
            printf("asynchronous connection completed: %d\n", err);
        } else {
            printf("failed to connect: %s\n", strerror(err));
            return -1;
        }
    } else {
        perror("connect");
        fprintf(stderr, "bad response to nonblock connection: %d\n", status);
        return -1;
    }

    // TODO: check socket for errors.

    // TODO: send request
    status = mcmc_send_request(c, requests[0], strlen(requests[0]), 1);
    //printf("sent request: %s\n", requests[x]);

    if (status != MCMC_OK) {
        fprintf(stderr, "Failed to send request to memcached\n");
        return -1;
    }

    mcmc_resp_t resp;
    status = mcmc_read(c, rbuf, bufsize, &resp);
    // this could race and fail, depending on the system.
    if (status == MCMC_WANT_READ) {
        printf("got MCMC_WANT_READ from a too-fast read as expected\n");
        pfds[0].fd = mcmc_fd(c);
        pfds[0].events = POLLIN;
        if (poll(pfds, 1, 1000) != 1) {
            fprintf(stderr, "poll on connect timed out or failed\n");
            return -1;
        }
        if (pfds[0].revents & POLLIN) {
            printf("asynchronous read ready\n");
        }

        show_response(c, rbuf, bufsize);
    }
    */

    buffer_mode();
    return 0;
}
