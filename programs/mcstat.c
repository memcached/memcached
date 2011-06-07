/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

#include <memcached/protocol_binary.h>

#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Try to connect to the server
 * @param host the name of the server
 * @param port the port to connect to
 * @return a socket descriptor connected to host:port for success, -1 otherwise
 */
static int connect_server(const char *hostname, const char *port)
{
    struct addrinfo *ainfo = NULL;
    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                              .ai_protocol = IPPROTO_TCP,
                              .ai_socktype = SOCK_STREAM };

    if (getaddrinfo(hostname, port, &hints, &ainfo) != 0) {
        return -1;
    }

    int sock = -1;
    struct addrinfo *ai = ainfo;
    while (ai != NULL) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (sock != -1) {
            if (connect(sock, ai->ai_addr, ai->ai_addrlen) != -1) {
                break;
            }
            close(sock);
            sock = -1;
        }
        ai = ai->ai_next;
    }

    freeaddrinfo(ainfo);
    return sock;
}

/**
 * Send the chunk of data to the other side, retry if an error occurs
 * (or terminate the program if retry wouldn't help us)
 * @param sock socket to write data to
 * @param buf buffer to send
 * @param len length of data to send
 */
static void retry_send(int sock, const void* buf, size_t len)
{
    off_t offset = 0;
    const char* ptr = buf;

    do {
        size_t num_bytes = len - offset;
        ssize_t nw = send(sock, ptr + offset, num_bytes, 0);
        if (nw == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to write: %s\n", strerror(errno));
                close(sock);
                exit(1);
            }
        } else {
            offset += nw;
        }
    } while (offset < len);
}

/**
 * Receive a fixed number of bytes from the socket.
 * (Terminate the program if we encounter a hard error...)
 * @param sock socket to receive data from
 * @param buf buffer to store data to
 * @param len length of data to receive
 */
static void retry_recv(int sock, void *buf, size_t len) {
    if (len == 0) {
        return;
    }
    off_t offset = 0;
    do {
        ssize_t nr = recv(sock, ((char*)buf) + offset, len - offset, 0);
        if (nr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to read: %s\n", strerror(errno));
                close(sock);
                exit(1);
            }
        } else {
            if (nr == 0) {
                fprintf(stderr, "Connection closed\n");
                close(sock);
                exit(1);
            }
            offset += nr;
        }
    } while (offset < len);
}

/**
 * Print the key value pair
 * @param key key to print
 * @param keylen length of key to print
 * @param val value to print
 * @param vallen length of value
 */
static void print(const char *key, int keylen, const char *val, int vallen) {
    fputs("STAT ", stdout);
    (void)fwrite(key, keylen, 1, stdout);
    fputs(" ", stdout);
    (void)fwrite(val, vallen, 1, stdout);
    fputs("\n", stdout);
    fflush(stdout);
}

/**
 * Request a stat from the server
 * @param sock socket connected to the server
 * @param key the name of the stat to receive (NULL == ALL)
 */
static void request_stat(int sock, const char *key)
{
    uint32_t buffsize = 0;
    char *buffer = NULL;
    uint16_t keylen = 0;
    if (key != NULL) {
        keylen = (uint16_t)strlen(key);
    }

    protocol_binary_request_stats request = {
        .message.header.request = {
            .magic = PROTOCOL_BINARY_REQ,
            .opcode = PROTOCOL_BINARY_CMD_STAT,
            .keylen = htons(keylen),
            .bodylen = htonl(keylen)
        }
    };

    retry_send(sock, &request, sizeof(request));
    if (keylen > 0) {
        retry_send(sock, key, keylen);
    }

    protocol_binary_response_no_extras response;
    do {
        retry_recv(sock, &response, sizeof(response.bytes));
        if (response.message.header.response.keylen != 0) {
            uint16_t keylen = ntohs(response.message.header.response.keylen);
            uint32_t vallen = ntohl(response.message.header.response.bodylen);
            if (vallen > buffsize) {
                if ((buffer = realloc(buffer, vallen)) == NULL) {
                    fprintf(stderr, "Failed to allocate memory\n");
                    exit(1);
                }
                buffsize = vallen;
            }
            retry_recv(sock, buffer, vallen);
            print(buffer, keylen, buffer + keylen, vallen - keylen);
        }
    } while (response.message.header.response.keylen != 0);
}

/**
 * Program entry point. Connect to a memcached server and use the binary
 * protocol to retrieve a given set of stats.
 *
 * @param argc argument count
 * @param argv argument vector
 * @return 0 if success, error code otherwise
 */
int main(int argc, char **argv)
{
    int cmd;
    const char * const default_ports[] = { "memcache", "11211", NULL };
    const char *port = NULL;
    const char *host = NULL;
    char *ptr;

    /* Initialize the socket subsystem */
    initialize_sockets();

    while ((cmd = getopt(argc, argv, "h:p:")) != EOF) {
        switch (cmd) {
        case 'h' :
            host = optarg;
            ptr = strchr(optarg, ':');
            if (ptr != NULL) {
                *ptr = '\0';
                port = ptr + 1;
            }
            break;
        case 'p':
            port = optarg;
            break;
        default:
            fprintf(stderr,
                    "Usage mcstat [-h host[:port]] [-p port] [statkey]*\n");
            return 1;
        }
    }

    if (host == NULL) {
        host = "localhost";
    }

    int sock = -1;
    if (port == NULL) {
        int ii = 0;
        do {
            port = default_ports[ii++];
            sock = connect_server(host, port);
        } while (sock == -1 && default_ports[ii] != NULL);
    } else {
        sock = connect_server(host, port);
    }

    if (sock == -1) {
        fprintf(stderr, "Failed to connect to memcached server (%s:%s): %s\n",
                host, port, strerror(errno));
        return 1;
    }

    if (optind == argc) {
        request_stat(sock, NULL);
    } else {
        for (int ii = optind; ii < argc; ++ii) {
            request_stat(sock, argv[ii]);
        }
    }

    close(sock);

    return 0;
}
