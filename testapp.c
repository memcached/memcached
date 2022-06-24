/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#undef NDEBUG
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "config.h"
#include "cache.h"
#include "crc32c.h"
#include "hash.h"
#include "jenkins_hash.h"
#include "stats_prefix.h"
#include "util.h"
#include "protocol_binary.h"
#ifdef TLS
#include <openssl/ssl.h>
#endif

#define TMP_TEMPLATE "/tmp/test_file.XXXXXXX"

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

hash_func hash;

static ssize_t tcp_read(struct conn *c, void *buf, size_t count);
static ssize_t tcp_write(struct conn *c, const void *buf, size_t count);
#ifdef TLS
static ssize_t ssl_read(struct conn *c, void *buf, size_t count);
static ssize_t ssl_write(struct conn *c, const void *buf, size_t count);
#endif

ssize_t tcp_read(struct conn *c, void *buf, size_t count) {
    assert(c != NULL);
    return read(c->sock, buf, count);
}

ssize_t tcp_write(struct conn *c, const void *buf, size_t count) {
    assert(c != NULL);
    return write(c->sock, buf, count);
}
#ifdef TLS
ssize_t ssl_read(struct conn *c, void *buf, size_t count) {
    assert(c != NULL);
    return SSL_read(c->ssl, buf, count);
}

ssize_t ssl_write(struct conn *c, const void *buf, size_t count) {
    assert(c != NULL);
    return SSL_write(c->ssl, buf, count);
}
#endif

static pid_t server_pid;
static in_port_t port;
static struct conn *con = NULL;
static bool allow_closed_read = false;
static bool enable_ssl = false;

static void close_conn() {
    if (con == NULL) return;
#ifdef TLS
    if (con->ssl) {
        SSL_shutdown(con->ssl);
        SSL_free(con->ssl);
    }
    if (con->ssl_ctx)
        SSL_CTX_free(con->ssl_ctx);
#endif
    if (con->sock > 0) close(con->sock);
    free(con);
    con = NULL;
}

static enum test_return cache_create_test(void)
{
    cache_t *cache = cache_create("test", sizeof(uint32_t), sizeof(char*));
    assert(cache != NULL);
    cache_destroy(cache);
    return TEST_PASS;
}

static enum test_return cache_reuse_test(void)
{
    int ii;
    cache_t *cache = cache_create("test", sizeof(uint32_t), sizeof(char*));
    if (cache == NULL) {
        return TEST_FAIL;
    }
    char *ptr = cache_alloc(cache);
    cache_free(cache, ptr);
    for (ii = 0; ii < 100; ++ii) {
        char *p = cache_alloc(cache);
        assert(p == ptr);
        cache_free(cache, ptr);
    }
    cache_destroy(cache);
    return TEST_PASS;
}


static enum test_return cache_bulkalloc(size_t datasize)
{
    cache_t *cache = cache_create("test", datasize, sizeof(char*));
    if (cache == NULL) {
        return TEST_FAIL;
    }
#define ITERATIONS 1024
    void *ptr[ITERATIONS];

    for (int ii = 0; ii < ITERATIONS; ++ii) {
        ptr[ii] = cache_alloc(cache);
        assert(ptr[ii] != 0);
        memset(ptr[ii], 0xff, datasize);
    }

    for (int ii = 0; ii < ITERATIONS; ++ii) {
        cache_free(cache, ptr[ii]);
    }

#undef ITERATIONS
    cache_destroy(cache);
    return TEST_PASS;
}

static enum test_return test_issue_161(void)
{
    enum test_return ret = cache_bulkalloc(1);
    if (ret == TEST_PASS) {
        ret = cache_bulkalloc(512);
    }

    return ret;
}

static enum test_return cache_redzone_test(void)
{
#ifndef HAVE_UMEM_H
    cache_t *cache = cache_create("test", sizeof(uint32_t), sizeof(char*));

    if (cache == NULL) {
        return TEST_FAIL;
    }
    /* Ignore SIGABRT */
    struct sigaction old_action;
    struct sigaction action = { .sa_handler = SIG_IGN, .sa_flags = 0};
    sigemptyset(&action.sa_mask);
    sigaction(SIGABRT, &action, &old_action);

    /* check memory debug.. */
    char *p = cache_alloc(cache);
    char old = *(p - 1);
    *(p - 1) = 0;
    cache_free(cache, p);
    assert(cache_error == -1);
    *(p - 1) = old;

    p[sizeof(uint32_t)] = 0;
    cache_free(cache, p);
    assert(cache_error == 1);

    /* restore signal handler */
    sigaction(SIGABRT, &old_action, NULL);

    cache_destroy(cache);

    return TEST_PASS;
#else
    return TEST_SKIP;
#endif
}

static enum test_return cache_limit_revised_downward_test(void)
{
    int limit = 10, allocated_num = limit + 1, i;
    char ** alloc_objs = calloc(allocated_num, sizeof(char *));

    cache_t *cache = cache_create("test", sizeof(uint32_t), sizeof(char*));
    assert(cache != NULL);

    /* cache->limit is 0 and we can allocate limit+1 items */
    for (i = 0; i < allocated_num; i++) {
        alloc_objs[i] = cache_alloc(cache);
        assert(alloc_objs[i] != NULL);
    }
    assert(cache->total == allocated_num);

    /* revised downward cache->limit */
    cache_set_limit(cache, limit);

    /* If we free one item, the cache->total should decreased by one*/
    cache_free(cache, alloc_objs[0]);

    assert(cache->total == allocated_num-1);
    cache_destroy(cache);

    free(alloc_objs);

    return TEST_PASS;
}

static enum test_return test_stats_prefix_find(void) {
    PREFIX_STATS *pfs1, *pfs2;

    stats_prefix_clear();
    pfs1 = stats_prefix_find("abc", 3);
    assert(pfs1 == NULL);
    pfs1 = stats_prefix_find("abc|", 4);
    assert(pfs1 == NULL);

    pfs1 = stats_prefix_find("abc:", 4);
    assert(pfs1 != NULL);
    assert(0ULL == (pfs1->num_gets + pfs1->num_sets + pfs1->num_deletes + pfs1->num_hits));
    pfs2 = stats_prefix_find("abc:", 4);
    assert(pfs1 == pfs2);
    pfs2 = stats_prefix_find("abc:d", 5);
    assert(pfs1 == pfs2);
    pfs2 = stats_prefix_find("xyz123:", 6);
    assert(pfs1 != pfs2);
    pfs2 = stats_prefix_find("ab:", 3);
    assert(pfs1 != pfs2);
    return TEST_PASS;
}

static enum test_return test_stats_prefix_record_get(void) {
    PREFIX_STATS *pfs;
    stats_prefix_clear();

    stats_prefix_record_get("abc:123", 7, false);
    pfs = stats_prefix_find("abc:123", 7);
    if (pfs == NULL) {
        return TEST_FAIL;
    }
    assert(1 == pfs->num_gets);
    assert(0 == pfs->num_hits);
    stats_prefix_record_get("abc:456", 7, false);
    assert(2 == pfs->num_gets);
    assert(0 == pfs->num_hits);
    stats_prefix_record_get("abc:456", 7, true);
    assert(3 == pfs->num_gets);
    assert(1 == pfs->num_hits);
    stats_prefix_record_get("def:", 4, true);
    assert(3 == pfs->num_gets);
    assert(1 == pfs->num_hits);
    return TEST_PASS;
}

static enum test_return test_stats_prefix_record_delete(void) {
    PREFIX_STATS *pfs;
    stats_prefix_clear();

    stats_prefix_record_delete("abc:123", 7);
    pfs = stats_prefix_find("abc:123", 7);
    if (pfs == NULL) {
        return TEST_FAIL;
    }
    assert(0 == pfs->num_gets);
    assert(0 == pfs->num_hits);
    assert(1 == pfs->num_deletes);
    assert(0 == pfs->num_sets);
    stats_prefix_record_delete("def:", 4);
    assert(1 == pfs->num_deletes);
    return TEST_PASS;
}

static enum test_return test_stats_prefix_record_set(void) {
    PREFIX_STATS *pfs;
    stats_prefix_clear();

    stats_prefix_record_set("abc:123", 7);
    pfs = stats_prefix_find("abc:123", 7);
    if (pfs == NULL) {
        return TEST_FAIL;
    }
    assert(0 == pfs->num_gets);
    assert(0 == pfs->num_hits);
    assert(0 == pfs->num_deletes);
    assert(1 == pfs->num_sets);
    stats_prefix_record_delete("def:", 4);
    assert(1 == pfs->num_sets);
    return TEST_PASS;
}

static enum test_return test_stats_prefix_dump(void) {
    int hashval = hash("abc", 3) % PREFIX_HASH_SIZE;
    char tmp[500];
    char *buf;
    const char *expected;
    int keynum;
    int length;

    stats_prefix_clear();

    assert(strcmp("END\r\n", (buf = stats_prefix_dump(&length))) == 0);
    assert(5 == length);
    stats_prefix_record_set("abc:123", 7);
    free(buf);
    expected = "PREFIX abc get 0 hit 0 set 1 del 0\r\nEND\r\n";
    assert(strcmp(expected, (buf = stats_prefix_dump(&length))) == 0);
    assert(strlen(expected) == length);
    stats_prefix_record_get("abc:123", 7, false);
    free(buf);
    expected = "PREFIX abc get 1 hit 0 set 1 del 0\r\nEND\r\n";
    assert(strcmp(expected, (buf = stats_prefix_dump(&length))) == 0);
    assert(strlen(expected) == length);
    stats_prefix_record_get("abc:123", 7, true);
    free(buf);
    expected = "PREFIX abc get 2 hit 1 set 1 del 0\r\nEND\r\n";
    assert(strcmp(expected, (buf = stats_prefix_dump(&length))) == 0);
    assert(strlen(expected) == length);
    stats_prefix_record_delete("abc:123", 7);
    free(buf);
    expected = "PREFIX abc get 2 hit 1 set 1 del 1\r\nEND\r\n";
    assert(strcmp(expected, (buf = stats_prefix_dump(&length))) == 0);
    assert(strlen(expected) == length);

    stats_prefix_record_delete("def:123", 7);
    free(buf);
    /* NOTE: Prefixes can be dumped in any order, so we verify that
       each expected line is present in the string. */
    buf = stats_prefix_dump(&length);
    assert(strstr(buf, "PREFIX abc get 2 hit 1 set 1 del 1\r\n") != NULL);
    assert(strstr(buf, "PREFIX def get 0 hit 0 set 0 del 1\r\n") != NULL);
    assert(strstr(buf, "END\r\n") != NULL);
    free(buf);

    /* Find a key that hashes to the same bucket as "abc" */
    bool found_match = false;
    for (keynum = 0; keynum < PREFIX_HASH_SIZE * 100; keynum++) {
        snprintf(tmp, sizeof(tmp), "%d:", keynum);
        /* -1 because only the prefix portion is used when hashing */
        if (hashval == hash(tmp, strlen(tmp) - 1) % PREFIX_HASH_SIZE) {
            found_match = true;
            break;
        }
    }
    assert(found_match);
    stats_prefix_record_set(tmp, strlen(tmp));
    buf = stats_prefix_dump(&length);
    assert(strstr(buf, "PREFIX abc get 2 hit 1 set 1 del 1\r\n") != NULL);
    assert(strstr(buf, "PREFIX def get 0 hit 0 set 0 del 1\r\n") != NULL);
    assert(strstr(buf, "END\r\n") != NULL);
    snprintf(tmp, sizeof(tmp), "PREFIX %d get 0 hit 0 set 1 del 0\r\n", keynum);
    assert(strstr(buf, tmp) != NULL);
    free(buf);

    /* Marking the end of these tests */
    stats_prefix_clear();

    return TEST_PASS;
}

static enum test_return test_safe_strtoul(void) {
    uint32_t val;
    assert(safe_strtoul("123", &val));
    assert(val == 123);
    assert(safe_strtoul("+123", &val));
    assert(val == 123);
    assert(!safe_strtoul("", &val));  // empty
    assert(!safe_strtoul("123BOGUS", &val));  // non-numeric
    assert(!safe_strtoul(" issue221", &val));  // non-numeric
    /* Not sure what it does, but this works with ICC :/
       assert(!safe_strtoul("92837498237498237498029383", &val)); // out of range
    */

    // extremes:
    assert(safe_strtoul("4294967295", &val)); // 2**32 - 1
    assert(val == 4294967295L);
    /* This actually works on 64-bit ubuntu
       assert(!safe_strtoul("4294967296", &val)); // 2**32
    */
    assert(!safe_strtoul("-1", &val));  // negative
    return TEST_PASS;
}


static enum test_return test_safe_strtoull(void) {
    uint64_t val;
    assert(safe_strtoull("123", &val));
    assert(val == 123);
    assert(safe_strtoull("+123", &val));
    assert(val == 123);
    assert(!safe_strtoull("", &val));  // empty
    assert(!safe_strtoull("123BOGUS", &val));  // non-numeric
    assert(!safe_strtoull("92837498237498237498029383", &val)); // out of range
    assert(!safe_strtoull(" issue221", &val));  // non-numeric

    // extremes:
    assert(safe_strtoull("18446744073709551615", &val)); // 2**64 - 1
    assert(val == 18446744073709551615ULL);
    assert(!safe_strtoull("18446744073709551616", &val)); // 2**64
    assert(!safe_strtoull("-1", &val));  // negative
    return TEST_PASS;
}

static enum test_return test_safe_strtoll(void) {
    int64_t val;
    assert(safe_strtoll("123", &val));
    assert(val == 123);
    assert(safe_strtoll("+123", &val));
    assert(val == 123);
    assert(safe_strtoll("-123", &val));
    assert(val == -123);
    assert(!safe_strtoll("", &val));  // empty
    assert(!safe_strtoll("123BOGUS", &val));  // non-numeric
    assert(!safe_strtoll("92837498237498237498029383", &val)); // out of range
    assert(!safe_strtoll(" issue221", &val));  // non-numeric

    // extremes:
    assert(!safe_strtoll("18446744073709551615", &val)); // 2**64 - 1
    assert(safe_strtoll("9223372036854775807", &val)); // 2**63 - 1
    assert(val == 9223372036854775807LL);
    /*
      assert(safe_strtoll("-9223372036854775808", &val)); // -2**63
      assert(val == -9223372036854775808LL);
    */
    assert(!safe_strtoll("-9223372036854775809", &val)); // -2**63 - 1

    // We'll allow space to terminate the string.  And leading space.
    assert(safe_strtoll(" 123 foo", &val));
    assert(val == 123);
    return TEST_PASS;
}

static enum test_return test_safe_strtol(void) {
    int32_t val;
    assert(safe_strtol("123", &val));
    assert(val == 123);
    assert(safe_strtol("+123", &val));
    assert(val == 123);
    assert(safe_strtol("-123", &val));
    assert(val == -123);
    assert(!safe_strtol("", &val));  // empty
    assert(!safe_strtol("123BOGUS", &val));  // non-numeric
    assert(!safe_strtol("92837498237498237498029383", &val)); // out of range
    assert(!safe_strtol(" issue221", &val));  // non-numeric

    // extremes:
    /* This actually works on 64-bit ubuntu
       assert(!safe_strtol("2147483648", &val)); // (expt 2.0 31.0)
    */
    assert(safe_strtol("2147483647", &val)); // (- (expt 2.0 31) 1)
    assert(val == 2147483647L);
    /* This actually works on 64-bit ubuntu
       assert(!safe_strtol("-2147483649", &val)); // (- (expt -2.0 31) 1)
    */

    // We'll allow space to terminate the string.  And leading space.
    assert(safe_strtol(" 123 foo", &val));
    assert(val == 123);
    return TEST_PASS;
}

/**
 * Function to start the server and let it listen on a random port
 *
 * @param port_out where to store the TCP port number the server is
 *                 listening on
 * @param daemon set to true if you want to run the memcached server
 *               as a daemon process
 * @return the pid of the memcached server
 */
static pid_t start_server(in_port_t *port_out, bool daemon, int timeout) {
    char environment[80];
    snprintf(environment, sizeof(environment),
             "MEMCACHED_PORT_FILENAME=/tmp/ports.%lu", (long)getpid());
    char *filename= environment + strlen("MEMCACHED_PORT_FILENAME=");
    char pid_file[80];
    snprintf(pid_file, sizeof(pid_file), "/tmp/pid.%lu", (long)getpid());

    remove(filename);
    remove(pid_file);

#ifdef __sun
    /* I want to name the corefiles differently so that they don't
       overwrite each other
    */
    char coreadm[128];
    snprintf(coreadm, sizeof(coreadm),
             "coreadm -p core.%%f.%%p %lu", (unsigned long)getpid());
    system(coreadm);
#endif

    pid_t pid = fork();
    assert(pid != -1);
    if (pid == 0) {
        /* Child */
        char *argv[24];
        int arg = 0;
        char tmo[24];
        snprintf(tmo, sizeof(tmo), "%u", timeout);

        putenv(environment);
#ifdef __sun
        putenv("LD_PRELOAD=watchmalloc.so.1");
        putenv("MALLOC_DEBUG=WATCH");
#endif

        if (!daemon) {
            argv[arg++] = "./timedrun";
            argv[arg++] = tmo;
        }
        argv[arg++] = "./memcached-debug";
        argv[arg++] = "-A";
        argv[arg++] = "-p";
        argv[arg++] = "-1";
        argv[arg++] = "-U";
        argv[arg++] = "0";
#ifdef TLS
        if (enable_ssl) {
            argv[arg++] = "-Z";
            argv[arg++] = "-o";
            argv[arg++] = "ssl_chain_cert=t/server_crt.pem";
            argv[arg++] = "-o";
            argv[arg++] = "ssl_key=t/server_key.pem";
        }
#endif
        /* Handle rpmbuild and the like doing this as root */
        if (getuid() == 0) {
            argv[arg++] = "-u";
            argv[arg++] = "root";
        }
        if (daemon) {
            argv[arg++] = "-d";
            argv[arg++] = "-P";
            argv[arg++] = pid_file;
        }
#ifdef MESSAGE_DEBUG
         argv[arg++] = "-vvv";
#endif
#ifdef HAVE_DROP_PRIVILEGES
        argv[arg++] = "-o";
        argv[arg++] = "relaxed_privileges";
#endif
        argv[arg++] = NULL;
        assert(execv(argv[0], argv) != -1);
    }

    /* Yeah just let us "busy-wait" for the file to be created ;-) */
    useconds_t wait_timeout = 1000000 * 10;
    useconds_t wait = 1000;
    while (access(filename, F_OK) == -1 && wait_timeout > 0) {
        usleep(wait);
        wait_timeout -= (wait > wait_timeout ? wait_timeout : wait);
    }

    if (access(filename, F_OK) == -1) {
        fprintf(stderr, "Failed to start the memcached server.\n");
        assert(false);
    }

    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open the file containing port numbers: %s\n",
                strerror(errno));
        assert(false);
    }

    *port_out = (in_port_t)-1;
    char buffer[80];
    while ((fgets(buffer, sizeof(buffer), fp)) != NULL) {
        if (strncmp(buffer, "TCP INET: ", 10) == 0) {
            int32_t val;
            assert(safe_strtol(buffer + 10, &val));
            *port_out = (in_port_t)val;
        }
    }
    fclose(fp);
    assert(remove(filename) == 0);

    if (daemon) {
        /* loop and wait for the pid file.. There is a potential race
         * condition that the server just created the file but isn't
         * finished writing the content, so we loop a few times
         * reading as well */
        while (access(pid_file, F_OK) == -1) {
            usleep(10);
        }

        fp = fopen(pid_file, "r");
        if (fp == NULL) {
            fprintf(stderr, "Failed to open pid file: %s\n",
                    strerror(errno));
            assert(false);
        }

        /* Avoid race by retrying 20 times */
        for (int x = 0; x < 20 && fgets(buffer, sizeof(buffer), fp) == NULL; x++) {
            usleep(10);
        }
        fclose(fp);

        int32_t val;
        assert(safe_strtol(buffer, &val));
        pid = (pid_t)val;
    }

    return pid;
}

static enum test_return test_issue_44(void) {
    in_port_t port;
    pid_t pid = start_server(&port, true, 600);
    assert(kill(pid, SIGHUP) == 0);
    sleep(1);
    assert(kill(pid, SIGTERM) == 0);

    return TEST_PASS;
}

static struct addrinfo *lookuphost(const char *hostname, in_port_t port)
{
    struct addrinfo *ai = 0;
    struct addrinfo hints = { .ai_family = AF_UNSPEC,
                              .ai_protocol = IPPROTO_TCP,
                              .ai_socktype = SOCK_STREAM };
    char service[NI_MAXSERV];
    int error;

    (void)snprintf(service, NI_MAXSERV, "%d", port);
    if ((error = getaddrinfo(hostname, service, &hints, &ai)) != 0) {
       if (error != EAI_SYSTEM) {
          fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
       } else {
          perror("getaddrinfo()");
       }
    }

    return ai;
}

static struct conn *connect_server(const char *hostname, in_port_t port,
                            bool nonblock, const bool ssl)
{
    struct conn *c;
    if (!(c = (struct conn *)calloc(1, sizeof(struct conn)))) {
        fprintf(stderr, "Failed to allocate the client connection: %s\n",
                strerror(errno));
        return NULL;
    }

    struct addrinfo *ai = lookuphost(hostname, port);
    int sock = -1;
    if (ai != NULL) {
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
    }
    c->sock = sock;
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

static enum test_return test_vperror(void) {
    int rv = 0;
    int oldstderr = dup(STDERR_FILENO);
    assert(oldstderr >= 0);
    char tmpl[sizeof(TMP_TEMPLATE)+1];
    strncpy(tmpl, TMP_TEMPLATE, sizeof(TMP_TEMPLATE)+1);

    int newfile = mkstemp(tmpl);
    assert(newfile > 0);
    rv = dup2(newfile, STDERR_FILENO);
    assert(rv == STDERR_FILENO);
    rv = close(newfile);
    assert(rv == 0);

    errno = EIO;
    vperror("Old McDonald had a farm.  %s", "EI EIO");

    /* Restore stderr */
    rv = dup2(oldstderr, STDERR_FILENO);
    assert(rv == STDERR_FILENO);


    /* Go read the file */
    char buf[80] = { 0 };
    FILE *efile = fopen(tmpl, "r");
    assert(efile);
    char *prv = fgets(buf, sizeof(buf), efile);
    assert(prv);
    fclose(efile);

    unlink(tmpl);

    char expected[80] = { 0 };
    snprintf(expected, sizeof(expected),
             "Old McDonald had a farm.  EI EIO: %s\n", strerror(EIO));

    /*
    fprintf(stderr,
            "\nExpected:  ``%s''"
            "\nGot:       ``%s''\n", expected, buf);
    */

    return strcmp(expected, buf) == 0 ? TEST_PASS : TEST_FAIL;
}

static void send_ascii_command(const char *buf) {
    off_t offset = 0;
    const char* ptr = buf;
    size_t len = strlen(buf);

    do {
        ssize_t nw = con->write((void*)con, ptr + offset, len - offset);
        if (nw == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to write: %s\n", strerror(errno));
                abort();
            }
        } else {
            offset += nw;
        }
    } while (offset < len);
}

/*
 * This is a dead slow single byte read, but it should only read out
 * _one_ response and I don't have an input buffer... The current
 * implementation only supports single-line responses, so if you want to use
 * it for get commands you need to implement that first ;-)
 */
static void read_ascii_response(char *buffer, size_t size) {
    off_t offset = 0;
    bool need_more = true;
    do {
        ssize_t nr = con->read(con, buffer + offset, 1);
        if (nr == -1) {
            if (errno != EINTR) {
                fprintf(stderr, "Failed to read: %s\n", strerror(errno));
                abort();
            }
        } else {
            assert(nr == 1);
            if (buffer[offset] == '\n') {
                need_more = false;
                buffer[offset + 1] = '\0';
            }
            offset += nr;
            assert(offset + 1 < size);
        }
    } while (need_more);
}

static enum test_return test_issue_92(void) {
    char buffer[1024];

    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);

    send_ascii_command("stats cachedump 1 0 0\r\n");

    read_ascii_response(buffer, sizeof(buffer));
    assert(strncmp(buffer, "END", strlen("END")) == 0);

    send_ascii_command("stats cachedump 200 0 0\r\n");
    read_ascii_response(buffer, sizeof(buffer));
    assert(strncmp(buffer, "CLIENT_ERROR", strlen("CLIENT_ERROR")) == 0);

    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);
    return TEST_PASS;
}

static enum test_return test_crc32c(void) {
    uint32_t crc_hw, crc_sw;

    char buffer[256];
    for (int x = 0; x < 256; x++)
        buffer[x] = x;

    /* Compare hardware to software implementation */
    crc_hw = crc32c(0, buffer, 256);
    crc_sw = crc32c_sw(0, buffer, 256);
    assert(crc_hw == 0x9c44184b);
    assert(crc_sw == 0x9c44184b);

    /* Test that passing a CRC in also works */
    crc_hw = crc32c(crc_hw, buffer, 256);
    crc_sw = crc32c_sw(crc_sw, buffer, 256);
    assert(crc_hw == 0xae10ee5a);
    assert(crc_sw == 0xae10ee5a);

    /* Test odd offsets/sizes */
    crc_hw = crc32c(crc_hw, buffer + 1, 256 - 2);
    crc_sw = crc32c_sw(crc_sw, buffer + 1, 256 - 2);
    assert(crc_hw == 0xed37b906);
    assert(crc_sw == 0xed37b906);

    return TEST_PASS;
}

static enum test_return test_issue_102(void) {
    char buffer[4096];
    memset(buffer, ' ', sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';

    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);

    send_ascii_command(buffer);
    /* verify that the server closed the connection */
    assert(con->read(con, buffer, sizeof(buffer)) == 0);

    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);

    snprintf(buffer, sizeof(buffer), "gets ");
    size_t offset = 5;
    while (offset < 4000) {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                           "%010u ", (unsigned int)offset);
    }

    send_ascii_command(buffer);
    usleep(250);

    send_ascii_command("\r\n");
    char rsp[80];
    read_ascii_response(rsp, sizeof(rsp));
    assert(strncmp(rsp, "END", strlen("END")) == 0);
    buffer[3]= ' ';
    send_ascii_command(buffer);
    usleep(250);
    send_ascii_command("\r\n");
    read_ascii_response(rsp, sizeof(rsp));
    assert(strncmp(rsp, "END", strlen("END")) == 0);

    memset(buffer, ' ', sizeof(buffer));
    int len = snprintf(buffer + 101, sizeof(buffer) - 101, "gets foo");
    buffer[101 + len] = ' ';
    buffer[sizeof(buffer) - 1] = '\0';
    send_ascii_command(buffer);
    /* verify that the server closed the connection */
    assert(con->read(con, buffer, sizeof(buffer)) == 0);

    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);

    return TEST_PASS;
}

static enum test_return start_memcached_server(void) {
    server_pid = start_server(&port, false, 600);
    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);
    return TEST_PASS;
}

static enum test_return stop_memcached_server(void) {
    close_conn();
    if (server_pid != -1) {
        assert(kill(server_pid, SIGTERM) == 0);
    }

    return TEST_PASS;
}

static enum test_return shutdown_memcached_server(void) {
    char buffer[1024];

    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);

    send_ascii_command("shutdown\r\n");
    /* verify that the server closed the connection */
    assert(con->read(con, buffer, sizeof(buffer)) == 0);

    close_conn();

    /* We set server_pid to -1 so that we don't later call kill() */
    if (kill(server_pid, 0) == 0) {
        server_pid = -1;
    }

    return TEST_PASS;
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

static off_t storage_command(char*buf,
                             size_t bufsz,
                             uint8_t cmd,
                             const void* key,
                             size_t keylen,
                             const void* dta,
                             size_t dtalen,
                             uint32_t flags,
                             uint32_t exp) {
    /* all of the storage commands use the same command layout */
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

static off_t ext_command(char* buf,
                         size_t bufsz,
                         uint8_t cmd,
                         const void* ext,
                         size_t extlen,
                         const void* key,
                         size_t keylen,
                         const void* dta,
                         size_t dtalen) {
    protocol_binary_request_no_extras *request = (void*)buf;
    assert(bufsz > sizeof(*request) + extlen + keylen + dtalen);

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;
    request->message.header.request.extlen = extlen;
    request->message.header.request.keylen = htons(keylen);
    request->message.header.request.bodylen = htonl(extlen + keylen + dtalen);
    request->message.header.request.opaque = 0xdeadbeef;

    off_t ext_offset = sizeof(protocol_binary_request_no_extras);
    off_t key_offset = ext_offset + extlen;
    off_t dta_offset = key_offset + keylen;

    if (ext != NULL) {
        memcpy(buf + ext_offset, ext, extlen);
    }
    if (key != NULL) {
        memcpy(buf + key_offset, key, keylen);
    }
    if (dta != NULL) {
        memcpy(buf + dta_offset, dta, dtalen);
    }

    return sizeof(*request) + extlen + keylen + dtalen;
}

static off_t raw_command(char* buf,
                         size_t bufsz,
                         uint8_t cmd,
                         const void* key,
                         size_t keylen,
                         const void* dta,
                         size_t dtalen) {
    /* all of the storage commands use the same command layout */
    return ext_command(buf, bufsz, cmd, NULL, 0, key, keylen, dta, dtalen);
}

static off_t flush_command(char* buf, size_t bufsz, uint8_t cmd, uint32_t exptime, bool use_extra) {
    protocol_binary_request_flush *request = (void*)buf;
    assert(bufsz > sizeof(*request));

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;

    off_t size = sizeof(protocol_binary_request_no_extras);
    if (use_extra) {
        request->message.header.request.extlen = 4;
        request->message.body.expiration = htonl(exptime);
        request->message.header.request.bodylen = htonl(4);
        size += 4;
    }

    request->message.header.request.opaque = 0xdeadbeef;

    return size;
}


static off_t touch_command(char* buf,
                           size_t bufsz,
                           uint8_t cmd,
                           const void* key,
                           size_t keylen,
                           uint32_t exptime) {
    protocol_binary_request_touch *request = (void*)buf;
    assert(bufsz > sizeof(*request));

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;

    request->message.header.request.keylen = htons(keylen);
    request->message.header.request.extlen = 4;
    request->message.body.expiration = htonl(exptime);
    request->message.header.request.bodylen = htonl(keylen + 4);

    request->message.header.request.opaque = 0xdeadbeef;

    off_t key_offset = sizeof(protocol_binary_request_no_extras) + 4;

    memcpy(buf + key_offset, key, keylen);
    return sizeof(protocol_binary_request_no_extras) + 4 + keylen;
}

static off_t arithmetic_command(char* buf,
                                size_t bufsz,
                                uint8_t cmd,
                                const void* key,
                                size_t keylen,
                                uint64_t delta,
                                uint64_t initial,
                                uint32_t exp) {
    protocol_binary_request_incr *request = (void*)buf;
    assert(bufsz > sizeof(*request) + keylen);

    memset(request, 0, sizeof(*request));
    request->message.header.request.magic = PROTOCOL_BINARY_REQ;
    request->message.header.request.opcode = cmd;
    request->message.header.request.keylen = htons(keylen);
    request->message.header.request.extlen = 20;
    request->message.header.request.bodylen = htonl(keylen + 20);
    request->message.header.request.opaque = 0xdeadbeef;
    request->message.body.delta = htonll(delta);
    request->message.body.initial = htonll(initial);
    request->message.body.expiration = htonl(exp);

    off_t key_offset = sizeof(protocol_binary_request_no_extras) + 20;

    memcpy(buf + key_offset, key, keylen);
    return key_offset + keylen;
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

static enum test_return test_binary_noop(void) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_NOOP,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_NOOP,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    return TEST_PASS;
}

static enum test_return test_binary_quit_impl(uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;
    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             cmd, NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_QUIT) {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_QUIT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    /* Socket should be closed now, read should return 0 */
    assert(con->read(con, buffer.bytes, sizeof(buffer.bytes)) == 0);
    close_conn();
    con = connect_server("127.0.0.1", port, false, enable_ssl);
    assert(con);

    return TEST_PASS;
}

static enum test_return test_binary_quit(void) {
    return test_binary_quit_impl(PROTOCOL_BINARY_CMD_QUIT);
}

static enum test_return test_binary_quitq(void) {
    return test_binary_quit_impl(PROTOCOL_BINARY_CMD_QUITQ);
}

static enum test_return test_binary_set_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    uint64_t value = 0xdeadbeefdeadcafe;
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                                 key, strlen(key), &value, sizeof(value),
                                 0, 0);

    /* Set should work over and over again */
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_SET) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
        }
    }

    if (cmd == PROTOCOL_BINARY_CMD_SETQ) {
        return test_binary_noop();
    }

    send.request.message.header.request.cas = receive.response.message.header.response.cas;
    safe_send(send.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_SET) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
        assert(receive.response.message.header.response.cas != send.request.message.header.request.cas);
    } else {
        return test_binary_noop();
    }

    return TEST_PASS;
}

static enum test_return test_binary_set(void) {
    return test_binary_set_impl("test_binary_set", PROTOCOL_BINARY_CMD_SET);
}

static enum test_return test_binary_setq(void) {
    return test_binary_set_impl("test_binary_setq", PROTOCOL_BINARY_CMD_SETQ);
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

static enum test_return test_binary_add(void) {
    return test_binary_add_impl("test_binary_add", PROTOCOL_BINARY_CMD_ADD);
}

static enum test_return test_binary_addq(void) {
    return test_binary_add_impl("test_binary_addq", PROTOCOL_BINARY_CMD_ADDQ);
}

static enum test_return test_binary_replace_impl(const char* key, uint8_t cmd) {
    uint64_t value = 0xdeadbeefdeadcafe;
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                                 key, strlen(key), &value, sizeof(value),
                                 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), &value, sizeof(value), 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = storage_command(send.bytes, sizeof(send.bytes), cmd,
                          key, strlen(key), &value, sizeof(value), 0, 0);
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_REPLACE) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response,
                                     PROTOCOL_BINARY_CMD_REPLACE,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
        }
    }

    if (cmd == PROTOCOL_BINARY_CMD_REPLACEQ) {
        test_binary_noop();
    }

    return TEST_PASS;
}

static enum test_return test_binary_replace(void) {
    return test_binary_replace_impl("test_binary_replace",
                                    PROTOCOL_BINARY_CMD_REPLACE);
}

static enum test_return test_binary_replaceq(void) {
    return test_binary_replace_impl("test_binary_replaceq",
                                    PROTOCOL_BINARY_CMD_REPLACEQ);
}

static enum test_return test_binary_delete_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                             key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), NULL, 0, 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes),
                      cmd, key, strlen(key), NULL, 0);
    safe_send(send.bytes, len, false);

    if (cmd == PROTOCOL_BINARY_CMD_DELETE) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_DELETE,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    return TEST_PASS;
}

static enum test_return test_binary_delete(void) {
    return test_binary_delete_impl("test_binary_delete",
                                   PROTOCOL_BINARY_CMD_DELETE);
}

static enum test_return test_binary_deleteq(void) {
    return test_binary_delete_impl("test_binary_deleteq",
                                   PROTOCOL_BINARY_CMD_DELETEQ);
}

static enum test_return test_binary_get_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;

    uint32_t expiration = htonl(3600);
    size_t extlen = 0;
    if (cmd == PROTOCOL_BINARY_CMD_GAT || cmd == PROTOCOL_BINARY_CMD_GATK)
        extlen = sizeof(expiration);

    size_t len = ext_command(send.bytes, sizeof(send.bytes), cmd,
                             extlen ? &expiration : NULL, extlen,
                             key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), NULL, 0,
                          0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    /* run a little pipeline test ;-) */
    len = 0;
    int ii;
    for (ii = 0; ii < 10; ++ii) {
        union {
            protocol_binary_request_no_extras request;
            char bytes[1024];
        } temp;
        size_t l = ext_command(temp.bytes, sizeof(temp.bytes), cmd,
                               extlen ? &expiration : NULL, extlen,
                               key, strlen(key), NULL, 0);
        memcpy(send.bytes + len, temp.bytes, l);
        len += l;
    }

    safe_send(send.bytes, len, false);
    for (ii = 0; ii < 10; ++ii) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    return TEST_PASS;
}

static enum test_return test_binary_get(void) {
    return test_binary_get_impl("test_binary_get", PROTOCOL_BINARY_CMD_GET);
}

static enum test_return test_binary_getk(void) {
    return test_binary_get_impl("test_binary_getk", PROTOCOL_BINARY_CMD_GETK);
}

static enum test_return test_binary_gat(void) {
    return test_binary_get_impl("test_binary_gat", PROTOCOL_BINARY_CMD_GAT);
}

static enum test_return test_binary_gatk(void) {
    return test_binary_get_impl("test_binary_gatk", PROTOCOL_BINARY_CMD_GATK);
}

static enum test_return test_binary_getq_impl(const char *key, uint8_t cmd) {
    const char *missing = "test_binary_getq_missing";
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, temp, receive;

    uint32_t expiration = htonl(3600);
    size_t extlen = 0;
    if (cmd == PROTOCOL_BINARY_CMD_GATQ || cmd == PROTOCOL_BINARY_CMD_GATKQ)
        extlen = sizeof(expiration);

    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_BINARY_CMD_ADD,
                                 key, strlen(key), NULL, 0,
                                 0, 0);
    size_t len2 = ext_command(temp.bytes, sizeof(temp.bytes), cmd,
                              extlen ? &expiration : NULL, extlen,
                              missing, strlen(missing), NULL, 0);
    /* I need to change the first opaque so that I can separate the two
     * return packets */
    temp.request.message.header.request.opaque = 0xfeedface;
    memcpy(send.bytes + len, temp.bytes, len2);
    len += len2;

    len2 = ext_command(temp.bytes, sizeof(temp.bytes), cmd,
                       extlen ? &expiration : NULL, extlen,
                       key, strlen(key), NULL, 0);
    memcpy(send.bytes + len, temp.bytes, len2);
    len += len2;

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);
    /* The first GETQ shouldn't return anything */
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    return TEST_PASS;
}

static enum test_return test_binary_getq(void) {
    return test_binary_getq_impl("test_binary_getq", PROTOCOL_BINARY_CMD_GETQ);
}

static enum test_return test_binary_getkq(void) {
    return test_binary_getq_impl("test_binary_getkq", PROTOCOL_BINARY_CMD_GETKQ);
}

static enum test_return test_binary_gatq(void) {
    return test_binary_getq_impl("test_binary_gatq", PROTOCOL_BINARY_CMD_GATQ);
}

static enum test_return test_binary_gatkq(void) {
    return test_binary_getq_impl("test_binary_gatkq", PROTOCOL_BINARY_CMD_GATKQ);
}

static enum test_return test_binary_incr_impl(const char* key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response_header;
        protocol_binary_response_incr response;
        char bytes[1024];
    } send, receive;
    size_t len = arithmetic_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), 1, 0, 0);

    int ii;
    for (ii = 0; ii < 10; ++ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_INCREMENT) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response_header, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
            assert(ntohll(receive.response.message.body.value) == ii);
        }
    }

    if (cmd == PROTOCOL_BINARY_CMD_INCREMENTQ) {
        test_binary_noop();
    }
    return TEST_PASS;
}

static enum test_return test_binary_incr(void) {
    return test_binary_incr_impl("test_binary_incr",
                                 PROTOCOL_BINARY_CMD_INCREMENT);
}

static enum test_return test_binary_incrq(void) {
    return test_binary_incr_impl("test_binary_incrq",
                                 PROTOCOL_BINARY_CMD_INCREMENTQ);
}

static enum test_return test_binary_decr_impl(const char* key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response_header;
        protocol_binary_response_decr response;
        char bytes[1024];
    } send, receive;
    size_t len = arithmetic_command(send.bytes, sizeof(send.bytes), cmd,
                                    key, strlen(key), 1, 9, 0);

    int ii;
    for (ii = 9; ii >= 0; --ii) {
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_DECREMENT) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response_header, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
            assert(ntohll(receive.response.message.body.value) == ii);
        }
    }

    /* decr on 0 should not wrap */
    safe_send(send.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_DECREMENT) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response_header, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
        assert(ntohll(receive.response.message.body.value) == 0);
    } else {
        test_binary_noop();
    }

    return TEST_PASS;
}

static enum test_return test_binary_decr(void) {
    return test_binary_decr_impl("test_binary_decr",
                                 PROTOCOL_BINARY_CMD_DECREMENT);
}

static enum test_return test_binary_decrq(void) {
    return test_binary_decr_impl("test_binary_decrq",
                                 PROTOCOL_BINARY_CMD_DECREMENTQ);
}

static enum test_return test_binary_version(void) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_VERSION,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
    validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_VERSION,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    return TEST_PASS;
}

static enum test_return test_binary_flush_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;

    size_t len = storage_command(send.bytes, sizeof(send.bytes),
                                 PROTOCOL_BINARY_CMD_ADD,
                                 key, strlen(key), NULL, 0, 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = flush_command(send.bytes, sizeof(send.bytes), cmd, 2, true);
    safe_send(send.bytes, len, false);
    if (cmd == PROTOCOL_BINARY_CMD_FLUSH) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_GET,
                      key, strlen(key), NULL, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    sleep(2);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                             PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);

    int ii;
    for (ii = 0; ii < 2; ++ii) {
        len = storage_command(send.bytes, sizeof(send.bytes),
                              PROTOCOL_BINARY_CMD_ADD,
                              key, strlen(key), NULL, 0, 0, 0);
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);

        len = flush_command(send.bytes, sizeof(send.bytes), cmd, 0, ii == 0);
        safe_send(send.bytes, len, false);
        if (cmd == PROTOCOL_BINARY_CMD_FLUSH) {
            safe_recv_packet(receive.bytes, sizeof(receive.bytes));
            validate_response_header(&receive.response, cmd,
                                     PROTOCOL_BINARY_RESPONSE_SUCCESS);
        }

        len = raw_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_GET,
                          key, strlen(key), NULL, 0);
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GET,
                                 PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    }

    return TEST_PASS;
}

static enum test_return test_binary_flush(void) {
    return test_binary_flush_impl("test_binary_flush",
                                  PROTOCOL_BINARY_CMD_FLUSH);
}

static enum test_return test_binary_flushq(void) {
    return test_binary_flush_impl("test_binary_flushq",
                                  PROTOCOL_BINARY_CMD_FLUSHQ);
}

static enum test_return test_binary_concat_impl(const char *key, uint8_t cmd) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } send, receive;
    const char *value = "world";

    size_t len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                              key, strlen(key), value, strlen(value));


    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, cmd,
                             PROTOCOL_BINARY_RESPONSE_NOT_STORED);

    len = storage_command(send.bytes, sizeof(send.bytes),
                          PROTOCOL_BINARY_CMD_ADD,
                          key, strlen(key), value, strlen(value), 0, 0);
    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_ADD,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    len = raw_command(send.bytes, sizeof(send.bytes), cmd,
                      key, strlen(key), value, strlen(value));
    safe_send(send.bytes, len, false);

    if (cmd == PROTOCOL_BINARY_CMD_APPEND || cmd == PROTOCOL_BINARY_CMD_PREPEND) {
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    } else {
        len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_NOOP,
                          NULL, 0, NULL, 0);
        safe_send(send.bytes, len, false);
        safe_recv_packet(receive.bytes, sizeof(receive.bytes));
        validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_NOOP,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    }

    len = raw_command(send.bytes, sizeof(send.bytes), PROTOCOL_BINARY_CMD_GETK,
                      key, strlen(key), NULL, 0);

    safe_send(send.bytes, len, false);
    safe_recv_packet(receive.bytes, sizeof(receive.bytes));
    validate_response_header(&receive.response, PROTOCOL_BINARY_CMD_GETK,
                             PROTOCOL_BINARY_RESPONSE_SUCCESS);

    assert(receive.response.message.header.response.keylen == strlen(key));
    assert(receive.response.message.header.response.bodylen == (strlen(key) + 2*strlen(value) + 4));

    char *ptr = receive.bytes;
    ptr += sizeof(receive.response);
    ptr += 4;

    assert(memcmp(ptr, key, strlen(key)) == 0);
    ptr += strlen(key);
    assert(memcmp(ptr, value, strlen(value)) == 0);
    ptr += strlen(value);
    assert(memcmp(ptr, value, strlen(value)) == 0);

    return TEST_PASS;
}

static enum test_return test_binary_append(void) {
    return test_binary_concat_impl("test_binary_append",
                                   PROTOCOL_BINARY_CMD_APPEND);
}

static enum test_return test_binary_prepend(void) {
    return test_binary_concat_impl("test_binary_prepend",
                                   PROTOCOL_BINARY_CMD_PREPEND);
}

static enum test_return test_binary_appendq(void) {
    return test_binary_concat_impl("test_binary_appendq",
                                   PROTOCOL_BINARY_CMD_APPENDQ);
}

static enum test_return test_binary_prependq(void) {
    return test_binary_concat_impl("test_binary_prependq",
                                   PROTOCOL_BINARY_CMD_PREPENDQ);
}

static enum test_return test_binary_stat(void) {
    union {
        protocol_binary_request_no_extras request;
        protocol_binary_response_no_extras response;
        char bytes[1024];
    } buffer;

    size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                             PROTOCOL_BINARY_CMD_STAT,
                             NULL, 0, NULL, 0);

    safe_send(buffer.bytes, len, false);
    do {
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, PROTOCOL_BINARY_CMD_STAT,
                                 PROTOCOL_BINARY_RESPONSE_SUCCESS);
    } while (buffer.response.message.header.response.keylen != 0);

    return TEST_PASS;
}

static enum test_return test_binary_illegal(void) {
    uint8_t cmd = 0x25;
    while (cmd != 0x00) {
        union {
            protocol_binary_request_no_extras request;
            protocol_binary_response_no_extras response;
            char bytes[1024];
        } buffer;
        size_t len = raw_command(buffer.bytes, sizeof(buffer.bytes),
                                 cmd, NULL, 0, NULL, 0);
        safe_send(buffer.bytes, len, false);
        safe_recv_packet(buffer.bytes, sizeof(buffer.bytes));
        validate_response_header(&buffer.response, cmd,
                                 PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND);
        ++cmd;
    }

    return TEST_PASS;
}

volatile bool hickup_thread_running;

static void *binary_hickup_recv_verification_thread(void *arg) {
    protocol_binary_response_no_extras *response = malloc(65*1024);
    if (response != NULL) {
        while (safe_recv_packet(response, 65*1024)) {
            /* Just validate the packet format */
            validate_response_header(response,
                                     response->message.header.response.opcode,
                                     response->message.header.response.status);
        }
        free(response);
    }
    hickup_thread_running = false;
    allow_closed_read = false;
    return NULL;
}

static enum test_return test_binary_pipeline_hickup_chunk(void *buffer, size_t buffersize) {
    off_t offset = 0;
    char *key[256] = { NULL };
    uint64_t value = 0xfeedfacedeadbeef;

    while (hickup_thread_running &&
           offset + sizeof(protocol_binary_request_no_extras) < buffersize) {
        union {
            protocol_binary_request_no_extras request;
            char bytes[65 * 1024];
        } command;
        uint8_t cmd = (uint8_t)(rand() & 0xff);
        size_t len;
        size_t keylen = (rand() % 250) + 1;

        switch (cmd) {
        case PROTOCOL_BINARY_CMD_ADD:
        case PROTOCOL_BINARY_CMD_ADDQ:
        case PROTOCOL_BINARY_CMD_REPLACE:
        case PROTOCOL_BINARY_CMD_REPLACEQ:
        case PROTOCOL_BINARY_CMD_SET:
        case PROTOCOL_BINARY_CMD_SETQ:
            len = storage_command(command.bytes, sizeof(command.bytes), cmd,
                                  key, keylen , &value, sizeof(value),
                                  0, 0);
            break;
        case PROTOCOL_BINARY_CMD_APPEND:
        case PROTOCOL_BINARY_CMD_APPENDQ:
        case PROTOCOL_BINARY_CMD_PREPEND:
        case PROTOCOL_BINARY_CMD_PREPENDQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                              key, keylen, &value, sizeof(value));
            break;
        case PROTOCOL_BINARY_CMD_FLUSH:
        case PROTOCOL_BINARY_CMD_FLUSHQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                              NULL, 0, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_NOOP:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                              NULL, 0, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_DELETE:
        case PROTOCOL_BINARY_CMD_DELETEQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                             key, keylen, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_DECREMENT:
        case PROTOCOL_BINARY_CMD_DECREMENTQ:
        case PROTOCOL_BINARY_CMD_INCREMENT:
        case PROTOCOL_BINARY_CMD_INCREMENTQ:
            len = arithmetic_command(command.bytes, sizeof(command.bytes), cmd,
                                     key, keylen, 1, 0, 0);
            break;
        case PROTOCOL_BINARY_CMD_VERSION:
            len = raw_command(command.bytes, sizeof(command.bytes),
                             PROTOCOL_BINARY_CMD_VERSION,
                             NULL, 0, NULL, 0);
            break;
        case PROTOCOL_BINARY_CMD_GET:
        case PROTOCOL_BINARY_CMD_GETK:
        case PROTOCOL_BINARY_CMD_GETKQ:
        case PROTOCOL_BINARY_CMD_GETQ:
            len = raw_command(command.bytes, sizeof(command.bytes), cmd,
                             key, keylen, NULL, 0);
            break;

        case PROTOCOL_BINARY_CMD_TOUCH:
        case PROTOCOL_BINARY_CMD_GAT:
        case PROTOCOL_BINARY_CMD_GATQ:
        case PROTOCOL_BINARY_CMD_GATK:
        case PROTOCOL_BINARY_CMD_GATKQ:
            len = touch_command(command.bytes, sizeof(command.bytes), cmd,
                                key, keylen, 10);
            break;

        case PROTOCOL_BINARY_CMD_STAT:
            len = raw_command(command.bytes, sizeof(command.bytes),
                              PROTOCOL_BINARY_CMD_STAT,
                              NULL, 0, NULL, 0);
            break;

        case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS:
        case PROTOCOL_BINARY_CMD_SASL_AUTH:
        case PROTOCOL_BINARY_CMD_SASL_STEP:
            /* Ignoring SASL */
        case PROTOCOL_BINARY_CMD_QUITQ:
        case PROTOCOL_BINARY_CMD_QUIT:
            /* I don't want to pass on the quit commands ;-) */
            cmd |= 0xf0;
            /* FALLTHROUGH */
        default:
            len = raw_command(command.bytes, sizeof(command.bytes),
                              cmd, NULL, 0, NULL, 0);
        }

        if ((len + offset) < buffersize) {
            memcpy(((char*)buffer) + offset, command.bytes, len);
            offset += len;
        } else {
            break;
        }
    }
    safe_send(buffer, offset, true);

    return TEST_PASS;
}

static enum test_return test_binary_pipeline_hickup(void)
{
    size_t buffersize = 65 * 1024;
    void *buffer = malloc(buffersize);
    int ii;

    pthread_t tid;
    int ret;
    allow_closed_read = true;
    hickup_thread_running = true;
    if ((ret = pthread_create(&tid, NULL,
                              binary_hickup_recv_verification_thread, NULL)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
        free(buffer);
        return TEST_FAIL;
    }

    /* Allow the thread to start */
    usleep(250);

    srand((int)time(NULL));
    for (ii = 0; ii < 2; ++ii) {
        test_binary_pipeline_hickup_chunk(buffer, buffersize);
    }

    /* send quitq to shut down the read thread ;-) */
    size_t len = raw_command(buffer, buffersize, PROTOCOL_BINARY_CMD_QUITQ,
                             NULL, 0, NULL, 0);
    safe_send(buffer, len, false);

    pthread_join(tid, NULL);
    free(buffer);
    return TEST_PASS;
}


static enum test_return test_issue_101(void) {
    enum { max = 2 };
    enum test_return ret = TEST_PASS;
    struct conn *conns[max];
    int ii = 0;
    pid_t child = 0;

    if (getenv("SKIP_TEST_101") != NULL) {
        return TEST_SKIP;
    }

    const char *command = "stats\r\nstats\r\nstats\r\nstats\r\nstats\r\n";
    size_t cmdlen = strlen(command);

    server_pid = start_server(&port, false, 1000);

    for (ii = 0; ii < max; ++ii) {
        conns[ii] = NULL;
        conns[ii] = connect_server("127.0.0.1", port, true, enable_ssl);
        assert(conns[ii]);
        assert(conns[ii]->sock > 0);
    }

    /* Send command on the connection until it blocks */
    for (ii = 0; ii < max; ++ii) {
        bool more = true;
        do {
            ssize_t err = conns[ii]->write(conns[ii], command, cmdlen);
            if (err == -1) {
                switch (errno) {
                case EINTR:
                    break;
                case ENOMEM:
                case EWOULDBLOCK:
                    more = false;
                    break;
                default:
                    ret = TEST_FAIL;
                    goto cleanup;
                }
            }
        } while (more);
    }

    child = fork();
    if (child == (pid_t)-1) {
        abort();
    } else if (child > 0) {
        int stat;
        pid_t c;
        while ((c = waitpid(child, &stat, 0)) == (pid_t)-1 && errno == EINTR);
        assert(c == child);
        assert(stat == 0);
    } else {
        con = connect_server("127.0.0.1", port, false, enable_ssl);
        assert(con);
        ret = test_binary_noop();
        close_conn();
        exit(0);
    }

 cleanup:
    /* close all connections */
    for (ii = 0; ii < max; ++ii) {
        struct conn *c = conns[ii];
        if (c == NULL) continue;
#ifdef TLS
        if (c->ssl) {
            SSL_shutdown(c->ssl);
            SSL_free(c->ssl);
        }
        if (c->ssl_ctx)
            SSL_CTX_free(c->ssl_ctx);
#endif
        if (c->sock > 0) close(c->sock);
        free(conns[ii]);
        conns[ii] = NULL;
    }

    assert(kill(server_pid, SIGTERM) == 0);

    return ret;
}

typedef enum test_return (*TEST_FUNC)(void);
struct testcase {
    const char *description;
    TEST_FUNC function;
};

struct testcase testcases[] = {
    { "cache_create", cache_create_test },
    { "cache_reuse", cache_reuse_test },
    { "cache_redzone", cache_redzone_test },
    { "cache_limit_revised_downward", cache_limit_revised_downward_test },
    { "stats_prefix_find", test_stats_prefix_find },
    { "stats_prefix_record_get", test_stats_prefix_record_get },
    { "stats_prefix_record_delete", test_stats_prefix_record_delete },
    { "stats_prefix_record_set", test_stats_prefix_record_set },
    { "stats_prefix_dump", test_stats_prefix_dump },
    { "issue_161", test_issue_161 },
    { "strtol", test_safe_strtol },
    { "strtoll", test_safe_strtoll },
    { "strtoul", test_safe_strtoul },
    { "strtoull", test_safe_strtoull },
    { "issue_44", test_issue_44 },
    { "vperror", test_vperror },
    { "issue_101", test_issue_101 },
    { "crc32c", test_crc32c },
    /* The following tests all run towards the same server */
    { "start_server", start_memcached_server },
    { "issue_92", test_issue_92 },
    { "issue_102", test_issue_102 },
    { "binary_noop", test_binary_noop },
    { "binary_quit", test_binary_quit },
    { "binary_quitq", test_binary_quitq },
    { "binary_set", test_binary_set },
    { "binary_setq", test_binary_setq },
    { "binary_add", test_binary_add },
    { "binary_addq", test_binary_addq },
    { "binary_replace", test_binary_replace },
    { "binary_replaceq", test_binary_replaceq },
    { "binary_delete", test_binary_delete },
    { "binary_deleteq", test_binary_deleteq },
    { "binary_get", test_binary_get },
    { "binary_getq", test_binary_getq },
    { "binary_getk", test_binary_getk },
    { "binary_getkq", test_binary_getkq },
    { "binary_gat", test_binary_gat },
    { "binary_gatq", test_binary_gatq },
    { "binary_gatk", test_binary_gatk },
    { "binary_gatkq", test_binary_gatkq },
    { "binary_incr", test_binary_incr },
    { "binary_incrq", test_binary_incrq },
    { "binary_decr", test_binary_decr },
    { "binary_decrq", test_binary_decrq },
    { "binary_version", test_binary_version },
    { "binary_flush", test_binary_flush },
    { "binary_flushq", test_binary_flushq },
    { "binary_append", test_binary_append },
    { "binary_appendq", test_binary_appendq },
    { "binary_prepend", test_binary_prepend },
    { "binary_prependq", test_binary_prependq },
    { "binary_stat", test_binary_stat },
    { "binary_illegal", test_binary_illegal },
    { "binary_pipeline_hickup", test_binary_pipeline_hickup },
    { "shutdown", shutdown_memcached_server },
    { "stop_server", stop_memcached_server },
    { NULL, NULL }
};

/* Stub out function defined in memcached.c */
void STATS_LOCK(void);
void STATS_UNLOCK(void);
void STATS_LOCK(void)
{}
void STATS_UNLOCK(void)
{}

int main(int argc, char **argv)
{
    int exitcode = 0;
    int ii = 0, num_cases = 0;
#ifdef TLS
    if (getenv("SSL_TEST") != NULL) {
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
        enable_ssl = true;
    }
#endif
    /* Initialized directly instead of using hash_init to avoid pulling in
       the definition of settings struct from memcached.h */
    hash = jenkins_hash;
    stats_prefix_init(':');

    crc32c_init();

    for (num_cases = 0; testcases[num_cases].description; num_cases++) {
        /* Just counting */
    }

    printf("1..%d\n", num_cases);

    for (ii = 0; testcases[ii].description != NULL; ++ii) {
        fflush(stdout);
#ifndef DEBUG
        /* the test program shouldn't run longer than 10 minutes... */
        alarm(600);
#endif
        enum test_return ret = testcases[ii].function();
        if (ret == TEST_SKIP) {
            fprintf(stdout, "ok # SKIP %d - %s\n", ii + 1, testcases[ii].description);
        } else if (ret == TEST_PASS) {
            fprintf(stdout, "ok %d - %s\n", ii + 1, testcases[ii].description);
        } else {
            fprintf(stdout, "not ok %d - %s\n", ii + 1, testcases[ii].description);
            exitcode = 1;
        }
        fflush(stdout);
    }

    return exitcode;
}
