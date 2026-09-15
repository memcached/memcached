/*
 * c_harness.h - Cross-platform C89 test harness and memcached client library.
 */

#ifndef TESTS_C_HARNESS_H
#define TESTS_C_HARNESS_H

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(_MSC_VER)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <process.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET test_socket_t;
typedef int test_socklen_t;
typedef HANDLE test_pid_t;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define TEST_INVALID_PID NULL
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
typedef int test_socket_t;
typedef socklen_t test_socklen_t;
typedef pid_t test_pid_t;
#define TEST_INVALID_SOCKET (-1)
#define TEST_INVALID_PID (-1)
#endif

#if defined(_MSC_VER)
typedef unsigned __int64 test_uint64_t;
typedef unsigned __int32 test_uint32_t;
typedef unsigned __int16 test_uint16_t;
typedef unsigned __int8 test_uint8_t;
#else
#include <stdint.h>
typedef uint64_t test_uint64_t;
typedef uint32_t test_uint32_t;
typedef uint16_t test_uint16_t;
typedef uint8_t test_uint8_t;
#endif

struct memcached_srv {
  test_pid_t pid;
  int port;
  char bin_path[512];
  char emulator[256];
};

struct memcached_client {
  test_socket_t sock;
  char buf[16384];
  size_t buf_len;
  size_t buf_pos;
};

struct bin_response {
  test_uint8_t magic;
  test_uint8_t opcode;
  test_uint16_t keylen;
  test_uint8_t extlen;
  test_uint8_t datatype;
  test_uint16_t status;
  test_uint32_t bodylen;
  test_uint32_t opaque;
  test_uint64_t cas;
  char extras[64];
  char key[256];
  char val[8192];
};

/* Test failure reporting */
extern int g_tests_run;
extern int g_tests_failed;
extern const char *g_current_test_name;

#define TEST_ASSERT(cond)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__,       \
              __LINE__);                                                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_MSG(cond, msg)                                             \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "ASSERTION FAILED: %s: %s (%s:%d)\n", #cond, (msg),      \
              __FILE__, __LINE__);                                             \
      return 1;                                                                \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_STR_EQ(actual, expected)                                   \
  do {                                                                         \
    if (strcmp((actual), (expected)) != 0) {                                   \
      fprintf(stderr, "ASSERTION FAILED: \"%s\" != \"%s\" (%s:%d)\n",          \
              (actual), (expected), __FILE__, __LINE__);                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

#define TEST_ASSERT_INT_EQ(actual, expected)                                   \
  do {                                                                         \
    if ((actual) != (expected)) {                                              \
      fprintf(stderr, "ASSERTION FAILED: %ld != %ld (%s:%d)\n",                \
              (long)(actual), (long)(expected), __FILE__, __LINE__);           \
      return 1;                                                                \
    }                                                                          \
  } while (0)

#define RUN_TEST(test_func)                                                    \
  do {                                                                         \
    int _res;                                                                  \
    g_tests_run++;                                                             \
    g_current_test_name = #test_func;                                          \
    _res = test_func();                                                        \
    if (_res == 0) {                                                           \
      printf("ok %d - %s\n", g_tests_run, #test_func);                         \
    } else {                                                                   \
      printf("not ok %d - %s\n", g_tests_run, #test_func);                     \
      g_tests_failed++;                                                        \
    }                                                                          \
    fflush(stdout);                                                            \
  } while (0)

/* Environment and sleep */
void test_harness_init(void);
void test_sleep_ms(int ms);
int find_free_port(void);
const char *get_memcached_bin(void);
const char *get_memcached_emulator(void);

/* Server lifecycle */
int srv_start(struct memcached_srv *srv, int port, const char *extra_args);
void srv_stop(struct memcached_srv *srv);
int run_cmd_capture(const char *cmd_line, char *out_buf, size_t max_len,
                    int *exit_code);

/* Client connection and socket IO */
int client_connect(struct memcached_client *c, int port);
void client_close(struct memcached_client *c);
int client_send(struct memcached_client *c, const void *data, size_t len);
int client_send_str(struct memcached_client *c, const char *str);
int client_readline(struct memcached_client *c, char *line_buf, size_t max_len);
int client_read_bytes(struct memcached_client *c, void *buf, size_t count);

/* ASCII Protocol Helpers */
int client_set(struct memcached_client *c, const char *key, const void *val,
               size_t val_len, unsigned int flags, int exptime, char *resp,
               size_t resp_len);
int client_add(struct memcached_client *c, const char *key, const void *val,
               size_t val_len, unsigned int flags, int exptime, char *resp,
               size_t resp_len);
int client_replace(struct memcached_client *c, const char *key, const void *val,
                   size_t val_len, unsigned int flags, int exptime, char *resp,
                   size_t resp_len);
int client_append(struct memcached_client *c, const char *key, const void *val,
                  size_t val_len, char *resp, size_t resp_len);
int client_prepend(struct memcached_client *c, const char *key, const void *val,
                   size_t val_len, char *resp, size_t resp_len);
int client_cas(struct memcached_client *c, const char *key, const void *val,
               size_t val_len, test_uint64_t cas_id, unsigned int flags,
               int exptime, char *resp, size_t resp_len);
int client_get(struct memcached_client *c, const char *key, char *val_out,
               size_t val_max, unsigned int *flags_out);
int client_gets(struct memcached_client *c, const char *key, char *val_out,
                size_t val_max, unsigned int *flags_out,
                test_uint64_t *cas_out);
int client_delete(struct memcached_client *c, const char *key, char *resp,
                  size_t resp_len);
int client_incr(struct memcached_client *c, const char *key, unsigned int delta,
                test_uint64_t *new_val, char *err_buf, size_t err_len);
int client_decr(struct memcached_client *c, const char *key, unsigned int delta,
                test_uint64_t *new_val, char *err_buf, size_t err_len);
int client_touch(struct memcached_client *c, const char *key, int exptime,
                 char *resp, size_t resp_len);
int client_flush_all(struct memcached_client *c, int delay, char *resp,
                     size_t resp_len);
int client_version(struct memcached_client *c, char *ver_out, size_t max_len);

/* Binary Protocol Helpers */
int bin_send(struct memcached_client *c, test_uint8_t opcode, const void *key,
             size_t key_len, const void *val, size_t val_len,
             const void *extras, size_t ext_len, test_uint8_t datatype,
             test_uint32_t opaque, test_uint64_t cas);
int bin_recv(struct memcached_client *c, struct bin_response *res);

#endif /* TESTS_C_HARNESS_H */
