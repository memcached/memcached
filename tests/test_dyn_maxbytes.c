/*
 * test_dyn_maxbytes.c - Test dynamically resizing maximum memory limit.
 */

#include "c_harness.h"

static int test_resize_maxbytes(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[256];
  test_uint64_t maxbytes = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "cache_memlimit 128\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "OK", 2) == 0);

  TEST_ASSERT(client_send_str(&c, "stats settings\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "STAT maxbytes ") != NULL) {
      unsigned long long val = 0;
      if (sscanf(line, "STAT maxbytes %llu", &val) == 1) {
        maxbytes = (test_uint64_t)val;
      }
    }
  }

  TEST_ASSERT(maxbytes == (test_uint64_t)128 * 1024 * 1024);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_dyn_maxbytes_run(void) {
  RUN_TEST(test_resize_maxbytes);
  return 0;
}
