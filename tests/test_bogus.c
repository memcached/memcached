/*
 * test_bogus.c - Test server error handling for malformed/bogus commands.
 */

#include "c_harness.h"

static int test_unknown_command(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[128];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "boguscommand\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strstr(line, "ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_malformed_set(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[128];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "set foo 0\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strstr(line, "CLIENT_ERROR") != NULL ||
              strstr(line, "ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_non_numeric_flags(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[128];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "set foo notanumber 0 5\r\nhello\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strstr(line, "ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_negative_bytes(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[128];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "set foo 0 0 -1\r\nhello\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strstr(line, "ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_bogus_run(void) {
  RUN_TEST(test_unknown_command);
  RUN_TEST(test_malformed_set);
  RUN_TEST(test_non_numeric_flags);
  RUN_TEST(test_negative_bytes);
  return 0;
}
