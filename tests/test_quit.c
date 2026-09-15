/*
 * test_quit.c - Test quit command clean connection termination.
 */

#include "c_harness.h"

static int test_quit_command(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char buf[128];
  int n;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "quit\r\n") == 0);

#if defined(_WIN32) || defined(_MSC_VER)
  n = recv(c.sock, buf, sizeof(buf), 0);
#else
  n = (int)recv(c.sock, buf, sizeof(buf), 0);
#endif
  TEST_ASSERT(n <= 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_quit_after_operations(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];
  char buf[128];
  int n;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "qkey", "qval", 4, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "qkey", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "qval");

  TEST_ASSERT(client_send_str(&c, "quit\r\n") == 0);

#if defined(_WIN32) || defined(_MSC_VER)
  n = recv(c.sock, buf, sizeof(buf), 0);
#else
  n = (int)recv(c.sock, buf, sizeof(buf), 0);
#endif
  TEST_ASSERT(n <= 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_quit_run(void) {
  RUN_TEST(test_quit_command);
  RUN_TEST(test_quit_after_operations);
  return 0;
}
