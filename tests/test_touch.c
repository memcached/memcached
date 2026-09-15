/*
 * test_touch.c - Test touch commands.
 */

#include "c_harness.h"

static int test_touch_extends_ttl(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "touch_key", "val", 3, 0, 2, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_touch(&c, "touch_key", 10, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "TOUCHED");

  test_sleep_ms(2500);

  TEST_ASSERT(client_get(&c, "touch_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "val");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_touch_nonexistent(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_touch(&c, "nonexistent_touch_key", 10, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "NOT_FOUND");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_touch_run(void) {
  RUN_TEST(test_touch_extends_ttl);
  RUN_TEST(test_touch_nonexistent);
  return 0;
}
