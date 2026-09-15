/*
 * test_flush_all.c - Test cache flushing commands.
 */

#include "c_harness.h"

static int test_immediate_flush(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "f1", "v1", 2, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT(client_set(&c, "f2", "v2", 2, 0, 0, resp, sizeof(resp)) == 0);

  TEST_ASSERT(client_flush_all(&c, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "OK");

  TEST_ASSERT(client_get(&c, "f1", val, sizeof(val), NULL) != 0);
  TEST_ASSERT(client_get(&c, "f2", val, sizeof(val), NULL) != 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_delayed_flush(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "df1", "val", 3, 0, 0, resp, sizeof(resp)) == 0);

  TEST_ASSERT(client_flush_all(&c, 2, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "OK");

  TEST_ASSERT(client_get(&c, "df1", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "val");

  test_sleep_ms(2500);

  TEST_ASSERT(client_get(&c, "df1", val, sizeof(val), NULL) != 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_flush_all_run(void) {
  RUN_TEST(test_immediate_flush);
  RUN_TEST(test_delayed_flush);
  return 0;
}
