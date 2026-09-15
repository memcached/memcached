/*
 * test_expirations.c - Test item TTL expiration behavior.
 */

#include "c_harness.h"

static int test_ttl_expiration(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "expire_key", "expire_val", 10, 0, 2, resp,
                         sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "expire_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "expire_val");

  test_sleep_ms(2500);

  TEST_ASSERT(client_get(&c, "expire_key", val, sizeof(val), NULL) != 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_permanent_item(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_set(&c, "perm_key", "perm_val", 8, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  test_sleep_ms(1000);

  TEST_ASSERT(client_get(&c, "perm_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "perm_val");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_expirations_run(void) {
  RUN_TEST(test_ttl_expiration);
  RUN_TEST(test_permanent_item);
  return 0;
}
