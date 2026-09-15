/*
 * test_multiversioning.c - Test overwriting existing keys repeatedly.
 */

#include "c_harness.h"

static int test_overwriting_same_key(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  const char *key = "multi_key";
  int i;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  for (i = 0; i < 20; i++) {
    char val[64];
    char resp[64];
    char got[64];

    snprintf(val, sizeof(val), "value_generation_%d", i);
    TEST_ASSERT(
        client_set(&c, key, val, strlen(val), 0, 0, resp, sizeof(resp)) == 0);
    TEST_ASSERT_STR_EQ(resp, "STORED");

    TEST_ASSERT(client_get(&c, key, got, sizeof(got), NULL) == 0);
    TEST_ASSERT_STR_EQ(got, val);
  }

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_multiversioning_run(void) {
  RUN_TEST(test_overwriting_same_key);
  return 0;
}
