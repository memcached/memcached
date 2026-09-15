/*
 * test_cas.c - Test compare-and-swap (CAS) protocol operations.
 */

#include "c_harness.h"

static int test_cas_workflow(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];
  test_uint64_t cas1 = 0;
  test_uint64_t cas2 = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "cas_key", "val1", 4, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_gets(&c, "cas_key", val, sizeof(val), NULL, &cas1) == 0);
  TEST_ASSERT_STR_EQ(val, "val1");
  TEST_ASSERT(cas1 > 0);

  TEST_ASSERT(client_cas(&c, "cas_key", "val2", 4, cas1, 0, 0, resp,
                         sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_gets(&c, "cas_key", val, sizeof(val), NULL, &cas2) == 0);
  TEST_ASSERT_STR_EQ(val, "val2");
  TEST_ASSERT(cas2 > 0);
  TEST_ASSERT(cas2 != cas1);

  TEST_ASSERT(client_cas(&c, "cas_key", "val3", 4, cas1, 0, 0, resp,
                         sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "EXISTS");

  TEST_ASSERT(client_get(&c, "cas_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "val2");

  TEST_ASSERT(client_set(&c, "cas_key", "val4", 4, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");
  TEST_ASSERT(client_get(&c, "cas_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "val4");

  TEST_ASSERT(client_cas(&c, "nonexistent_cas", "v", 1, 12345, 0, 0, resp,
                         sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "NOT_FOUND");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_cas_run(void) {
  RUN_TEST(test_cas_workflow);
  return 0;
}
