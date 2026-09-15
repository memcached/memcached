/*
 * test_incrdecr.c - Test arithmetic increment and decrement operations.
 */

#include "c_harness.h"

static int test_incr_decr_flow(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  test_uint64_t val = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "counter", "0", 1, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_incr(&c, "counter", 1, &val, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(val, 1);

  TEST_ASSERT(client_incr(&c, "counter", 99, &val, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(val, 100);

  TEST_ASSERT(client_decr(&c, "counter", 30, &val, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(val, 70);

  TEST_ASSERT(client_decr(&c, "counter", 70, &val, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(val, 0);

  TEST_ASSERT(client_decr(&c, "counter", 5, &val, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(val, 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_incr_nonexistent(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char err[64];
  test_uint64_t val = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_incr(&c, "nonexistent_counter", 1, &val, err, sizeof(err)) != 0);
  TEST_ASSERT_STR_EQ(err, "NOT_FOUND");

  TEST_ASSERT(
      client_decr(&c, "nonexistent_counter", 1, &val, err, sizeof(err)) != 0);
  TEST_ASSERT_STR_EQ(err, "NOT_FOUND");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_incr_non_numeric(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char err[128];
  test_uint64_t val = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_set(&c, "text_val", "hello", 5, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_incr(&c, "text_val", 1, &val, err, sizeof(err)) != 0);
  TEST_ASSERT(strstr(err, "CLIENT_ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_incrdecr_run(void) {
  RUN_TEST(test_incr_decr_flow);
  RUN_TEST(test_incr_nonexistent);
  RUN_TEST(test_incr_non_numeric);
  return 0;
}
