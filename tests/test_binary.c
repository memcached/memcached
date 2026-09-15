/*
 * test_binary.c - Test binary protocol commands.
 */

#include "c_harness.h"

static int test_bin_noop(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  struct bin_response resp;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(bin_send(&c, 0x0A, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);

  TEST_ASSERT_INT_EQ(resp.opcode, 0x0A);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_bin_version(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  struct bin_response resp;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(bin_send(&c, 0x0B, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);

  TEST_ASSERT_INT_EQ(resp.opcode, 0x0B);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);
  TEST_ASSERT(strlen(resp.val) > 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_bin_set_and_get(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  struct bin_response resp;
  char extras[8];

  memset(extras, 0, sizeof(extras));

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(bin_send(&c, 0x01, "bin_k1", 6, "bin_v1", 6, extras, 8, 0, 0x1234,
                       0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.opcode, 0x01);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);
  TEST_ASSERT_INT_EQ(resp.opaque, 0x1234);
  TEST_ASSERT(resp.cas > 0);

  TEST_ASSERT(bin_send(&c, 0x00, "bin_k1", 6, NULL, 0, NULL, 0, 0, 0x5678, 0) ==
              0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.opcode, 0x00);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);
  TEST_ASSERT_INT_EQ(resp.opaque, 0x5678);
  TEST_ASSERT_STR_EQ(resp.val, "bin_v1");

  TEST_ASSERT(bin_send(&c, 0x00, "nonexistent_bin_key", 19, NULL, 0, NULL, 0, 0,
                       0x9999, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.opcode, 0x00);
  TEST_ASSERT_INT_EQ(resp.status, 0x01);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_bin_delete(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  struct bin_response resp;
  char extras[8];

  memset(extras, 0, sizeof(extras));

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(bin_send(&c, 0x01, "del_bink", 8, "del_binv", 8, extras, 8, 0, 0,
                       0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  TEST_ASSERT(bin_send(&c, 0x04, "del_bink", 8, NULL, 0, NULL, 0, 0, 0, 0) ==
              0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  TEST_ASSERT(bin_send(&c, 0x04, "del_bink", 8, NULL, 0, NULL, 0, 0, 0, 0) ==
              0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x01);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_bin_add_and_replace(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  struct bin_response resp;
  char extras[8];

  memset(extras, 0, sizeof(extras));

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(bin_send(&c, 0x02, "ar_bink", 7, "ar_initial", 10, extras, 8, 0,
                       0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  TEST_ASSERT(
      bin_send(&c, 0x02, "ar_bink", 7, "ar_fail", 7, extras, 8, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x02);

  TEST_ASSERT(bin_send(&c, 0x03, "ar_bink", 7, "ar_replaced", 11, extras, 8, 0,
                       0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  TEST_ASSERT(bin_send(&c, 0x00, "ar_bink", 7, NULL, 0, NULL, 0, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);
  TEST_ASSERT_STR_EQ(resp.val, "ar_replaced");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_bin_flush(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  struct bin_response resp;
  char extras[8];

  memset(extras, 0, sizeof(extras));

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      bin_send(&c, 0x01, "fl_bink", 7, "fl_val", 6, extras, 8, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  TEST_ASSERT(bin_send(&c, 0x08, NULL, 0, NULL, 0, NULL, 0, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x00);

  TEST_ASSERT(bin_send(&c, 0x00, "fl_bink", 7, NULL, 0, NULL, 0, 0, 0, 0) == 0);
  TEST_ASSERT(bin_recv(&c, &resp) == 0);
  TEST_ASSERT_INT_EQ(resp.status, 0x01);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_binary_run(void) {
  RUN_TEST(test_bin_noop);
  RUN_TEST(test_bin_version);
  RUN_TEST(test_bin_set_and_get);
  RUN_TEST(test_bin_delete);
  RUN_TEST(test_bin_add_and_replace);
  RUN_TEST(test_bin_flush);
  return 0;
}
