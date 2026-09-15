/*
 * test_flags.c - Test flag handling across numeric ranges.
 */

#include "c_harness.h"

static int test_flag_ranges(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  static const unsigned int flag_values[] = {0, 123, 65535, 2147483647U,
                                             4294967295U};
  int i;
  int count = (int)(sizeof(flag_values) / sizeof(flag_values[0]));

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  for (i = 0; i < count; i++) {
    unsigned int flags = flag_values[i];
    char key[64];
    char resp[64];
    char val[64];
    unsigned int got_flags = 0;

    snprintf(key, sizeof(key), "flag_key_%u", flags);
    TEST_ASSERT(
        client_set(&c, key, "flagval", 7, flags, 0, resp, sizeof(resp)) == 0);
    TEST_ASSERT_STR_EQ(resp, "STORED");

    TEST_ASSERT(client_get(&c, key, val, sizeof(val), &got_flags) == 0);
    TEST_ASSERT_STR_EQ(val, "flagval");
    TEST_ASSERT_INT_EQ(got_flags, flags);
  }

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_flags_run(void) {
  RUN_TEST(test_flag_ranges);
  return 0;
}
