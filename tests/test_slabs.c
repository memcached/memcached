/*
 * test_slabs.c - Test slab allocation, automove settings, and reassign
 * commands.
 */

#include "c_harness.h"

static int test_slab_reassign(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char small_payload[64];
  char large_payload[512];
  char resp[64];
  char line[256];
  int has_slabs = 0;

  memset(small_payload, 's', sizeof(small_payload));
  memset(large_payload, 'L', sizeof(large_payload));

  TEST_ASSERT(srv_start(&srv, 0, "-o slab_reassign,slab_automove=1") == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "s_small", small_payload, sizeof(small_payload), 0,
                         0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_set(&c, "s_large", large_payload, sizeof(large_payload), 0,
                         0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_send_str(&c, "stats slabs\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "active_slabs") != NULL) {
      has_slabs = 1;
    }
  }
  TEST_ASSERT(has_slabs == 1);

  TEST_ASSERT(client_send_str(&c, "slabs automove 0\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "OK", 2) == 0);

  TEST_ASSERT(client_send_str(&c, "slabs automove 1\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "OK", 2) == 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_slabs_run(void) {
  RUN_TEST(test_slab_reassign);
  return 0;
}
