/*
 * test_metaget.c - Test meta command protocol (mg, ms, md).
 */

#include "c_harness.h"

static int test_meta_set_and_get(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[128];
  char val[64];
  char crlf[2];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "ms mg_key 5 T3600\r\nhello\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "HD", 2) == 0);

  TEST_ASSERT(client_send_str(&c, "mg mg_key v s c\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "VA 5", 4) == 0);

  TEST_ASSERT(client_read_bytes(&c, val, 5) == 0);
  val[5] = '\0';
  TEST_ASSERT(client_read_bytes(&c, crlf, 2) == 0);
  TEST_ASSERT_STR_EQ(val, "hello");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_meta_delete(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char line[128];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "md_key", "val", 3, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_send_str(&c, "md md_key\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "HD", 2) == 0);

  TEST_ASSERT(client_send_str(&c, "mg md_key\r\n") == 0);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "EN", 2) == 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_metaget_run(void) {
  RUN_TEST(test_meta_set_and_get);
  RUN_TEST(test_meta_delete);
  return 0;
}
