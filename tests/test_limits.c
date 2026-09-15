/*
 * test_limits.c - Test item size limits and maximum key lengths.
 */

#include "c_harness.h"

static int test_max_key_length(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char key250[251];
  char key251[252];
  char line[512];
  char val[64];
  char resp[64];

  memset(key250, 'a', 250);
  key250[250] = '\0';

  memset(key251, 'b', 251);
  key251[251] = '\0';

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  /* 250-byte key is allowed */
  TEST_ASSERT(client_set(&c, key250, "val250", 6, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, key250, val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "val250");

  /* 251-byte key is rejected */
  snprintf(line, sizeof(line), "set %s 0 0 3\r\nval\r\n", key251);
  client_send_str(&c, line);
  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strstr(line, "CLIENT_ERROR") != NULL ||
              strstr(line, "ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_oversized_value(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  size_t oversized_len = 1024 * 1024 + 1024;
  char *buf;
  char line[256];
  int header_len;
  size_t total_len;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  buf = (char *)malloc(oversized_len + 128);
  TEST_ASSERT(buf != NULL);

  header_len = snprintf(buf, 128, "set oversized_key 0 0 %lu\r\n",
                        (unsigned long)oversized_len);
  memset(buf + header_len, 'x', oversized_len);
  buf[header_len + oversized_len] = '\r';
  buf[header_len + oversized_len + 1] = '\n';
  total_len = (size_t)header_len + oversized_len + 2;

  /* Send entire command buffer */
  client_send(&c, buf, total_len);
  free(buf);

  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strstr(line, "SERVER_ERROR") != NULL ||
              strstr(line, "CLIENT_ERROR") != NULL ||
              strstr(line, "ERROR") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_limits_run(void) {
  RUN_TEST(test_max_key_length);
  RUN_TEST(test_oversized_value);
  return 0;
}
