/*
 * test_getset.c - Test get/set operations, pipelining, and binary safety.
 */

#include "c_harness.h"

static int test_basic_set_get(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_set(&c, "k_basic", "val_basic", 9, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "k_basic", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "val_basic");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_empty_value(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "empty_k", "", 0, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "empty_k", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_whitespace_in_value(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  const char *payload = "line1\tline2   end";
  char resp[64];
  char val[128];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "ws_key", payload, strlen(payload), 0, 0, resp,
                         sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "ws_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, payload);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_binary_characters_in_value(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char binary_payload[10];
  char val[64];
  char resp[64];

  binary_payload[0] = 0;
  binary_payload[1] = 1;
  binary_payload[2] = 2;
  binary_payload[3] = (char)255;
  binary_payload[4] = (char)128;
  binary_payload[5] = 64;
  binary_payload[6] = 0;
  binary_payload[7] = 10;
  binary_payload[8] = 13;
  binary_payload[9] = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "bin_val", binary_payload, 10, 0, 0, resp,
                         sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "bin_val", val, sizeof(val), NULL) == 0);
  TEST_ASSERT(memcmp(val, binary_payload, 10) == 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_pipelining(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  const char *pipeline_req = "set pipe1 0 0 4\r\nval1\r\n"
                             "set pipe2 0 0 4\r\nval2\r\n"
                             "get pipe1 pipe2\r\n";
  char line[256];
  char v1[32], v2[32];
  int got_v1 = 0, got_v2 = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, pipeline_req) == 0);

  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "STORED", 6) == 0);

  TEST_ASSERT(client_readline(&c, line, sizeof(line)) > 0);
  TEST_ASSERT(strncmp(line, "STORED", 6) == 0);

  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strncmp(line, "VALUE pipe1 ", 12) == 0) {
      char crlf[2];
      TEST_ASSERT(client_read_bytes(&c, v1, 4) == 0);
      v1[4] = '\0';
      TEST_ASSERT(client_read_bytes(&c, crlf, 2) == 0);
      got_v1 = 1;
    } else if (strncmp(line, "VALUE pipe2 ", 12) == 0) {
      char crlf[2];
      TEST_ASSERT(client_read_bytes(&c, v2, 4) == 0);
      v2[4] = '\0';
      TEST_ASSERT(client_read_bytes(&c, crlf, 2) == 0);
      got_v2 = 1;
    }
  }

  TEST_ASSERT(got_v1 && got_v2);
  TEST_ASSERT_STR_EQ(v1, "val1");
  TEST_ASSERT_STR_EQ(v2, "val2");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_getset_run(void) {
  RUN_TEST(test_basic_set_get);
  RUN_TEST(test_empty_value);
  RUN_TEST(test_whitespace_in_value);
  RUN_TEST(test_binary_characters_in_value);
  RUN_TEST(test_pipelining);
  return 0;
}
