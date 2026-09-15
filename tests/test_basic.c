/*
 * test_basic.c - Test core memcached protocol operations.
 */

#include "c_harness.h"

static int test_version(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char ver[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_version(&c, ver, sizeof(ver)) == 0);
  TEST_ASSERT(strstr(ver, "1.") != NULL);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_set_and_get(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];
  unsigned int flags = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "foo", "fooval", 6, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "foo", val, sizeof(val), &flags) == 0);
  TEST_ASSERT_STR_EQ(val, "fooval");
  TEST_ASSERT_INT_EQ(flags, 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_multiget(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char line[256];
  char val_k1[32];
  char val_k2[32];
  char val_k3[32];
  int got_k1 = 0, got_k2 = 0, got_k3 = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "k1", "v1", 2, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT(client_set(&c, "k2", "v2", 2, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT(client_set(&c, "k3", "v3", 2, 0, 0, resp, sizeof(resp)) == 0);

  TEST_ASSERT(client_send_str(&c, "get k1 k2 k3 nonexistent\r\n") == 0);

  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strncmp(line, "VALUE k1 ", 9) == 0) {
      char crlf[2];
      TEST_ASSERT(client_read_bytes(&c, val_k1, 2) == 0);
      val_k1[2] = '\0';
      TEST_ASSERT(client_read_bytes(&c, crlf, 2) == 0);
      got_k1 = 1;
    } else if (strncmp(line, "VALUE k2 ", 9) == 0) {
      char crlf[2];
      TEST_ASSERT(client_read_bytes(&c, val_k2, 2) == 0);
      val_k2[2] = '\0';
      TEST_ASSERT(client_read_bytes(&c, crlf, 2) == 0);
      got_k2 = 1;
    } else if (strncmp(line, "VALUE k3 ", 9) == 0) {
      char crlf[2];
      TEST_ASSERT(client_read_bytes(&c, val_k3, 2) == 0);
      val_k3[2] = '\0';
      TEST_ASSERT(client_read_bytes(&c, crlf, 2) == 0);
      got_k3 = 1;
    }
  }

  TEST_ASSERT(got_k1 && got_k2 && got_k3);
  TEST_ASSERT_STR_EQ(val_k1, "v1");
  TEST_ASSERT_STR_EQ(val_k2, "v2");
  TEST_ASSERT_STR_EQ(val_k3, "v3");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_add_and_replace(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  client_delete(&c, "add_key", resp, sizeof(resp));

  TEST_ASSERT(
      client_add(&c, "add_key", "initial", 7, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(
      client_add(&c, "add_key", "second", 6, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "NOT_STORED");

  TEST_ASSERT(client_replace(&c, "add_key", "replaced_val", 12, 0, 0, resp,
                             sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "add_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "replaced_val");

  client_delete(&c, "nonexistent_replace", resp, sizeof(resp));
  TEST_ASSERT(client_replace(&c, "nonexistent_replace", "v", 1, 0, 0, resp,
                             sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "NOT_STORED");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_delete(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_set(&c, "del_key", "del_val", 7, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_delete(&c, "del_key", resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "DELETED");

  TEST_ASSERT(client_delete(&c, "del_key", resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "NOT_FOUND");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_append_prepend(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "ap_key", "middle", 6, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_append(&c, "ap_key", "_end", 4, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_prepend(&c, "ap_key", "start_", 6, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_get(&c, "ap_key", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "start_middle_end");

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_incr_decr(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  test_uint64_t n = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "num_key", "10", 2, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_incr(&c, "num_key", 5, &n, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(n, 15);

  TEST_ASSERT(client_decr(&c, "num_key", 3, &n, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(n, 12);

  TEST_ASSERT(client_decr(&c, "num_key", 100, &n, NULL, 0) == 0);
  TEST_ASSERT_INT_EQ(n, 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_stats(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[256];
  int has_version = 0, has_curr_conn = 0, has_cmd_get = 0, has_cmd_set = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "stats\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "STAT version ") != NULL)
      has_version = 1;
    if (strstr(line, "STAT curr_connections ") != NULL)
      has_curr_conn = 1;
    if (strstr(line, "STAT cmd_get ") != NULL)
      has_cmd_get = 1;
    if (strstr(line, "STAT cmd_set ") != NULL)
      has_cmd_set = 1;
  }

  TEST_ASSERT(has_version && has_curr_conn && has_cmd_get && has_cmd_set);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_flush_all(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char val[64];

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_set(&c, "flush_me", "data", 4, 0, 0, resp, sizeof(resp)) ==
              0);
  TEST_ASSERT(client_get(&c, "flush_me", val, sizeof(val), NULL) == 0);
  TEST_ASSERT_STR_EQ(val, "data");

  TEST_ASSERT(client_flush_all(&c, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "OK");

  test_sleep_ms(1100);

  TEST_ASSERT(client_get(&c, "flush_me", val, sizeof(val), NULL) != 0);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_basic_run(void) {
  RUN_TEST(test_version);
  RUN_TEST(test_set_and_get);
  RUN_TEST(test_multiget);
  RUN_TEST(test_add_and_replace);
  RUN_TEST(test_delete);
  RUN_TEST(test_append_prepend);
  RUN_TEST(test_incr_decr);
  RUN_TEST(test_stats);
  RUN_TEST(test_flush_all);
  return 0;
}
