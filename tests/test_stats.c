/*
 * test_stats.c - Test server statistics reporting.
 */

#include "c_harness.h"

static int test_general_stats(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[256];
  int has_pid = 0, has_uptime = 0, has_time = 0, has_version = 0;
  int has_curr_items = 0, has_total_items = 0, has_bytes = 0;
  int has_curr_conn = 0, has_total_conn = 0, has_cmd_get = 0, has_cmd_set = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "stats\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "STAT pid ") != NULL)
      has_pid = 1;
    if (strstr(line, "STAT uptime ") != NULL)
      has_uptime = 1;
    if (strstr(line, "STAT time ") != NULL)
      has_time = 1;
    if (strstr(line, "STAT version ") != NULL)
      has_version = 1;
    if (strstr(line, "STAT curr_items ") != NULL)
      has_curr_items = 1;
    if (strstr(line, "STAT total_items ") != NULL)
      has_total_items = 1;
    if (strstr(line, "STAT bytes ") != NULL)
      has_bytes = 1;
    if (strstr(line, "STAT curr_connections ") != NULL)
      has_curr_conn = 1;
    if (strstr(line, "STAT total_connections ") != NULL)
      has_total_conn = 1;
    if (strstr(line, "STAT cmd_get ") != NULL)
      has_cmd_get = 1;
    if (strstr(line, "STAT cmd_set ") != NULL)
      has_cmd_set = 1;
  }

  TEST_ASSERT(has_pid && has_uptime && has_time && has_version);
  TEST_ASSERT(has_curr_items && has_total_items && has_bytes);
  TEST_ASSERT(has_curr_conn && has_total_conn && has_cmd_get && has_cmd_set);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_settings_stats(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[256];
  int has_maxconns = 0, has_tcpport = 0, has_udpport = 0;
  int has_inter = 0, has_verbosity = 0, has_oldest = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "stats settings\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "STAT maxconns ") != NULL)
      has_maxconns = 1;
    if (strstr(line, "STAT tcpport ") != NULL)
      has_tcpport = 1;
    if (strstr(line, "STAT udpport ") != NULL)
      has_udpport = 1;
    if (strstr(line, "STAT inter ") != NULL)
      has_inter = 1;
    if (strstr(line, "STAT verbosity ") != NULL)
      has_verbosity = 1;
    if (strstr(line, "STAT oldest ") != NULL)
      has_oldest = 1;
  }

  TEST_ASSERT(has_maxconns && has_tcpport && has_udpport && has_inter &&
              has_verbosity && has_oldest);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

static int test_items_and_slabs_stats(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char resp[64];
  char line[256];
  int has_slabs_active = 0;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(
      client_set(&c, "stat_key", "stat_val", 8, 0, 0, resp, sizeof(resp)) == 0);
  TEST_ASSERT_STR_EQ(resp, "STORED");

  TEST_ASSERT(client_send_str(&c, "stats items\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
  }

  TEST_ASSERT(client_send_str(&c, "stats slabs\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "active_slabs") != NULL) {
      has_slabs_active = 1;
    }
  }

  TEST_ASSERT(has_slabs_active == 1);

  client_close(&c);
  srv_stop(&srv);
  return 0;
}

int test_stats_run(void) {
  RUN_TEST(test_general_stats);
  RUN_TEST(test_settings_stats);
  RUN_TEST(test_items_and_slabs_stats);
  return 0;
}
