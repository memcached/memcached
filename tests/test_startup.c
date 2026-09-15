/*
 * test_startup.c - Test server command-line options and startup validation.
 */

#include "c_harness.h"

static int test_default_startup(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char ver[64];
  int res;

  TEST_ASSERT(srv_start(&srv, 0, NULL) == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);
  res = client_version(&c, ver, sizeof(ver));
  client_close(&c);
  srv_stop(&srv);

  TEST_ASSERT(res == 0);
  TEST_ASSERT(strlen(ver) > 0);
  return 0;
}

static int test_illegal_threads(void) {
  const char *bin = get_memcached_bin();
  char cmd[512];
  int exit_code = 0;

#if defined(_WIN32) || defined(_MSC_VER)
  snprintf(cmd, sizeof(cmd), "%s -t 0 2>&1", bin);
#else
  const char *emu = get_memcached_emulator();
  if (emu && strlen(emu) > 0) {
    snprintf(cmd, sizeof(cmd), "%s %s -t 0 2>&1", emu, bin);
  } else {
    snprintf(cmd, sizeof(cmd), "%s -t 0 2>&1", bin);
  }
#endif

  run_cmd_capture(cmd, NULL, 0, &exit_code);
  TEST_ASSERT(exit_code != 0);
  return 0;
}

static int test_help(void) {
  const char *bin = get_memcached_bin();
  char cmd[512];
  char out[2048];
  int exit_code = 0;

#if defined(_WIN32) || defined(_MSC_VER)
  snprintf(cmd, sizeof(cmd), "%s -h 2>&1", bin);
#else
  const char *emu = get_memcached_emulator();
  if (emu && strlen(emu) > 0) {
    snprintf(cmd, sizeof(cmd), "%s %s -h 2>&1", emu, bin);
  } else {
    snprintf(cmd, sizeof(cmd), "%s -h 2>&1", bin);
  }
#endif

  run_cmd_capture(cmd, out, sizeof(out), &exit_code);
  TEST_ASSERT(strstr(out, "-p") != NULL || strstr(out, "memcached") != NULL ||
              exit_code == 0);
  return 0;
}

static int test_custom_maxconns(void) {
  struct memcached_srv srv;
  struct memcached_client c;
  char line[256];
  int found_maxconns = 0;

  TEST_ASSERT(srv_start(&srv, 0, "-c 512") == 0);
  TEST_ASSERT(client_connect(&c, srv.port) == 0);

  TEST_ASSERT(client_send_str(&c, "stats settings\r\n") == 0);
  while (client_readline(&c, line, sizeof(line)) > 0) {
    if (strncmp(line, "END", 3) == 0) {
      break;
    }
    if (strstr(line, "maxconns") != NULL && strstr(line, "512") != NULL) {
      found_maxconns = 1;
    }
  }

  client_close(&c);
  srv_stop(&srv);

  TEST_ASSERT(found_maxconns == 1);
  return 0;
}

int test_startup_run(void) {
  RUN_TEST(test_default_startup);
  RUN_TEST(test_illegal_threads);
  RUN_TEST(test_help);
  RUN_TEST(test_custom_maxconns);
  return 0;
}
