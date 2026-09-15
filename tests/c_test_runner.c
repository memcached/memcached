/*
 * c_test_runner.c - Test runner for C89 memcached test suites.
 */

#include "c_harness.h"

int test_startup_run(void);
int test_basic_run(void);
int test_getset_run(void);
int test_flags_run(void);
int test_cas_run(void);
int test_touch_run(void);
int test_incrdecr_run(void);
int test_expirations_run(void);
int test_flush_all_run(void);
int test_stats_run(void);
int test_bogus_run(void);
int test_quit_run(void);
int test_multiversioning_run(void);
int test_binary_run(void);
int test_limits_run(void);
int test_metaget_run(void);
int test_dyn_maxbytes_run(void);
int test_slabs_run(void);

struct test_module {
  const char *name;
  int (*func)(void);
};

static const struct test_module modules[] = {
    {"test_startup", test_startup_run},
    {"test_basic", test_basic_run},
    {"test_getset", test_getset_run},
    {"test_flags", test_flags_run},
    {"test_cas", test_cas_run},
    {"test_touch", test_touch_run},
    {"test_incrdecr", test_incrdecr_run},
    {"test_expirations", test_expirations_run},
    {"test_flush_all", test_flush_all_run},
    {"test_stats", test_stats_run},
    {"test_bogus", test_bogus_run},
    {"test_quit", test_quit_run},
    {"test_multiversioning", test_multiversioning_run},
    {"test_binary", test_binary_run},
    {"test_limits", test_limits_run},
    {"test_metaget", test_metaget_run},
    {"test_dyn_maxbytes", test_dyn_maxbytes_run},
    {"test_slabs", test_slabs_run}};

int main(int argc, char **argv) {
  int i;
  int num_modules;
  const char *target = "all";

  num_modules = (int)(sizeof(modules) / sizeof(modules[0]));

  if (argc > 1) {
    target = argv[1];
  }

  test_harness_init();

  if (strcmp(target, "all") == 0) {
    for (i = 0; i < num_modules; i++) {
      modules[i].func();
    }
  } else {
    int found = 0;
    for (i = 0; i < num_modules; i++) {
      if (strcmp(target, modules[i].name) == 0 ||
          (strncmp(target, "test_", 5) != 0 &&
           strcmp(target, modules[i].name + 5) == 0)) {
        modules[i].func();
        found = 1;
        break;
      }
    }
    if (!found) {
      fprintf(stderr, "Unknown test module: %s\n", target);
      return 1;
    }
  }

  printf("\nTest summary: %d tests run, %d failed.\n", g_tests_run,
         g_tests_failed);
  return (g_tests_failed == 0) ? 0 : 1;
}
