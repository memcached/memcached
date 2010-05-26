#include <sys/wait.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <engine_loader.h>
#include <memcached/engine_testapp.h>
#include <memcached/extension_loggers.h>
#include <memcached/mock_server.h>

EXTENSION_LOGGER_DESCRIPTOR *logger_descriptor = NULL;

static void usage(void) {
    printf("\n");
    printf("engine_testapp -E <path_to_engine_lib> -T <path_to_testlib>\n");
    printf("               [-e <engine_config>] [-h]\n");
    printf("\n");
    printf("-E <path_to_engine_lib>      Path to the engine library file. The\n");
    printf("                             engine library file is a library file\n");
    printf("                             (.so or .dll) that the contains the \n");
    printf("                             implementation of the engine being\n");
    printf("                             tested.\n");
    printf("\n");
    printf("-T <path_to_testlib>         Path to the test library file. The test\n");
    printf("                             library file is a library file (.so or\n");
    printf("                             .dll) that contains the set of tests\n");
    printf("                             to be executed.\n");
    printf("\n");
    printf("-e <engine_config>           Engine configuration string passed to\n");
    printf("                             the engine.\n");
    printf("\n");
    printf("-h                           Prints this usage text.\n");
    printf("\n");
}

static int report_test(enum test_result r) {
    int rc = 0;
    char *msg = NULL;
    bool color_enabled = getenv("TESTAPP_ENABLE_COLOR") != NULL;
    int color = 0;
    char color_str[8] = { 0 };
    char *reset_color = "\033[m";
    switch(r) {
    case SUCCESS:
        msg="OK";
        color = 32;
        break;
    case FAIL:
        color = 31;
        msg="FAIL";
        rc = 1;
        break;
    case DIED:
        color = 31;
        msg = "DIED";
        rc = 1;
        break;
    case CORE:
        color = 31;
        msg = "CORE DUMPED";
        rc = 1;
        break;
    case PENDING:
        color = 33;
        msg = "PENDING";
        break;
    }
    assert(msg);
    if (color_enabled) {
        snprintf(color_str, sizeof(color_str), "\033[%dm", color);
    }
    printf("%s%s%s\n", color_str, msg, color_enabled ? reset_color : "");
    return rc;
}

static ENGINE_HANDLE_V1 *start_your_engines(const char *engine, const char* cfg, bool engine_init) {

    ENGINE_HANDLE *engine_handle = NULL;

    init_mock_server(engine_handle);
    if(!load_engine(engine, &get_mock_server_api, logger_descriptor, &engine_handle)) {
        fprintf(stderr, "Failed to load engine %s.\n", engine);
        return NULL;
    }

    if (engine_init) {
        if(!init_engine(engine_handle, cfg, logger_descriptor)) {
            fprintf(stderr, "Failed to init engine %s with config %s.\n", engine, cfg);
            return NULL;
        }
    }

    return (ENGINE_HANDLE_V1*) engine_handle;
}

static void reload_engine(ENGINE_HANDLE **h, ENGINE_HANDLE_V1 **h1, const char* engine, const char *cfg, bool init) {
    (*h1)->destroy((*h));
    *h1 = start_your_engines(engine, cfg, init);
    *h = (ENGINE_HANDLE*)(*h1);
}

static enum test_result run_test(engine_test_t test, const char *engine, const char *default_cfg) {
    enum test_result ret = PENDING;
    if (test.tfun != NULL) {
#ifndef USE_GCOV
        pid_t pid = fork();
        if (pid == 0) {
#endif
            /* Start the engines and go */
            ENGINE_HANDLE_V1 *h = start_your_engines(engine, test.cfg ? test.cfg : default_cfg, true);
            if (test.test_setup != NULL) {
                if (!test.test_setup((ENGINE_HANDLE*)h, h)) {
                    fprintf(stderr, "Failed to run setup for test %s\n", test.name);
                    return FAIL;
                }
            }
            ret = test.tfun((ENGINE_HANDLE*)h, h);
            if (test.test_teardown != NULL) {
                if (!test.test_teardown((ENGINE_HANDLE*)h, h)) {
                    fprintf(stderr, "WARNING: Failed to run teardown for test %s\n", test.name);
                }
            }
            h->destroy((ENGINE_HANDLE*)h);
#ifndef USE_GCOV
            exit((int)ret);
        } else if (pid == (pid_t)-1) {
            ret = FAIL;
        } else {
            int rc;
            while (waitpid(pid, &rc, 0) == (pid_t)-1) {
                if (errno != EINTR) {
                    abort();
                }
            }

            if (WIFEXITED(rc)) {
                ret = (enum test_result)WEXITSTATUS(rc);
            } else if (WIFSIGNALED(rc) && WCOREDUMP(rc)) {
                ret = CORE;
            } else {
                ret = DIED;
            }
        }
#endif
    }

    return ret;
}


int main(int argc, char **argv) {
    int c, exitcode = 0, num_cases = 0;
    const char *engine = NULL;
    const char *engine_args = NULL;
    const char *test_suite = NULL;
    engine_test_t *testcases = NULL;
    logger_descriptor = get_null_logger();

    /* Hack to remove the warning from C99 */
    union {
        GET_TESTS get_tests;
        void* voidptr;
    } my_get_test = {.get_tests = NULL };

    /* Hack to remove the warning from C99 */
    union {
        SETUP_SUITE setup_suite;
        void* voidptr;
    } my_setup_suite = {.setup_suite = NULL };

    /* Hack to remove the warning from C99 */
    union {
        TEARDOWN_SUITE teardown_suite;
        void* voidptr;
    } my_teardown_suite = {.teardown_suite = NULL };


    /* Use unbuffered stdio */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* process arguments */
    while (-1 != (c = getopt(argc, argv,
          "h"  /* usage */
          "E:"  /* Engine to load */
          "e:"  /* Engine options */
          "T:"   /* Library with tests to load */
        ))) {
        switch (c) {
        case 'E':
            engine = optarg;
            break;
        case 'e':
            engine_args = optarg;
            break;
        case 'h':
            usage();
            return 0;
        case 'T':
            test_suite = optarg;
            break;
        default:
            fprintf(stderr, "Illegal argument \"%c\"\n", c);
            return 1;
        }
    }

    //validate args
    if (engine == NULL) {
        fprintf(stderr, "You must provide a path to the storage engine library.\n");
        return 1;
    }

    if (test_suite == NULL) {
        fprintf(stderr, "You must provide a path to the testsuite library.\n");
        return 1;
    }

    //load test_suite
    void* handle = dlopen(test_suite, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        const char *msg = dlerror();
        fprintf(stderr, "Failed to load testsuite %s: %s\n", test_suite, msg ? msg : "unknown error");
        return 1;
    }

    //get the test cases
    void *symbol = dlsym(handle, "get_tests");
    if (symbol == NULL) {
        const char *msg = dlerror();
        fprintf(stderr, "Could not find get_tests function in testsuite %s: %s\n", test_suite, msg ? msg : "unknown error");
        return 1;
    }
    my_get_test.voidptr = symbol;
    testcases = (*my_get_test.get_tests)();

    //set up the suite if needed
    struct test_harness harness = { .default_engine_cfg = engine_args,
                                    .engine_path = engine,
                                    .reload_engine = reload_engine,
                                    .start_engine = start_your_engines};
    symbol = dlsym(handle, "setup_suite");
    if (symbol != NULL) {
        my_setup_suite.voidptr = symbol;
        if (!(*my_setup_suite.setup_suite)(&harness)) {
            fprintf(stderr, "Failed to set up test suite %s \n", test_suite);
            return 1;
        }
    }


    for (num_cases = 0; testcases[num_cases].name; num_cases++) {
        /* Just counting */
    }

    printf("1..%d\n", num_cases);

    int i;
    for (i = 0; testcases[i].name; i++) {
        printf("Running %s... ", testcases[i].name);
        fflush(stdout);
        exitcode += report_test(run_test(testcases[i], engine, engine_args));
    }

    //tear down the suite if needed
    symbol = dlsym(handle, "teardown_suite");
    if (symbol != NULL) {
        my_teardown_suite.voidptr = symbol;
        if (!(*my_teardown_suite.teardown_suite)()) {
            fprintf(stderr, "Failed to teardown up test suite %s \n", test_suite);
        }
    }

    return exitcode;
}
