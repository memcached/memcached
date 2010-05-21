/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_ENGINE_TESTAPP_H
#define MEMCACHED_ENGINE_TESTAPP_H

#include <memcached/engine.h>

#ifdef    __cplusplus
extern "C" {
#endif

enum test_result {
    SUCCESS = 11,
    FAIL = 13,
    DIED = 14,
    CORE = 15,
    PENDING = 19
};

typedef struct test {
    const char *name;
    enum test_result(*tfun)(ENGINE_HANDLE *, ENGINE_HANDLE_V1 *);
    bool(*test_setup)(ENGINE_HANDLE *, ENGINE_HANDLE_V1 *);
    bool(*test_teardown)(ENGINE_HANDLE *, ENGINE_HANDLE_V1 *);
    const char *cfg;
} engine_test_t;

typedef engine_test_t* (*GET_TESTS)(void);

typedef bool (*SETUP_SUITE)(void);

typedef bool (*TEARDOWN_SUITE)(void);

#ifdef    __cplusplus
}
#endif

#endif    /* MEMCACHED_ENGINE_TESTAPP_H */
