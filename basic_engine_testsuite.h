/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef BASIC_ENGINE_TESTSUITE_H
#define BASIC_ENGINE_TESTSUITE_H 1

#include <memcached/engine_testapp.h>

MEMCACHED_PUBLIC_API
engine_test_t* get_tests(void);

MEMCACHED_PUBLIC_API
bool setup_suite(struct test_harness *th);


#endif
