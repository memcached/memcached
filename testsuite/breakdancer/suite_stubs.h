/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef TESTSUITE_H
#define TESTSUITE_H 1

#include <memcached/engine.h>
#include <memcached/engine_testapp.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

MEMCACHED_PUBLIC_API
engine_test_t* get_tests(void);

MEMCACHED_PUBLIC_API
bool setup_suite(struct test_harness *th);


bool test_setup(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
bool teardown(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void delay(int amt);
void add(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void append(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void decr(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void decrWithDefault(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void prepend(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void flush(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void del(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void set(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void incr(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);
void incrWithDefault(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);

void checkValue(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1, const char* exp);
void assertNotExists(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1);

#define assertHasError() assert(hasError)
#define assertHasNoError() assert(!hasError)

extern int expiry;
extern bool hasError;
extern struct test_harness testHarness;

#ifdef __cplusplus
}
#endif

#endif /* SUITE_STUBS_H */
