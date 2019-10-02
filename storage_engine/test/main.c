/* Sample test for storage engine */

#include "engine.h"
#include "test_helper.h"
#include "item_access_tests.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define KEY1 "Key1"
#define VALUE1 "Value"
#define KEY2 "Key2"
#define VALUE2 "Value1Value2Value3"

storage_engine *engine;
core_handle core;


int main() {
    printf("Running tests\n");

    core = create_core_mock();
    engine = create_engine();
    engine->apply_defaults(NULL);
    char *options = "";
    engine->read_config(&options);
    int init_success = engine->init(&core);
    assert(init_success == 0);
    engine->start_threads();

    char *locator = test_write(engine, KEY1, VALUE1);
    printf("Write test passed\n");
    test_read(engine, locator, KEY1, VALUE1);
    printf("Read test passed\n");
    test_delete(engine, locator, KEY1, strlen(VALUE1));
    test_read(engine, locator, KEY1, NULL);
    printf("Delete test passed\n");
    free(locator);

    locator = test_chunked_write(engine, KEY2, VALUE2, 6);
    printf("Write chunked test passed\n");
    test_read(engine, locator, KEY2, VALUE2);
    printf("Read chunked test passed\n");
    free(locator);

    printf("Tests complete\n");
}

