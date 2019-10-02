#include "item_access_tests.h"
#include <unistd.h>
#include <assert.h>

char *test_write(storage_engine *engine, char *key, char *value) {
    unsigned int nkey = strlen(key);
    unsigned int nvalue = strlen(value);
    char *locator = calloc(1, engine->locator_size);

    item *it = generate_item(key, nkey, value, nvalue);
    int ret = engine->write_item(it, 0, locator);
    assert(ret == 0);

    char written_key[nkey+1];
    sprintf(written_key, "%.*s", it->nkey, ITEM_key(it));
    assert(strncmp(key, written_key, nkey) == 0);

    char written_value[nvalue+1];
    sprintf(written_value, "%.*s", it->nbytes, ITEM_data(it));
    assert(strncmp(value, written_value, nvalue) == 0);

    return locator;
}

char *test_chunked_write(storage_engine *engine, char *key, char *value, unsigned int nperchunk) {
    unsigned int nkey = strlen(key);
    unsigned int nvalue = strlen(value);
    char *locator = calloc(1, engine->locator_size);

    item *it = generate_chunked_item(key, nkey, value, nvalue, nperchunk);
    int ret = engine->write_item(it, 0, locator);
    assert(ret == 0);

    char written_key[nkey+1];
    sprintf(written_key, "%.*s", it->nkey, ITEM_key(it));
    assert(strncmp(key, written_key, nkey) == 0);

    return locator;
}

void test_read(storage_engine *engine, char *locator, char *key, char *expvalue) {
    unsigned int nkey = strlen(key);
    unsigned int nexpvalue = 0;
    if(expvalue) {
        nexpvalue = strlen(expvalue);
    }

    item *hdr_it = generate_hdr_item(key, nkey, locator, engine->locator_size, nexpvalue);
    storage_read rd = prepare_read(hdr_it);
    int ret = engine->read_item(&rd, NULL, locator);
    assert(ret == 0);

    engine->submit(&rd);
    while(rd.active) {
        sleep(1);
    }

    if(expvalue) {
        assert(!rd.miss);

        char read_key[nkey+1];
        sprintf(read_key, "%.*s", rd.read_it->nkey, ITEM_key(rd.read_it));
        assert(strncmp(key, read_key, nkey) == 0);

        char read_value[nexpvalue+1];
        sprintf(read_value, "%.*s", rd.read_it->nbytes, ITEM_data(rd.read_it));
        assert(strncmp(expvalue, read_value, nexpvalue) == 0);
    }
    else {
        assert(rd.miss);
    }
}

void test_delete(storage_engine *engine, char *locator, char *key, unsigned int nvalue) {
    item *hdr_it = generate_hdr_item(key, strlen(key), locator, engine->locator_size, nvalue);
    int ret = engine->delete_item(hdr_it, locator);
    assert(ret == 0);
}
