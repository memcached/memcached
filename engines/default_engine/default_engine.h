/*
 * Summary: Specification of the storage engine interface.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Trond Norbye <trond.norbye@sun.com>
 */
#ifndef MEMCACHED_DEFAULT_ENGINE_H
#define MEMCACHED_DEFAULT_ENGINE_H

#include "config.h"

#include <pthread.h>
#include <stdbool.h>

#include <memcached/engine.h>
#include <memcached/util.h>
#include <memcached/visibility.h>

/* Slab sizing definitions. */
#define POWER_SMALLEST 1
#define POWER_LARGEST  200
#define CHUNK_ALIGN_BYTES 8
#define DONT_PREALLOC_SLABS
#define MAX_NUMBER_OF_SLAB_CLASSES (POWER_LARGEST + 1)

/** How long an object can reasonably be assumed to be locked before
    harvesting it on a low memory condition. */
#define TAIL_REPAIR_TIME (3 * 3600)


/* Forward decl */
struct default_engine;

#include "trace.h"
#include "items.h"
#include "assoc.h"
#include "slabs.h"

#ifdef __cplusplus
extern "C" {
#endif

   /* Flags */
#define ITEM_WITH_CAS 1

#define ITEM_LINKED (1<<8)

/* temp */
#define ITEM_SLABBED (2<<8)

struct config {
   bool use_cas;
   size_t verbose;
   rel_time_t oldest_live;
   bool evict_to_free;
   size_t maxbytes;
   bool preallocate;
   float factor;
   size_t chunk_size;
   size_t item_size_max;
   bool ignore_vbucket;
   bool vb0;
};

MEMCACHED_PUBLIC_API
ENGINE_ERROR_CODE create_instance(uint64_t interface,
                                  GET_SERVER_API get_server_api,
                                  ENGINE_HANDLE **handle);

/**
 * Statistic information collected by the default engine
 */
struct engine_stats {
   pthread_mutex_t lock;
   uint64_t evictions;
   uint64_t reclaimed;
   uint64_t curr_bytes;
   uint64_t curr_items;
   uint64_t total_items;
};

struct engine_scrubber {
   pthread_mutex_t lock;
   bool running;
   uint64_t visited;
   uint64_t cleaned;
   time_t started;
   time_t stopped;
};

struct tap_connections {
    pthread_mutex_t lock;
    size_t size;
    const void* *clients;
};

struct vbucket_info {
    int state : 2;
};

#define NUM_VBUCKETS 65536

/**
 * Definition of the private instance data used by the default engine.
 *
 * This is currently "work in progress" so it is not as clean as it should be.
 */
struct default_engine {
   ENGINE_HANDLE_V1 engine;
   SERVER_HANDLE_V1 server;
   GET_SERVER_API get_server_api;

   /**
    * Is the engine initalized or not
    */
   bool initialized;

   struct assoc assoc;
   struct slabs slabs;
   struct items items;

   /**
    * The cache layer (item_* and assoc_*) is currently protected by
    * this single mutex
    */
   pthread_mutex_t cache_lock;

   struct config config;
   struct engine_stats stats;
   struct engine_scrubber scrubber;
   struct tap_connections tap_connections;

   union {
       engine_info engine_info;
       char buffer[sizeof(engine_info) +
                   (sizeof(feature_info) * LAST_REGISTERED_ENGINE_FEATURE)];
   } info;

   char vbucket_infos[NUM_VBUCKETS];
};

char* item_get_data(const hash_item* item);
const void* item_get_key(const hash_item* item);
void item_set_cas(ENGINE_HANDLE *handle, const void *cookie,
                  item* item, uint64_t val);
uint64_t item_get_cas(const hash_item* item);
uint8_t item_get_clsid(const hash_item* item);
#endif
