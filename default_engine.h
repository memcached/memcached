/*
 * Summary: Specification of the storage engine interface.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Trond Norbye <trond.norbye@sun.com>
 */
#ifndef MEMCACHED_DEFAULT_ENGINE_H
#define MEMCACHED_DEFAULT_ENGINE_H

#include <pthread.h>
#include <stdbool.h>

#include <memcached/engine.h>

/* Forward decl */
struct default_engine;

#include "items.h"
#include "assoc.h"
#include "hash.h"
#include "slabs.h"

#ifdef __cplusplus
extern "C" {
#endif

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
};

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


/**
 * Definition of the private instance data used by the default engine.
 *
 * This is currently "work in progress" so it is not as clean as it should be.
 */
struct default_engine {
   ENGINE_HANDLE_V1 engine;
   SERVER_HANDLE_V1 server;

   /**
    * Is the engine initalized or not
    */
   bool initialized;

   /**
    * The cache layer (item_* and assoc_*) is currently protected by
    * this single mutex
    */
   pthread_mutex_t cache_lock;

   struct config config;
   struct engine_stats stats;
};

#endif
