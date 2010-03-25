#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stddef.h>
#include <inttypes.h>

#include "default_engine.h"
#include "util.h"
#include "memcached/config_parser.h"

static const char* default_get_info(ENGINE_HANDLE* handle);
static ENGINE_ERROR_CODE default_initialize(ENGINE_HANDLE* handle,
                                            const char* config_str);
static void default_destroy(ENGINE_HANDLE* handle);
static ENGINE_ERROR_CODE default_item_allocate(ENGINE_HANDLE* handle,
                                               const void* cookie,
                                               item **item,
                                               const void* key,
                                               const size_t nkey,
                                               const size_t nbytes,
                                               const int flags,
                                               const rel_time_t exptime);
static ENGINE_ERROR_CODE default_item_delete(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             item* item);
static void default_item_release(ENGINE_HANDLE* handle, const void *cookie,
                                 item* item);
static ENGINE_ERROR_CODE default_get(ENGINE_HANDLE* handle,
                                     const void* cookie,
                                     item** item,
                                     const void* key,
                                     const int nkey);
static ENGINE_ERROR_CODE default_get_stats(ENGINE_HANDLE* handle,
                  const void *cookie,
                  const char *stat_key,
                  int nkey,
                  ADD_STAT add_stat);
static void default_reset_stats(ENGINE_HANDLE* handle, const void *cookie);
static ENGINE_ERROR_CODE default_store(ENGINE_HANDLE* handle,
                                       const void *cookie,
                                       item* item,
                                       uint64_t *cas,
                                       ENGINE_STORE_OPERATION operation);
static ENGINE_ERROR_CODE default_arithmetic(ENGINE_HANDLE* handle,
                                            const void* cookie,
                                            const void* key,
                                            const int nkey,
                                            const bool increment,
                                            const bool create,
                                            const uint64_t delta,
                                            const uint64_t initial,
                                            const rel_time_t exptime,
                                            uint64_t *cas,
                                            uint64_t *result);
static ENGINE_ERROR_CODE default_flush(ENGINE_HANDLE* handle,
                                       const void* cookie, time_t when);
static ENGINE_ERROR_CODE initalize_configuration(struct default_engine *se,
                                                 const char *cfg_str);
static ENGINE_ERROR_CODE default_unknown_command(ENGINE_HANDLE* handle,
                                                 const void* cookie,
                                                 protocol_binary_request_header *request,
                                                 ADD_RESPONSE response);

ENGINE_ERROR_CODE create_instance(uint64_t interface,
                                  GET_SERVER_API get_server_api,
                                  ENGINE_HANDLE **handle) {
   SERVER_HANDLE_V1 *api = get_server_api(1);
   if (interface != 1 || api == NULL) {
      return ENGINE_ENOTSUP;
   }

   struct default_engine *engine = malloc(sizeof(*engine));
   if (engine == NULL) {
      return ENGINE_ENOMEM;
   }

   struct default_engine default_engine = {
      .engine = {
         .interface = {
            .interface = 1
         },
         .get_info = default_get_info,
         .initialize = default_initialize,
         .destroy = default_destroy,
         .allocate = default_item_allocate,
         .remove = default_item_delete,
         .release = default_item_release,
         .get = default_get,
         .get_stats = default_get_stats,
         .reset_stats = default_reset_stats,
         .store = default_store,
         .arithmetic = default_arithmetic,
         .flush = default_flush,
         .unknown_command = default_unknown_command,
         .item_get_cas = item_get_cas,
         .item_set_cas = item_set_cas,
         .item_get_key = item_get_key,
         .item_get_data = item_get_data,
         .item_get_clsid = item_get_clsid
      },
      .server = *api,
      .initialized = true,
      .assoc = {
         .hashpower = 16,
      },
      .slabs = {
         .lock = PTHREAD_MUTEX_INITIALIZER
      },
      .cache_lock = PTHREAD_MUTEX_INITIALIZER,
      .stats = {
         .lock = PTHREAD_MUTEX_INITIALIZER,
      },
      .config = {
         .use_cas = true,
         .verbose = 0,
         .oldest_live = 0,
         .evict_to_free = true,
         .maxbytes = 64 * 1024 * 1024,
         .preallocate = false,
         .factor = 1.25,
         .chunk_size = 48,
         .item_size_max= 1024 * 1024,
      }
   };

   default_engine.server = *api;
   *engine = default_engine;

   *handle = (ENGINE_HANDLE*)&engine->engine;
   return ENGINE_SUCCESS;
}

static inline struct default_engine* get_handle(ENGINE_HANDLE* handle) {
   return (struct default_engine*)handle;
}

static inline hash_item* get_real_item(item* item) {
   hash_item it;
   ptrdiff_t offset = (caddr_t)&it.item - (caddr_t)&it;
   return (hash_item*) (((caddr_t) item) - (offset));
}

static const char* default_get_info(ENGINE_HANDLE* handle) {
   return "Default engine v0.1";
}

static ENGINE_ERROR_CODE default_initialize(ENGINE_HANDLE* handle,
                                            const char* config_str) {
   struct default_engine* se = get_handle(handle);

   ENGINE_ERROR_CODE ret = initalize_configuration(se, config_str);
   if (ret != ENGINE_SUCCESS) {
      return ret;
   }

   ret = assoc_init(se);
   if (ret != ENGINE_SUCCESS) {
      return ret;
   }

   ret = slabs_init(se, se->config.maxbytes, se->config.factor,
                    se->config.preallocate);
   if (ret != ENGINE_SUCCESS) {
      return ret;
   }

   return ENGINE_SUCCESS;
}

static void default_destroy(ENGINE_HANDLE* handle) {
   struct default_engine* se = get_handle(handle);

   if (se->initialized) {
      pthread_mutex_destroy(&se->cache_lock);
      pthread_mutex_destroy(&se->stats.lock);
      se->initialized = false;
      free(se);
   }
}

static ENGINE_ERROR_CODE default_item_allocate(ENGINE_HANDLE* handle,
                                               const void* cookie,
                                               item **item,
                                               const void* key,
                                               const size_t nkey,
                                               const size_t nbytes,
                                               const int flags,
                                               const rel_time_t exptime) {
   struct default_engine* engine = get_handle(handle);
   size_t ntotal = sizeof(hash_item) + nkey + nbytes;
   if (engine->config.use_cas) {
      ntotal += sizeof(uint64_t);
   }
   unsigned int id = slabs_clsid(engine, ntotal);
   if (id == 0) {
      return ENGINE_E2BIG;
   }

   hash_item *it;
   it = item_alloc(engine, key, nkey, flags, exptime, nbytes);

   if (it != NULL) {
      *item = &it->item;
      return ENGINE_SUCCESS;
   } else {
      return ENGINE_ENOMEM;
   }
}

static ENGINE_ERROR_CODE default_item_delete(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             item* item) {
   item_unlink(get_handle(handle), get_real_item(item));
   return ENGINE_SUCCESS;
}

static void default_item_release(ENGINE_HANDLE* handle,
                                 const void *cookie,
                                 item* item) {
   item_release(get_handle(handle), get_real_item(item));
}

static ENGINE_ERROR_CODE default_get(ENGINE_HANDLE* handle,
                                     const void* cookie,
                                     item** item,
                                     const void* key,
                                     const int nkey) {
   hash_item *it = item_get(get_handle(handle), key, nkey);
   if (it != NULL) {
      *item = &it->item;
      return ENGINE_SUCCESS;
   } else {
      *item = NULL;
      return ENGINE_KEY_ENOENT;
   }
}

static ENGINE_ERROR_CODE default_get_stats(ENGINE_HANDLE* handle,
                                           const void* cookie,
                                           const char* stat_key,
                                           int nkey,
                                           ADD_STAT add_stat)
{
   struct default_engine* engine = get_handle(handle);
   ENGINE_ERROR_CODE ret = ENGINE_SUCCESS;

   if (stat_key == NULL) {
      char val[128];
      int len;

      pthread_mutex_lock(&engine->stats.lock);
      len = sprintf(val, "%"PRIu64, (uint64_t)engine->stats.evictions);
      add_stat("evictions", 9, val, len, cookie);
      len = sprintf(val, "%"PRIu64, (uint64_t)engine->stats.curr_items);
      add_stat("curr_items", 10, val, len, cookie);
      len = sprintf(val, "%"PRIu64, (uint64_t)engine->stats.total_items);
      add_stat("total_items", 11, val, len, cookie);
      len = sprintf(val, "%"PRIu64, (uint64_t)engine->stats.curr_bytes);
      add_stat("bytes", 5, val, len, cookie);
      len = sprintf(val, "%"PRIu64, engine->stats.reclaimed);
      add_stat("reclaimed", 9, val, len, cookie);
      pthread_mutex_unlock(&engine->stats.lock);
   } else if (strncmp(stat_key, "slabs", 5) == 0) {
      slabs_stats(engine, add_stat, cookie);
   } else if (strncmp(stat_key, "items", 5) == 0) {
      item_stats(engine, add_stat, cookie);
   } else if (strncmp(stat_key, "sizes", 5) == 0) {
      item_stats_sizes(engine, add_stat, cookie);
   } else {
      ret = ENGINE_KEY_ENOENT;
   }

   return ret;
}

static ENGINE_ERROR_CODE default_store(ENGINE_HANDLE* handle,
                                       const void *cookie,
                                       item* item,
                                       uint64_t *cas,
                                       ENGINE_STORE_OPERATION operation) {
   return store_item(get_handle(handle), get_real_item(item), cas, operation);
}

static ENGINE_ERROR_CODE default_arithmetic(ENGINE_HANDLE* handle,
                                            const void* cookie,
                                            const void* key,
                                            const int nkey,
                                            const bool increment,
                                            const bool create,
                                            const uint64_t delta,
                                            const uint64_t initial,
                                            const rel_time_t exptime,
                                            uint64_t *cas,
                                            uint64_t *result) {
   ENGINE_ERROR_CODE ret = ENGINE_SUCCESS;
   struct default_engine *engine = get_handle(handle);
   hash_item *item = item_get(engine, key, nkey);

   if (item == NULL) {
      if (!create) {
         return ENGINE_KEY_ENOENT;
      } else {
         char buffer[1023];
         int len = snprintf(buffer, sizeof(buffer), "%"PRIu64"\r\n",
                            (uint64_t)initial);

         item = item_alloc(engine, key, nkey, 0, exptime, len);
         if (item == NULL) {
            return ENGINE_ENOMEM;
         }
         memcpy((void*)item_get_data(&item->item), buffer, len);
         if ((ret = store_item(engine, item, cas,
                               OPERATION_ADD)) == ENGINE_KEY_EEXISTS) {
            item_release(engine, item);
            return default_arithmetic(handle, cookie, key, nkey, increment,
                                      create, delta, initial, exptime, cas,
                                      result);
         }

         *result = initial;
         *cas = item_get_cas(&item->item);
         item_release(engine, item);
      }
   } else {
      ret = add_delta(engine, item, increment, delta, cas, result);
      item_release(engine, item);
   }

   return ret;
}

static ENGINE_ERROR_CODE default_flush(ENGINE_HANDLE* handle,
                                       const void* cookie, time_t when) {
   item_flush_expired(get_handle(handle), when);

   return ENGINE_SUCCESS;
}

static void default_reset_stats(ENGINE_HANDLE* handle, const void *cookie) {
   struct default_engine *engine = get_handle(handle);
   item_stats_reset(engine);

   pthread_mutex_lock(&engine->stats.lock);
   engine->stats.evictions = 0;
   engine->stats.reclaimed = 0;
   engine->stats.total_items = 0;
   pthread_mutex_unlock(&engine->stats.lock);
}

static ENGINE_ERROR_CODE initalize_configuration(struct default_engine *se,
                                                 const char *cfg_str) {
   ENGINE_ERROR_CODE ret = ENGINE_SUCCESS;

   if (cfg_str != NULL) {
      struct config_item items[] = {
         { .key = "use_cas",
           .datatype = DT_BOOL,
           .value.dt_bool = &se->config.use_cas },
         { .key = "verbose",
           .datatype = DT_SIZE,
           .value.dt_size = &se->config.verbose },
         { .key = "eviction",
           .datatype = DT_BOOL,
           .value.dt_bool = &se->config.evict_to_free },
         { .key = "cache_size",
           .datatype = DT_SIZE,
           .value.dt_size = &se->config.maxbytes },
         { .key = "preallocate",
           .datatype = DT_BOOL,
           .value.dt_bool = &se->config.preallocate },
         { .key = "factor",
           .datatype = DT_FLOAT,
           .value.dt_float = &se->config.factor },
         { .key = "chunk_size",
           .datatype = DT_SIZE,
           .value.dt_size = &se->config.chunk_size },
         { .key = "item_size_max",
           .datatype = DT_SIZE,
           .value.dt_size = &se->config.item_size_max },
         { .key = "config_file",
           .datatype = DT_CONFIGFILE },
         { .key = NULL}
      };

      ret = se->server.parse_config(cfg_str, items, stderr);
   }

   return ENGINE_SUCCESS;
}

static ENGINE_ERROR_CODE default_unknown_command(ENGINE_HANDLE* handle,
                                                 const void* cookie,
                                                 protocol_binary_request_header *request,
                                                 ADD_RESPONSE response)
{
   if (response(NULL, 0, NULL, 0, NULL, 0,
                PROTOCOL_BINARY_RAW_BYTES,
                PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, 0, cookie)) {
      return ENGINE_SUCCESS;
   } else {
      return ENGINE_FAILED;
   }
}


uint64_t item_get_cas(const item* item)
{
    if (item->iflag & ITEM_WITH_CAS) {
        return *(uint64_t*)(item + 1);
    }
    return 0;
}

void item_set_cas(item* item, uint64_t val)
{
    if (item->iflag & ITEM_WITH_CAS) {
        *(uint64_t*)(item + 1) = val;
    }
}

const char* item_get_key(const item* item)
{
    char *ret = (void*)(item + 1);
    if (item->iflag & ITEM_WITH_CAS) {
        ret += sizeof(uint64_t);
    }

    return ret;
}

char* item_get_data(const item* item)
{
    return ((char*)item_get_key(item)) + item->nkey;
}

uint8_t item_get_clsid(const item* item)
{
    return 0;
}
