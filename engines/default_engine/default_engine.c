/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"

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
#include "memcached/util.h"
#include "memcached/config_parser.h"

static const engine_info* default_get_info(ENGINE_HANDLE* handle);
static ENGINE_ERROR_CODE default_initialize(ENGINE_HANDLE* handle,
                                            const char* config_str);
static void default_destroy(ENGINE_HANDLE* handle,
                            const bool force);
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
                                             const void* key,
                                             const size_t nkey,
                                             uint64_t cas,
                                             uint16_t vbucket);

static void default_item_release(ENGINE_HANDLE* handle, const void *cookie,
                                 item* item);
static ENGINE_ERROR_CODE default_get(ENGINE_HANDLE* handle,
                                     const void* cookie,
                                     item** item,
                                     const void* key,
                                     const int nkey,
                                     uint16_t vbucket);
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
                                       ENGINE_STORE_OPERATION operation,
                                       uint16_t vbucket);
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
                                            uint64_t *result,
                                            uint16_t vbucket);
static ENGINE_ERROR_CODE default_flush(ENGINE_HANDLE* handle,
                                       const void* cookie, time_t when);
static ENGINE_ERROR_CODE initalize_configuration(struct default_engine *se,
                                                 const char *cfg_str);
static ENGINE_ERROR_CODE default_unknown_command(ENGINE_HANDLE* handle,
                                                 const void* cookie,
                                                 protocol_binary_request_header *request,
                                                 ADD_RESPONSE response);

static ENGINE_ERROR_CODE default_tap_notify(ENGINE_HANDLE* handle,
                                            const void *cookie,
                                            void *engine_specific,
                                            uint16_t nengine,
                                            uint8_t ttl,
                                            uint16_t tap_flags,
                                            tap_event_t tap_event,
                                            uint32_t tap_seqno,
                                            const void *key,
                                            size_t nkey,
                                            uint32_t flags,
                                            uint32_t exptime,
                                            uint64_t cas,
                                            const void *data,
                                            size_t ndata,
                                            uint16_t vbucket);

static TAP_ITERATOR default_get_tap_iterator(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             const void* client,
                                             size_t nclient,
                                             uint32_t flags,
                                             const void* userdata,
                                             size_t nuserdata);

static void default_handle_disconnect(const void *cookie,
                                      ENGINE_EVENT_TYPE type,
                                      const void *event_data,
                                      const void *cb_data);

union vbucket_info_adapter {
    char c;
    struct vbucket_info v;
};

static void set_vbucket_state(struct default_engine *e,
                              uint16_t vbid, vbucket_state_t to) {
    union vbucket_info_adapter vi;
    vi.c = e->vbucket_infos[vbid];
    vi.v.state = to;
    e->vbucket_infos[vbid] = vi.c;
}

static vbucket_state_t get_vbucket_state(struct default_engine *e,
                                         uint16_t vbid) {
    union vbucket_info_adapter vi;
    vi.c = e->vbucket_infos[vbid];
    return vi.v.state;
}

static bool handled_vbucket(struct default_engine *e, uint16_t vbid) {
    return e->config.ignore_vbucket
        || (get_vbucket_state(e, vbid) == vbucket_state_active);
}

/* mechanism for handling bad vbucket requests */
#define VBUCKET_GUARD(e, v) if (!handled_vbucket(e, v)) { return ENGINE_NOT_MY_VBUCKET; }

static bool get_item_info(ENGINE_HANDLE *handle, const void *cookie,
                          const item* item, item_info *item_info);

static const char const * vbucket_state_name(vbucket_state_t s) {
    static const char const * vbucket_states[] = {
        [vbucket_state_active] = "active",
        [vbucket_state_replica] = "replica",
        [vbucket_state_pending] = "pending",
        [vbucket_state_dead] = "dead"
    };
    if (is_valid_vbucket_state_t(s)) {
        return vbucket_states[s];
    } else {
        return "Illegal vbucket state";
    }
}

ENGINE_ERROR_CODE create_instance(uint64_t interface,
                                  GET_SERVER_API get_server_api,
                                  ENGINE_HANDLE **handle) {
   SERVER_HANDLE_V1 *api = get_server_api();
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
         .tap_notify = default_tap_notify,
         .get_tap_iterator = default_get_tap_iterator,
         .item_set_cas = item_set_cas,
         .get_item_info = get_item_info
      },
      .server = *api,
      .get_server_api = get_server_api,
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
       },
      .scrubber = {
         .lock = PTHREAD_MUTEX_INITIALIZER,
      },
      .tap_connections = {
         .lock = PTHREAD_MUTEX_INITIALIZER,
         .size = 10,
      },
      .info.engine_info = {
           .description = "Default engine v0.1",
           .num_features = 1,
           .features = {
               [0].feature = ENGINE_FEATURE_LRU
           }
       }
   };

   *engine = default_engine;
   engine->tap_connections.clients = calloc(default_engine.tap_connections.size, sizeof(void*));
   if (engine->tap_connections.clients == NULL) {
       free(engine);
       return ENGINE_ENOMEM;
   }
   *handle = (ENGINE_HANDLE*)&engine->engine;
   return ENGINE_SUCCESS;
}

static inline struct default_engine* get_handle(ENGINE_HANDLE* handle) {
   return (struct default_engine*)handle;
}

static inline hash_item* get_real_item(item* item) {
    return (hash_item*)item;
}

static const engine_info* default_get_info(ENGINE_HANDLE* handle) {
    return &get_handle(handle)->info.engine_info;
}

static ENGINE_ERROR_CODE default_initialize(ENGINE_HANDLE* handle,
                                            const char* config_str) {
   struct default_engine* se = get_handle(handle);

   ENGINE_ERROR_CODE ret = initalize_configuration(se, config_str);
   if (ret != ENGINE_SUCCESS) {
      return ret;
   }

   /* fixup feature_info */
   if (se->config.use_cas) {
       se->info.engine_info.features[se->info.engine_info.num_features++].feature = ENGINE_FEATURE_CAS;
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

   se->server.callback->register_callback(handle, ON_DISCONNECT, default_handle_disconnect, handle);

   return ENGINE_SUCCESS;
}

static void default_destroy(ENGINE_HANDLE* handle, const bool force) {
   (void) force;
   struct default_engine* se = get_handle(handle);

   if (se->initialized) {
      pthread_mutex_destroy(&se->cache_lock);
      pthread_mutex_destroy(&se->stats.lock);
      pthread_mutex_destroy(&se->slabs.lock);
      se->initialized = false;
      free(se->tap_connections.clients);
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
   it = item_alloc(engine, key, nkey, flags, engine->server.core->realtime(exptime),
                   nbytes, cookie);

   if (it != NULL) {
      *item = it;
      return ENGINE_SUCCESS;
   } else {
      return ENGINE_ENOMEM;
   }
}

static ENGINE_ERROR_CODE default_item_delete(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             const void* key,
                                             const size_t nkey,
                                             uint64_t cas,
                                             uint16_t vbucket)
{
   struct default_engine* engine = get_handle(handle);
   VBUCKET_GUARD(engine, vbucket);

   hash_item *it = item_get(engine, key, nkey);
   if (it == NULL) {
      return ENGINE_KEY_ENOENT;
   }

   if (cas == 0 || cas == item_get_cas(it)) {
      item_unlink(engine, it);
      item_release(engine, it);
   } else {
      return ENGINE_KEY_EEXISTS;
   }

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
                                     const int nkey,
                                     uint16_t vbucket) {
   struct default_engine *engine = get_handle(handle);
   VBUCKET_GUARD(engine, vbucket);

   *item = item_get(engine, key, nkey);
   if (*item != NULL) {
      return ENGINE_SUCCESS;
   } else {
      return ENGINE_KEY_ENOENT;
   }
}

static void stats_vbucket(struct default_engine *e,
                          ADD_STAT add_stat,
                          const void *cookie) {
    for (int i = 0; i < NUM_VBUCKETS; i++) {
        vbucket_state_t state = get_vbucket_state(e, i);
        if (state != vbucket_state_dead) {
            char buf[16];
            snprintf(buf, sizeof(buf), "vb_%d", i);
            const char * state_name = vbucket_state_name(state);
            add_stat(buf, strlen(buf), state_name, strlen(state_name), cookie);
        }
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
      len = sprintf(val, "%"PRIu64, (uint64_t)engine->config.maxbytes);
      add_stat("engine_maxbytes", 15, val, len, cookie);
      pthread_mutex_unlock(&engine->stats.lock);
   } else if (strncmp(stat_key, "slabs", 5) == 0) {
      slabs_stats(engine, add_stat, cookie);
   } else if (strncmp(stat_key, "items", 5) == 0) {
      item_stats(engine, add_stat, cookie);
   } else if (strncmp(stat_key, "sizes", 5) == 0) {
      item_stats_sizes(engine, add_stat, cookie);
   } else if (strncmp(stat_key, "vbucket", 7) == 0) {
      stats_vbucket(engine, add_stat, cookie);
   } else if (strncmp(stat_key, "scrub", 5) == 0) {
      char val[128];
      int len;

      pthread_mutex_lock(&engine->scrubber.lock);
      if (engine->scrubber.running) {
         add_stat("scrubber:status", 15, "running", 7, cookie);
      } else {
         add_stat("scrubber:status", 15, "stopped", 7, cookie);
      }

      if (engine->scrubber.started != 0) {
         if (engine->scrubber.stopped != 0) {
            time_t diff = engine->scrubber.started - engine->scrubber.stopped;
            len = sprintf(val, "%"PRIu64, (uint64_t)diff);
            add_stat("scrubber:last_run", 17, val, len, cookie);
         }

         len = sprintf(val, "%"PRIu64, engine->scrubber.visited);
         add_stat("scrubber:visited", 16, val, len, cookie);
         len = sprintf(val, "%"PRIu64, engine->scrubber.cleaned);
         add_stat("scrubber:cleaned", 16, val, len, cookie);
      }
      pthread_mutex_unlock(&engine->scrubber.lock);
   } else {
      ret = ENGINE_KEY_ENOENT;
   }

   return ret;
}

static ENGINE_ERROR_CODE default_store(ENGINE_HANDLE* handle,
                                       const void *cookie,
                                       item* item,
                                       uint64_t *cas,
                                       ENGINE_STORE_OPERATION operation,
                                       uint16_t vbucket) {
    struct default_engine *engine = get_handle(handle);
    VBUCKET_GUARD(engine, vbucket);
    return store_item(engine, get_real_item(item), cas, operation,
                      cookie);
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
                                            uint64_t *result,
                                            uint16_t vbucket) {
   struct default_engine *engine = get_handle(handle);
   VBUCKET_GUARD(engine, vbucket);

   return arithmetic(engine, cookie, key, nkey, increment,
                     create, delta, initial, engine->server.core->realtime(exptime), cas,
                     result);
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

   se->config.vb0 = true;

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
         { .key = "ignore_vbucket",
           .datatype = DT_BOOL,
           .value.dt_bool = &se->config.ignore_vbucket },
         { .key = "vb0",
           .datatype = DT_BOOL,
           .value.dt_bool = &se->config.vb0 },
         { .key = "config_file",
           .datatype = DT_CONFIGFILE },
         { .key = NULL}
      };

      ret = se->server.core->parse_config(cfg_str, items, stderr);
   }

   if (se->config.vb0) {
       set_vbucket_state(se, 0, vbucket_state_active);
   }

   return ENGINE_SUCCESS;
}

static bool set_vbucket(struct default_engine *e,
                        const void* cookie,
                        protocol_binary_request_set_vbucket *req,
                        ADD_RESPONSE response) {
    size_t bodylen = ntohl(req->message.header.request.bodylen)
        - ntohs(req->message.header.request.keylen);
    if (bodylen != sizeof(vbucket_state_t)) {
        const char *msg = "Incorrect packet format";
        return response(NULL, 0, NULL, 0, msg, strlen(msg),
                        PROTOCOL_BINARY_RAW_BYTES,
                        PROTOCOL_BINARY_RESPONSE_EINVAL, 0, cookie);
    }
    vbucket_state_t state;
    memcpy(&state, &req->message.body.state, sizeof(state));
    state = ntohl(state);

    if (!is_valid_vbucket_state_t(state)) {
        const char *msg = "Invalid vbucket state";
        return response(NULL, 0, NULL, 0, msg, strlen(msg),
                        PROTOCOL_BINARY_RAW_BYTES,
                        PROTOCOL_BINARY_RESPONSE_EINVAL, 0, cookie);
    }

    set_vbucket_state(e, ntohs(req->message.header.request.vbucket), state);
    return response(NULL, 0, NULL, 0, &state, sizeof(state),
                    PROTOCOL_BINARY_RAW_BYTES,
                    PROTOCOL_BINARY_RESPONSE_SUCCESS, 0, cookie);
}

static bool get_vbucket(struct default_engine *e,
                        const void* cookie,
                        protocol_binary_request_get_vbucket *req,
                        ADD_RESPONSE response) {
    vbucket_state_t state;
    state = get_vbucket_state(e, ntohs(req->message.header.request.vbucket));
    state = ntohl(state);

    return response(NULL, 0, NULL, 0, &state, sizeof(state),
                    PROTOCOL_BINARY_RAW_BYTES,
                    PROTOCOL_BINARY_RESPONSE_SUCCESS, 0, cookie);
}

static bool rm_vbucket(struct default_engine *e,
                       const void *cookie,
                       protocol_binary_request_header *req,
                       ADD_RESPONSE response) {
    set_vbucket_state(e, ntohs(req->request.vbucket), vbucket_state_dead);
    return response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                    PROTOCOL_BINARY_RESPONSE_SUCCESS, 0, cookie);
}

static bool scrub_cmd(struct default_engine *e,
                      const void *cookie,
                      protocol_binary_request_header *request,
                      ADD_RESPONSE response) {

    protocol_binary_response_status res = PROTOCOL_BINARY_RESPONSE_SUCCESS;
    if (!item_start_scrub(e)) {
        res = PROTOCOL_BINARY_RESPONSE_EBUSY;
    }

    return response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                    res, 0, cookie);
}

static bool touch(struct default_engine *e, const void *cookie,
                  protocol_binary_request_header *request,
                  ADD_RESPONSE response) {
    if (request->request.extlen != 4 || request->request.keylen == 0) {
        return response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                        PROTOCOL_BINARY_RESPONSE_EINVAL, 0, cookie);
    }

    protocol_binary_request_touch *t = (void*)request;
    void *key = t->bytes + sizeof(t->bytes);
    uint32_t exptime = ntohl(t->message.body.expiration);
    uint16_t nkey = ntohs(request->request.keylen);

    hash_item *item = touch_item(e, key, nkey,
                                 e->server.core->realtime(exptime));
    if (item == NULL) {
        if (request->request.opcode == PROTOCOL_BINARY_CMD_GATQ) {
            return true;
        } else {
            return response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                            PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0, cookie);
        }
    } else {
        bool ret;
        if (request->request.opcode == PROTOCOL_BINARY_CMD_TOUCH) {
            ret = response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                           PROTOCOL_BINARY_RESPONSE_SUCCESS, 0, cookie);
        } else {
            ret = response(NULL, 0, &item->flags, sizeof(item->flags),
                           item_get_data(item), item->nbytes,
                           PROTOCOL_BINARY_RAW_BYTES,
                           PROTOCOL_BINARY_RESPONSE_SUCCESS,
                           item_get_cas(item), cookie);
        }
        item_release(e, item);
        return ret;
    }
}

static ENGINE_ERROR_CODE default_unknown_command(ENGINE_HANDLE* handle,
                                                 const void* cookie,
                                                 protocol_binary_request_header *request,
                                                 ADD_RESPONSE response)
{
    struct default_engine* e = get_handle(handle);
    bool sent;

    switch(request->request.opcode) {
    case PROTOCOL_BINARY_CMD_SCRUB:
        sent = scrub_cmd(e, cookie, request, response);
        break;
    case PROTOCOL_BINARY_CMD_DEL_VBUCKET:
        sent = rm_vbucket(e, cookie, request, response);
        break;
    case PROTOCOL_BINARY_CMD_SET_VBUCKET:
        sent = set_vbucket(e, cookie, (void*)request, response);
        break;
    case PROTOCOL_BINARY_CMD_GET_VBUCKET:
        sent = get_vbucket(e, cookie, (void*)request, response);
        break;
    case PROTOCOL_BINARY_CMD_TOUCH:
    case PROTOCOL_BINARY_CMD_GAT:
    case PROTOCOL_BINARY_CMD_GATQ:
        sent = touch(e, cookie, request, response);
        break;
    default:
        sent = response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                        PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, 0, cookie);
        break;
    }

    if (sent) {
        return ENGINE_SUCCESS;
    } else {
        return ENGINE_FAILED;
    }
}


uint64_t item_get_cas(const hash_item* item)
{
    if (item->iflag & ITEM_WITH_CAS) {
        return *(uint64_t*)(item + 1);
    }
    return 0;
}

void item_set_cas(ENGINE_HANDLE *handle, const void *cookie,
                  item* item, uint64_t val)
{
    hash_item* it = get_real_item(item);
    if (it->iflag & ITEM_WITH_CAS) {
        *(uint64_t*)(it + 1) = val;
    }
}

const void* item_get_key(const hash_item* item)
{
    char *ret = (void*)(item + 1);
    if (item->iflag & ITEM_WITH_CAS) {
        ret += sizeof(uint64_t);
    }

    return ret;
}

char* item_get_data(const hash_item* item)
{
    return ((char*)item_get_key(item)) + item->nkey;
}

uint8_t item_get_clsid(const hash_item* item)
{
    return 0;
}

static bool get_item_info(ENGINE_HANDLE *handle, const void *cookie,
                          const item* item, item_info *item_info)
{
    hash_item* it = (hash_item*)item;
    if (item_info->nvalue < 1) {
        return false;
    }
    item_info->cas = item_get_cas(it);
    item_info->exptime = it->exptime;
    item_info->nbytes = it->nbytes;
    item_info->flags = it->flags;
    item_info->clsid = it->slabs_clsid;
    item_info->nkey = it->nkey;
    item_info->nvalue = 1;
    item_info->key = item_get_key(it);
    item_info->value[0].iov_base = item_get_data(it);
    item_info->value[0].iov_len = it->nbytes;
    return true;
}

static ENGINE_ERROR_CODE default_tap_notify(ENGINE_HANDLE* handle,
                                            const void *cookie,
                                            void *engine_specific,
                                            uint16_t nengine,
                                            uint8_t ttl,
                                            uint16_t tap_flags,
                                            tap_event_t tap_event,
                                            uint32_t tap_seqno,
                                            const void *key,
                                            size_t nkey,
                                            uint32_t flags,
                                            uint32_t exptime,
                                            uint64_t cas,
                                            const void *data,
                                            size_t ndata,
                                            uint16_t vbucket) {
    struct default_engine* engine = get_handle(handle);
    vbucket_state_t state;
    item *it;
    ENGINE_ERROR_CODE ret = ENGINE_SUCCESS;

    switch (tap_event) {
    case TAP_ACK:
        /* We don't provide a tap stream, so we should never receive this */
        abort();

    case TAP_FLUSH:
        return default_flush(handle, cookie, 0);

    case TAP_DELETION:
        return default_item_delete(handle, cookie, key, nkey, cas, vbucket);

    case TAP_MUTATION:
        it = engine->server.cookie->get_engine_specific(cookie);
        if (it == NULL) {
            ret = default_item_allocate(handle, cookie, &it, key, nkey, ndata, flags, exptime);
            switch (ret) {
            case ENGINE_SUCCESS:
                break;
            case ENGINE_ENOMEM:
                return ENGINE_TMPFAIL;
            default:
                return ret;
            }
        }
        memcpy(item_get_data(it), data, ndata);
        engine->server.cookie->store_engine_specific(cookie, NULL);
        item_set_cas(handle, cookie, it, cas);
        ret = default_store(handle, cookie, it, &cas, OPERATION_SET, vbucket);
        if (ret == ENGINE_EWOULDBLOCK) {
            engine->server.cookie->store_engine_specific(cookie, it);
        } else {
            item_release(engine, it);
        }

        break;

    case TAP_VBUCKET_SET:
        if (nengine != sizeof(vbucket_state_t)) {
            // illegal size of the vbucket set package...
            return ENGINE_DISCONNECT;
        }

        memcpy(&state, engine_specific, nengine);
        state = (vbucket_state_t)ntohl(state);

        if (!is_valid_vbucket_state_t(state)) {
            return ENGINE_DISCONNECT;
        }

        set_vbucket_state(engine, vbucket, state);
        return ENGINE_SUCCESS;

    case TAP_OPAQUE:
        // not supported, ignore
    default:
        engine->server.log->get_logger()->log(EXTENSION_LOG_DEBUG, cookie,
                    "Ignoring unknown tap event: %x", tap_event);
    }

    return ret;
}

static TAP_ITERATOR default_get_tap_iterator(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             const void* client,
                                             size_t nclient,
                                             uint32_t flags,
                                             const void* userdata,
                                             size_t nuserdata) {
    struct default_engine* engine = get_handle(handle);

    if ((flags & TAP_CONNECT_FLAG_TAKEOVER_VBUCKETS)) { /* Not supported */
        return NULL;
    }

    pthread_mutex_lock(&engine->tap_connections.lock);
    int ii;
    for (ii = 0; ii < engine->tap_connections.size; ++ii) {
        if (engine->tap_connections.clients[ii] == NULL) {
            engine->tap_connections.clients[ii] = cookie;
            break;
        }
    }
    pthread_mutex_unlock(&engine->tap_connections.lock);
    if (ii == engine->tap_connections.size) {
        // @todo allow more connections :)
        return NULL;
    }

    if (!initialize_item_tap_walker(engine, cookie)) {
        /* Failed to create */
        pthread_mutex_lock(&engine->tap_connections.lock);
        engine->tap_connections.clients[ii] = NULL;
        pthread_mutex_unlock(&engine->tap_connections.lock);
        return NULL;
    }

    return item_tap_walker;
 }

static void default_handle_disconnect(const void *cookie,
                                      ENGINE_EVENT_TYPE type,
                                      const void *event_data,
                                      const void *cb_data) {
    struct default_engine *engine = (struct default_engine*)cb_data;
    pthread_mutex_lock(&engine->tap_connections.lock);
    int ii;
    for (ii = 0; ii < engine->tap_connections.size; ++ii) {
        if (engine->tap_connections.clients[ii] == cookie) {
            free(engine->server.cookie->get_engine_specific(cookie));
            break;
        }
    }
    pthread_mutex_unlock(&engine->tap_connections.lock);
}
