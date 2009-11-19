#ifndef MEMCACHED_ENGINE_H
#define MEMCACHED_ENGINE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "memcached/protocol_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ENGINE_INTERFACE_VERSION 1

   typedef enum {
      ENGINE_SUCCESS = 0x00, /* The command executed successfully */
      ENGINE_KEY_ENOENT = 0x01, /* The key does not exists */
      ENGINE_KEY_EEXISTS = 0x02, /* The key already exists */
      ENGINE_ENOMEM = 0x03, /* Could not allocate memory */
      ENGINE_NOT_STORED = 0x04, /* The item was not stored */
      ENGINE_EINVAL = 0x05, /* Invalid arguments */
      ENGINE_ENOTSUP = 0x06, /* The engine does not support this */
      ENGINE_EWOULDBLOCK = 0x07, /* This would cause the engine to block */
      ENGINE_E2BIG = 0x08, /* The data is too big for the engine */
      ENGINE_WANT_MORE = 0x09, /* The engine want more data if the frontend
                                * have more data available. */
      ENGINE_FAILED = 0xff /* Generic failue. */
   } ENGINE_ERROR_CODE;

   typedef enum {
      OPERATION_ADD = 1,
      OPERATION_SET,
      OPERATION_REPLACE,
      OPERATION_APPEND,
      OPERATION_PREPEND,
      OPERATION_CAS
   } ENGINE_STORE_OPERATION;


#define ITEM_WITH_CAS 1
#define ITEM_KEY_PTR  2
#define ITEM_DATA_PTR 4

   /** Time relative to server start. Smaller than time_t on 64-bit systems. */
   typedef uint32_t rel_time_t;


   rel_time_t realtime(const time_t exptime);
extern volatile rel_time_t current_time;


   typedef struct {
      rel_time_t exptime; /* When the item will expire (relative to process
                             startup) */
      uint32_t nbytes; /* The total size of the data (in bytes) */
      uint32_t flags; /* Flags associated with the item */
      uint16_t nkey; /* The total length of the key (in bytes) */
      uint16_t iflag; /* Intermal flags. lower 8 bit is reserved for the core
                         server, the upper 8 bits is reserved for engine
                         implementation.
                      */
   } item;

   uint64_t ITEM_get_cas(const item*);
   void ITEM_set_cas(item*, uint64_t);
   char* ITEM_key(const item*);
   char* ITEM_data(const item*);
   void ITEM_set_data_ptr(const item*, void*);
   static inline uint8_t ITEM_clsid(const item* item) {
      return 0;
   }

   void notify_io_complete(const void *cookie, ENGINE_ERROR_CODE status);

   /**
    * Callback for any function producing stats.
    *
    * @param key the stat's key
    * @param klen length of the key
    * @param val the stat's value in an ascii form (e.g. text form of a number)
    * @param vlen length of the value
    * @parm cookie magic callback cookie
    */
   typedef void (*ADD_STAT)(const char *key, const uint16_t klen,
                            const char *val, const uint32_t vlen,
                            const void *cookie);

   /**
    * Callback for adding a response backet
    * @param key The key to put in the response
    * @param keylen The length of the key
    * @param ext The data to put in the extended field in the response
    * @param extlen The number of bytes in the ext field
    * @param body The data body
    * @param bodylen The number of bytes in the body
    * @param datatype This is currently not used and should be set to 0
    * @param status The status code of the return packet (see in protocol_binary
    *               for the legal values)
    * @param cas The cas to put in the return packet
    * @param cookie The cookie provided by the frontend
    */
   typedef void (*ADD_RESPONSE)(const void *key, uint16_t keylen,
                                const void *ext, uint8_t extlen,
                                const void *body, uint32_t bodylen,
                                uint8_t datatype, uint16_t status,
                                uint64_t cas, const void *cookie);

   typedef struct engine_interface{
      uint64_t interface; /* The version number on the following structure */
   } ENGINE_HANDLE;

   /**
    * The signature for the "create_instance" function exported from the module.
    *
    * This function should fill out an engine inteface structure according to
    * the interface parameter (Note: it is possible to return a lower version
    * number).
    *
    * @param interface The highest interface level the server supports
    * @param Where to store the interface handle
    * @return See description of ENGINE_ERROR_CODE
    */
   typedef ENGINE_ERROR_CODE (*CREATE_INSTANCE)(uint64_t interface,
                                                ENGINE_HANDLE** handle);


   /**
    * Definition of the first version of the engine interface
    */
   typedef struct engine_interface_v1 {
      struct engine_interface interface;
      const char* (*get_info)(ENGINE_HANDLE* handle);
      ENGINE_ERROR_CODE (*initialize)(ENGINE_HANDLE* handle,
                                      const char* config_str);
      void (*destroy)(ENGINE_HANDLE* handle);

      /*
       * Item operations
       */
      ENGINE_ERROR_CODE (*allocate)(ENGINE_HANDLE* handle,
                                    const void* cookie,
                                    item **item,
                                    const void* key,
                                    const size_t nkey,
                                    const size_t nbytes,
                                    const int flags,
                                    const rel_time_t exptime);
      ENGINE_ERROR_CODE (*remove)(ENGINE_HANDLE* handle,
                                  const void* cookie,
                                  item* item);
      void (*release)(ENGINE_HANDLE* handle, item* item);
      ENGINE_ERROR_CODE (*get)(ENGINE_HANDLE* handle,
                               const void* cookie,
                               item** item,
                               const void* key,
                               const int nkey);
      ENGINE_ERROR_CODE (*store)(ENGINE_HANDLE* handle,
                                 const void *cookie,
                                 item* item,
                                 uint64_t *cas,
                                 ENGINE_STORE_OPERATION operation);
      ENGINE_ERROR_CODE (*arithmetic)(ENGINE_HANDLE* handle,
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
      ENGINE_ERROR_CODE (*flush)(ENGINE_HANDLE* handle,
                                 const void* cookie, time_t when);

      /*
       * Statistics
       */
      ENGINE_ERROR_CODE (*get_stats)(ENGINE_HANDLE* handle,
                                     const void* cookie,
                                     const char* stat_key,
                                     int nkey,
                                     ADD_STAT add_stat);
      void (*reset_stats)(ENGINE_HANDLE* handle);

      /*
       * Engine specific
       */
      ENGINE_ERROR_CODE (*unknow_command)(ENGINE_HANDLE* handle,
                                          const void* cookie,
                                          protocol_binary_request_header *request,
                                          ADD_RESPONSE response);
   } ENGINE_HANDLE_V1;

#ifdef __cplusplus
}
#endif

#endif
