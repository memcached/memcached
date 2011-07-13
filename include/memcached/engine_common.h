/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef ENGINE_COMMON_H
#define ENGINE_COMMON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __WIN32__
#undef interface
#endif
    typedef struct engine_interface {
        uint64_t interface; /**< The version number on the engine structure */
    } ENGINE_HANDLE;

    /**
     * Callback for any function producing stats.
     *
     * @param key the stat's key
     * @param klen length of the key
     * @param val the stat's value in an ascii form (e.g. text form of a number)
     * @param vlen length of the value
     * @param cookie magic callback cookie
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
     * @return true if return message was successfully created, false if an
     *              error occured that prevented the message from being sent
     */
    typedef bool (*ADD_RESPONSE)(const void *key, uint16_t keylen,
                                 const void *ext, uint8_t extlen,
                                 const void *body, uint32_t bodylen,
                                 uint8_t datatype, uint16_t status,
                                 uint64_t cas, const void *cookie);


#ifdef __cplusplus
}
#endif

#endif /* ENGINE_COMMON_H */
