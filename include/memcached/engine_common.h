#ifndef ENGINE_COMMON_H
#define ENGINE_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct engine_interface {
        uint64_t interface; /**< The version number on the engine structure */
    } ENGINE_HANDLE;

#ifdef __cplusplus
}
#endif

#endif /* ENGINE_COMMON_H */
