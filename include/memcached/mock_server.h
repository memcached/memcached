#ifndef MEMCACHED_MOCK_SERVER_H
#define MEMCACHED_MOCK_SERVER_H

#include <memcached/engine.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct mock_connstruct {
    uint64_t magic;
    const char *uname;
    const char *config;
    void *engine_data;
    bool connected;
    struct mock_connstruct *next;
    int sfd;
    ENGINE_ERROR_CODE status;
    uint64_t evictions;
};

struct mock_callbacks {
    EVENT_CALLBACK cb;
    const void *cb_data;
    struct mock_callbacks *next;
};

struct mock_stats {
    uint64_t astat;
};

MEMCACHED_PUBLIC_API SERVER_HANDLE_V1 *get_mock_server_api(void);

MEMCACHED_PUBLIC_API void init_mock_server(ENGINE_HANDLE *server_engine);

MEMCACHED_PUBLIC_API
struct mock_connstruct *mk_mock_connection(const char *user,
                                           const char *config);

MEMCACHED_PUBLIC_API void disconnect_mock_connection(struct mock_connstruct *c);

MEMCACHED_PUBLIC_API void disconnect_all_mock_connections(struct mock_connstruct *c);

MEMCACHED_PUBLIC_API void destroy_mock_event_callbacks_rec(struct mock_callbacks *h);

MEMCACHED_PUBLIC_API void destroy_mock_event_callbacks(void);

#ifdef  __cplusplus
}
#endif

#endif  /* MEMCACHED_MOCK_SERVER_H */
