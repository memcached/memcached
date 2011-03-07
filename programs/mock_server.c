#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <memcached/engine.h>
#include <memcached/extension.h>
#include <memcached/extension_loggers.h>
#include <mock_server.h>

#define REALTIME_MAXDELTA 60*60*24*3
#define CONN_MAGIC 16369814453946373207ULL

struct mock_extensions {
    EXTENSION_DAEMON_DESCRIPTOR *daemons;
    EXTENSION_LOGGER_DESCRIPTOR *logger;
};

struct mock_callbacks *mock_event_handlers[MAX_ENGINE_EVENT_TYPE + 1];
time_t process_started;     /* when the mock server was started */
rel_time_t time_travel_offset;
rel_time_t current_time;
struct mock_connstruct *connstructs;
struct mock_extensions extensions;
EXTENSION_LOGGER_DESCRIPTOR *null_logger = NULL;
EXTENSION_LOGGER_DESCRIPTOR *stderr_logger = NULL;
ENGINE_HANDLE *engine = NULL;

/**
 * SERVER CORE API FUNCTIONS
 */

static void mock_get_auth_data(const void *cookie, auth_data_t *data) {
    struct mock_connstruct *c = (struct mock_connstruct *)cookie;
    if (c != NULL) {
        data->username = c->uname;
        data->config = c->config;
    }
}

static void mock_store_engine_specific(const void *cookie, void *engine_data) {
    if (cookie) {
        struct mock_connstruct *c = (struct mock_connstruct *)cookie;
        assert(c->magic == CONN_MAGIC);
        c->engine_data = engine_data;
    }
}

static void *mock_get_engine_specific(const void *cookie) {
    struct mock_connstruct *c = (struct mock_connstruct *)cookie;
    assert(c == NULL || c->magic == CONN_MAGIC);
    return c ? c->engine_data : NULL;
}

static int mock_get_socket_fd(const void *cookie) {
    struct mock_connstruct *c = (struct mock_connstruct *)cookie;
    return c->sfd;
}

static void mock_set_tap_nack_mode(const void *cookie, bool enable) {
   (void)cookie;
   (void)enable;
}

static void mock_cookie_reserve(const void *cookie) {
    (void)cookie;
}

static void mock_cookie_release(const void *cookie) {
    (void)cookie;
}

static const char *mock_get_server_version() {
    return "mock server";
}

static uint32_t mock_hash( const void *key, size_t length, const uint32_t initval) {
    //this is a very stupid hash indeed
    return 1;
}

/* time-sensitive callers can call it by hand with this, outside the
   normal ever-1-second timer */
static rel_time_t mock_get_current_time(void) {
    struct timeval timer;
    gettimeofday(&timer, NULL);
    current_time = (rel_time_t) (timer.tv_sec - process_started + time_travel_offset);
    return current_time;
}

static rel_time_t mock_realtime(const time_t exptime) {
    /* no. of seconds in 30 days - largest possible delta exptime */

    if (exptime == 0) return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA) {
        /* if item expiration is at/before the server started, give it an
           expiration time of 1 second after the server started.
           (because 0 means don't expire).  without this, we'd
           underflow and wrap around to some large value way in the
           future, effectively making items expiring in the past
           really expiring never */
        if (exptime <= process_started)
            return (rel_time_t)1;
        return (rel_time_t)(exptime - process_started);
    } else {
        return (rel_time_t)(exptime + mock_get_current_time());
    }
}

static void mock_notify_io_complete(const void *cookie, ENGINE_ERROR_CODE status) {
    struct mock_connstruct *c = (struct mock_connstruct *)cookie;
    pthread_mutex_lock(&c->mutex);
    c->status = status;
    pthread_cond_signal(&c->cond);
    pthread_mutex_unlock(&c->mutex);
}

static time_t mock_abstime(const rel_time_t exptime)
{
    return process_started + exptime;
}

void mock_time_travel(int by) {
    time_travel_offset += by;
}

static int mock_parse_config(const char *str, struct config_item items[], FILE *error) {
    return parse_config(str, items, error);
}

/**
 * SERVER STAT API FUNCTIONS
 */

static void *mock_new_independent_stats(void) {
    struct mockstats *mockstats = calloc(sizeof(mockstats),1);
    return mockstats;
}

static void mock_release_independent_stats(void *stats) {
    struct mockstats *mockstats = stats;
    free(mockstats);
}

static void mock_count_eviction(const void *cookie, const void *key, const int nkey) {
    struct mock_connstruct *c = (struct mock_connstruct *)cookie;
    c->evictions++;
}

/**
 * SERVER STAT API FUNCTIONS
 */

static bool mock_register_extension(extension_type_t type, void *extension)
{
    if (extension == NULL) {
        return false;
    }

    switch (type) {
    case EXTENSION_DAEMON:
        for (EXTENSION_DAEMON_DESCRIPTOR *ptr =  extensions.daemons;
             ptr != NULL;
             ptr = ptr->next) {
            if (ptr == extension) {
                return false;
            }
        }
        ((EXTENSION_DAEMON_DESCRIPTOR *)(extension))->next = extensions.daemons;
        extensions.daemons = extension;
        return true;
    case EXTENSION_LOGGER:
        extensions.logger = extension;
        return true;
    default:
        return false;
    }
}

static void mock_unregister_extension(extension_type_t type, void *extension)
{
    switch (type) {
    case EXTENSION_DAEMON:
        {
            EXTENSION_DAEMON_DESCRIPTOR *prev = NULL;
            EXTENSION_DAEMON_DESCRIPTOR *ptr = extensions.daemons;

            while (ptr != NULL && ptr != extension) {
                prev = ptr;
                ptr = ptr->next;
            }

            if (ptr != NULL && prev != NULL) {
                prev->next = ptr->next;
            }

            if (extensions.daemons == ptr) {
                extensions.daemons = ptr->next;
            }
        }
        break;
    case EXTENSION_LOGGER:
        if (extensions.logger == extension) {
            if (stderr_logger == extension) {
                extensions.logger = null_logger;
            } else {
                extensions.logger = stderr_logger;
            }
        }
        break;

    default:
        ;
    }

}

static void* mock_get_extension(extension_type_t type)
{
    switch (type) {
    case EXTENSION_DAEMON:
        return extensions.daemons;

    case EXTENSION_LOGGER:
        return extensions.logger;

    default:
        return NULL;
    }
}

/**
 * SERVER CALLBACK API FUNCTIONS
 */

static void mock_register_callback(ENGINE_HANDLE *eh,
                                   ENGINE_EVENT_TYPE type,
                                   EVENT_CALLBACK cb,
                                   const void *cb_data) {
    struct mock_callbacks *h =
        calloc(sizeof(struct mock_callbacks), 1);
    assert(h);
    h->cb = cb;
    h->cb_data = cb_data;
    h->next = mock_event_handlers[type];
    mock_event_handlers[type] = h;
}

static void mock_perform_callbacks(ENGINE_EVENT_TYPE type,
                                   const void *data,
                                   const void *c) {
    for (struct mock_callbacks *h = mock_event_handlers[type];
         h; h = h->next) {
        h->cb(c, type, data, h->cb_data);
    }
}

SERVER_HANDLE_V1 *get_mock_server_api(void)
{
    static SERVER_CORE_API core_api = {
        .server_version = mock_get_server_version,
        .hash = mock_hash,
        .realtime = mock_realtime,
        .get_current_time = mock_get_current_time,
        .abstime = mock_abstime,
        .parse_config = mock_parse_config
    };

    static SERVER_COOKIE_API server_cookie_api = {
        .get_auth_data = mock_get_auth_data,
        .store_engine_specific = mock_store_engine_specific,
        .get_engine_specific = mock_get_engine_specific,
        .get_socket_fd = mock_get_socket_fd,
        .set_tap_nack_mode = mock_set_tap_nack_mode,
        .notify_io_complete = mock_notify_io_complete,
        .reserve = mock_cookie_reserve,
        .release = mock_cookie_release
    };

    static SERVER_STAT_API server_stat_api = {
        .new_stats = mock_new_independent_stats,
        .release_stats = mock_release_independent_stats,
        .evicting = mock_count_eviction
    };

    static SERVER_EXTENSION_API extension_api = {
        .register_extension = mock_register_extension,
        .unregister_extension = mock_unregister_extension,
        .get_extension = mock_get_extension
    };

    static SERVER_CALLBACK_API callback_api = {
        .register_callback = mock_register_callback,
        .perform_callbacks = mock_perform_callbacks
    };

    static SERVER_HANDLE_V1 rv = {
        .interface = 1,
        .core = &core_api,
        .stat = &server_stat_api,
        .extension = &extension_api,
        .callback = &callback_api,
        .cookie = &server_cookie_api
    };

    return &rv;
}

void init_mock_server(ENGINE_HANDLE *server_engine) {
    process_started = time(0);
    null_logger = get_null_logger();
    stderr_logger = get_stderr_logger();
    engine = server_engine;
    extensions.logger = null_logger;
}

struct mock_connstruct *mk_mock_connection(const char *user, const char *config) {
    struct mock_connstruct *rv = calloc(sizeof(struct mock_connstruct), 1);
    auth_data_t ad;
    assert(rv);
    rv->magic = CONN_MAGIC;
    rv->uname = user ? strdup(user) : NULL;
    rv->config = config ? strdup(config) : NULL;
    rv->connected = true;
    rv->next = connstructs;
    rv->evictions = 0;
    rv->sfd = 0; //TODO make this more realistic
    rv->status = ENGINE_SUCCESS;
    connstructs = rv;
    mock_perform_callbacks(ON_CONNECT, NULL, rv);
    if (rv->uname) {
        mock_get_auth_data(rv, &ad);
        mock_perform_callbacks(ON_AUTH, (const void*)&ad, rv);
    }

    assert(pthread_mutex_init(&rv->mutex, NULL) == 0);
    assert(pthread_cond_init(&rv->cond, NULL) == 0);

    return rv;
}

const void *create_mock_cookie(void) {
    struct mock_connstruct *rv = calloc(sizeof(struct mock_connstruct), 1);
    assert(rv);
    rv->magic = CONN_MAGIC;
    rv->connected = true;
    rv->status = ENGINE_SUCCESS;
    rv->handle_ewouldblock = true;
    assert(pthread_mutex_init(&rv->mutex, NULL) == 0);
    assert(pthread_cond_init(&rv->cond, NULL) == 0);

    return rv;
}

void destroy_mock_cookie(const void *cookie) {
    free((void*)cookie);
}

void mock_set_ewouldblock_handling(const void *cookie, bool enable) {
    struct mock_connstruct *v = (void*)cookie;
    v->handle_ewouldblock = enable;
}

void lock_mock_cookie(const void *cookie) {
   struct mock_connstruct *c = (void*)cookie;
   pthread_mutex_lock(&c->mutex);
}

void unlock_mock_cookie(const void *cookie) {
   struct mock_connstruct *c = (void*)cookie;
   pthread_mutex_unlock(&c->mutex);
}

void waitfor_mock_cookie(const void *cookie) {
   struct mock_connstruct *c = (void*)cookie;
   pthread_cond_wait(&c->cond, &c->mutex);
}

void disconnect_mock_connection(struct mock_connstruct *c) {
    c->connected = false;
    mock_perform_callbacks(ON_DISCONNECT, NULL, c);
}

void disconnect_all_mock_connections(struct mock_connstruct *c) {
    if (c) {
        disconnect_mock_connection(c);
        disconnect_all_mock_connections(c->next);
        free((void*)c->uname);
        free((void*)c->config);
        free(c);
    }
}

void destroy_mock_event_callbacks_rec(struct mock_callbacks *h) {
    if (h) {
        destroy_mock_event_callbacks_rec(h->next);
        free(h);
    }
}

void destroy_mock_event_callbacks(void) {
    int i = 0;
    for (i = 0; i < MAX_ENGINE_EVENT_TYPE; i++) {
        destroy_mock_event_callbacks_rec(mock_event_handlers[i]);
        mock_event_handlers[i] = NULL;
    }
}

