/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "utilities/engine_loader.h"
#include <memcached/types.h>

static const char * const feature_descriptions[] = {
    "compare and swap",
    "persistent storage",
    "secondary engine",
    "access control",
    "multi tenancy",
    "LRU"
};

void *handle = NULL;

bool load_engine(const char *soname,
                 SERVER_HANDLE_V1 *(*get_server_api)(void),
                 EXTENSION_LOGGER_DESCRIPTOR *logger,
                 ENGINE_HANDLE **engine_handle)
{
    ENGINE_HANDLE *engine = NULL;
    /* Hack to remove the warning from C99 */
    union my_hack {
        CREATE_INSTANCE create;
        void* voidptr;
    } my_create = {.create = NULL };

    handle = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        const char *msg = dlerror();
        logger->log(EXTENSION_LOG_WARNING, NULL,
                "Failed to open library \"%s\": %s\n",
                soname ? soname : "self",
                msg ? msg : "unknown error");
        return false;
    }

    void *symbol = dlsym(handle, "create_instance");
    if (symbol == NULL) {
        logger->log(EXTENSION_LOG_WARNING, NULL,
                "Could not find symbol \"create_instance\" in %s: %s\n",
                soname ? soname : "self",
                dlerror());
        return false;
    }
    my_create.voidptr = symbol;

    /* request a instance with protocol version 1 */
    ENGINE_ERROR_CODE error = (*my_create.create)(1, get_server_api, &engine);

    if (error != ENGINE_SUCCESS || engine == NULL) {
        logger->log(EXTENSION_LOG_WARNING, NULL,
                "Failed to create instance. Error code: %d\n", error);
        dlclose(handle);
        return false;
    }
    *engine_handle = engine;
    return true;
}

bool init_engine(ENGINE_HANDLE * engine,
                 const char *config_str,
                 EXTENSION_LOGGER_DESCRIPTOR *logger)
{
    ENGINE_HANDLE_V1 *engine_v1 = NULL;

    if (handle == NULL) {
        logger->log(EXTENSION_LOG_WARNING, NULL,
                "Failed to initialize engine, engine must fist be loaded.");
        return false;
    }

    if (engine->interface == 1) {
        engine_v1 = (ENGINE_HANDLE_V1*)engine;

        // validate that the required engine interface is implemented:
        if (engine_v1->get_info == NULL || engine_v1->initialize == NULL ||
            engine_v1->destroy == NULL || engine_v1->allocate == NULL ||
            engine_v1->remove == NULL || engine_v1->release == NULL ||
            engine_v1->get == NULL || engine_v1->store == NULL ||
            engine_v1->flush == NULL ||
            engine_v1->get_stats == NULL || engine_v1->reset_stats == NULL ||
            engine_v1->item_set_cas == NULL ||
            engine_v1->get_item_info == NULL)
        {
            logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Failed to initialize engine; it does not implement the engine interface.");
            return false;
        }

        ENGINE_ERROR_CODE error = engine_v1->initialize(engine,config_str);
        if (error != ENGINE_SUCCESS) {
            engine_v1->destroy(engine, false);
            logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Failed to initialize instance. Error code: %d\n",
                    error);
            dlclose(handle);
            return false;
        }
    } else {
        logger->log(EXTENSION_LOG_WARNING, NULL,
                 "Unsupported interface level\n");
        dlclose(handle);
        return false;
    }
    return true;
}

void log_engine_details(ENGINE_HANDLE * engine,
                        EXTENSION_LOGGER_DESCRIPTOR *logger)
{
    ENGINE_HANDLE_V1 *engine_v1 = (ENGINE_HANDLE_V1*)engine;
    const engine_info *info;
    info = engine_v1->get_info(engine);
    if (info) {
        char message[4096];
        ssize_t nw = snprintf(message, sizeof(message), "Loaded engine: %s\n",
                                        info->description ?
                                        info->description : "Unknown");
        if (nw == -1) {
            return;
        }
        ssize_t offset = nw;
        bool comma = false;

        if (info->num_features > 0) {
            nw = snprintf(message + offset, sizeof(message) - offset,
                          "Supplying the following features: ");
            if (nw == -1) {
                return;
            }
            offset += nw;
            for (int ii = 0; ii < info->num_features; ++ii) {
                if (info->features[ii].description != NULL) {
                    nw = snprintf(message + offset, sizeof(message) - offset,
                                  "%s%s", comma ? ", " : "",
                                  info->features[ii].description);
                } else {
                    if (info->features[ii].feature <= LAST_REGISTERED_ENGINE_FEATURE) {
                        nw = snprintf(message + offset, sizeof(message) - offset,
                                      "%s%s", comma ? ", " : "",
                                      feature_descriptions[info->features[ii].feature]);
                    } else {
                        nw = snprintf(message + offset, sizeof(message) - offset,
                                      "%sUnknown feature: %d", comma ? ", " : "",
                                      info->features[ii].feature);
                    }
                }
                comma = true;
                if (nw == -1) {
                    return;
                }
                offset += nw;
            }
        }
        logger->log(EXTENSION_LOG_INFO, NULL, "%s\n", message);
    } else {
        logger->log(EXTENSION_LOG_INFO, NULL,
                                        "Loaded engine: Unknown\n");
    }
}
