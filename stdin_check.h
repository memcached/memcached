#ifndef STDIN_CHECK_H
#define STDIN_CHECK_H

#include "memcached/extension.h"

/* prototype required to avoid warnings treated as failures on some *NIX */
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api);
#endif
