/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <windows.h>
#include <dlfcn.h>
#include <stdbool.h>

/*
 * Keep track if the user tried to call dlopen(NULL, xx) to be able to give a sane
 * error message
 */
static bool self = false;

void* dlopen(const char* path, int mode) {
    if (path == NULL) {
        // We don't support opening ourself
        self = true;
        return NULL;
    }

    void* handle = LoadLibrary(path);
    if (handle == NULL) {
        char *buf = malloc(strlen(path) + 20);
        sprintf(buf, "%s.dll", path);
        handle = LoadLibrary(buf);
        free(buf);
    }

    return handle;
}

void* dlsym(void* handle, const char* symbol) {
    return GetProcAddress(handle, symbol);
}

int dlclose(void* handle) {
    // dlclose returns zero on success.
    // FreeLibrary returns nonzero on success.
    return FreeLibrary(handle) != 0;
}

static char dlerror_buf[200];

const char *dlerror(void) {
    if (self) {
        return "not supported";
    }

    DWORD err = GetLastError();
    LPVOID error_msg;
    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                      FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      NULL, err, 0, (LPTSTR)&error_msg, 0, NULL) != 0) {
        strncpy(dlerror_buf, error_msg, sizeof(dlerror_buf));
        dlerror_buf[sizeof(dlerror_buf) - 1] = '\0';
        LocalFree(error_msg);
    } else {
        return "Failed to get error message";
    }

    return dlerror_buf;
}
