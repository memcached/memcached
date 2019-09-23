/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "authfile.h"

// TODO: frontend needs a refactor so this can avoid global objects.

#define MAX_ENTRY_LEN 256
// Not supposed to be a huge database!
#define MAX_ENTRIES 8

typedef struct auth_entry {
    char *user;
    size_t ulen;
    char *pass;
    size_t plen;
} auth_t;

auth_t main_auth_entries[MAX_ENTRIES];
int entry_cnt = 0;
char *main_auth_data = NULL;

enum authfile_ret authfile_load(const char *file) {
    struct stat sb;
    char *auth_data = NULL;
    auth_t auth_entries[MAX_ENTRIES];

    if (stat(file, &sb) == -1) {
        return AUTHFILE_MISSING;
    }

    auth_data = calloc(1, sb.st_size);

    if (auth_data == NULL) {
        return AUTHFILE_OOM;
    }

    FILE *pwfile = fopen(file, "r");
    if (pwfile == NULL) {
        // not strictly necessary but to be safe.
        free(auth_data);
        return AUTHFILE_OPENFAIL;
    }

    char *auth_cur = auth_data;
    auth_t *entry_cur = auth_entries;
    int used = 0;

    while ((fgets(auth_cur, MAX_ENTRY_LEN, pwfile)) != NULL) {
        int x;
        int found = 0;

        for (x = 0; x < MAX_ENTRY_LEN; x++) {
            if (!found && auth_cur[x] == ':') {
                entry_cur->user = auth_cur;
                entry_cur->ulen = x;
                entry_cur->pass = &auth_cur[x+1];
                found = 1;
            } else if (found) {
                // Find end of password.
                if (auth_cur[x] == '\n' ||
                    auth_cur[x] == '\r' ||
                    auth_cur[x] == '\0') {
                    entry_cur->plen = x - (entry_cur->ulen + 1);
                    break;
                }
            }
        }

        // malformed line.
        if (!found) {
            (void)fclose(pwfile);
            free(auth_data);
            return AUTHFILE_MALFORMED;
        }

        // FIXME: no silent truncation.
        if (++used == MAX_ENTRIES) {
            break;
        }
        // EOF
        if (auth_cur[x] == '\0')
            break;

        auth_cur += x;
        entry_cur++;
    }

    // swap the main pointer out now, so if there's an error reloading we
    // don't break the existing authentication.
    if (main_auth_data != NULL) {
        free(main_auth_data);
    }

    entry_cnt = used;
    main_auth_data = auth_data;
    memcpy(main_auth_entries, auth_entries, sizeof(auth_entries));

    (void)fclose(pwfile);

    return AUTHFILE_OK;
}

// if only loading the file could be this short...
int authfile_check(const char *user, const char *pass) {
    size_t ulen = strlen(user);
    size_t plen = strlen(pass);

    for (int x = 0; x < entry_cnt; x++) {
        auth_t *e = &main_auth_entries[x];
        if (ulen == e->ulen && plen == e->plen &&
            memcmp(user, e->user, e->ulen) == 0 &&
            memcmp(pass, e->pass, e->plen) == 0) {
            return 1;
        }
    }

    return 0;
}
