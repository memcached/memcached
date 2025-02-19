#ifndef PROTO_PARSER_H
#define PROTO_PARSER_H

#include "config.h"
#include "proto_parser_type.h"
#include <stdbool.h>

// certain classes of ascii commands have similar parsing (ie;
// get/gets/gat/gats). Use types so we don't have to test a ton of them.
enum proxy_cmd_types {
    CMD_TYPE_GENERIC = 0,
    CMD_TYPE_GET, // get/gets/gat/gats
    CMD_TYPE_META, // m*'s.
};

// all possible commands.
#define CMD_FIELDS \
    X(CMD_MG) \
    X(CMD_MS) \
    X(CMD_MD) \
    X(CMD_MN) \
    X(CMD_MA) \
    X(CMD_ME) \
    X(CMD_GET) \
    X(CMD_GAT) \
    X(CMD_SET) \
    X(CMD_ADD) \
    X(CMD_CAS) \
    X(CMD_GETS) \
    X(CMD_GATS) \
    X(CMD_INCR) \
    X(CMD_DECR) \
    X(CMD_TOUCH) \
    X(CMD_APPEND) \
    X(CMD_DELETE) \
    X(CMD_REPLACE) \
    X(CMD_PREPEND) \
    X(CMD_END_STORAGE) \
    X(CMD_QUIT) \
    X(CMD_STATS) \
    X(CMD_SLABS) \
    X(CMD_WATCH) \
    X(CMD_LRU) \
    X(CMD_VERSION) \
    X(CMD_SHUTDOWN) \
    X(CMD_EXTSTORE) \
    X(CMD_FLUSH_ALL) \
    X(CMD_VERBOSITY) \
    X(CMD_LRU_CRAWLER) \
    X(CMD_REFRESH_CERTS) \
    X(CMD_CACHE_MEMLIMIT)

#define X(name) name,
enum proxy_defines {
    CMD_BASE = 0,
    CMD_FIELDS
    CMD_SIZE, // used to define array size for command hooks.
    CMD_ANY, // override _all_ commands
    CMD_ANY_STORAGE, // override commands specific to key storage.
    CMD_FINAL, // end cap for convenience.
};
#undef X

#define MCP_PARSER_KEY(pr) (&(pr)->request[(pr)->tok.tokens[(pr)->keytoken]])

#define META_SPACE(p) { \
    *p = ' '; \
    p++; \
}

#define META_CHAR(p, c) { \
    *p = ' '; \
    *(p+1) = c; \
    p += 2; \
}

// NOTE: being a little casual with the write buffer.
// the buffer needs to be sized that the longest possible meta response will
// fit. Here we allow the key to fill up to half the write buffer, in case
// something terrible has gone wrong.
#define META_KEY(p, key, nkey, bin) { \
    META_CHAR(p, 'k'); \
    if (!bin) { \
        memcpy(p, key, nkey); \
        p += nkey; \
    } else { \
        p += base64_encode((unsigned char *) key, nkey, (unsigned char *)p, WRITE_BUFFER_SIZE / 2); \
        *p = ' '; \
        *(p+1) = 'b'; \
        p += 2; \
    } \
}

#define MFLAG_MAX_OPT_LENGTH 20
#define MFLAG_MAX_OPAQUE_LENGTH 32

#define PROCESS_REQUEST_OK 0
#define PROCESS_REQUEST_BAD_FORMAT -1
#define PROCESS_REQUEST_CMD_NOT_FOUND -2
int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen);
int mc_prcmp(mcp_parser_t *pr, int token, const char *s);
bool mc_toktou32(mcp_parser_t *pr, int token, uint32_t *val);
bool mc_tokto32(mcp_parser_t *pr, int token, int32_t *val);
bool mc_toktod(mcp_parser_t *pr, int token, double *val);
bool mc_parse_exptime(mc_resp *resp, mcp_parser_t *pr, int token, rel_time_t *exptime);

typedef int (*parser_storage_get_cb)(LIBEVENT_THREAD *t, item *it, mc_resp *resp);
int process_get_cmd(LIBEVENT_THREAD *t, const char *key, const int nkey, mc_resp *resp, parser_storage_get_cb storage_cb, rel_time_t exptime, bool return_cas, bool should_touch);
item *process_update_cmd_start(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas);
void process_update_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas);
void process_arithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, const bool incr);
void process_delete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);
void process_touch_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);

void process_mget_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, parser_storage_get_cb storage_cb);
item *process_mset_cmd_start(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp,
        uint64_t *cas_in, bool *has_cas_in, short *comm);
void process_mset_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);
void process_mdelete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);
void process_marithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);

#endif
