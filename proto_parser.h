#ifndef PROTO_PARSER_H
#define PROTO_PARSER_H

#include "config.h"
#include "vendor/mcmc/mcmc.h"
#include <stdbool.h>

typedef struct mcp_parser_s mcp_parser_t;

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

// Note that we must use offsets into request for tokens,
// as *request can change between parsing and later accessors.
struct mcp_parser_s {
    const char *request;
    void *vbuf; // temporary buffer for holding value lengths.
    mcmc_tokenizer_t tok; // tokenizer structure
    uint8_t command;
    uint8_t cmd_type; // command class.
    uint8_t keytoken; // because GAT. sigh. also cmds without a key.
    uint32_t reqlen; // full length of request buffer.
    int vlen;
    uint32_t klen; // length of key.
    bool noreply; // if quiet/noreply mode is set.
};

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

struct _meta_flags {
    unsigned int has_error :1; // flipped if we found an error during parsing.
    unsigned int no_update :1;
    unsigned int locked :1;
    unsigned int vivify :1;
    unsigned int la :1;
    unsigned int hit :1;
    unsigned int value :1;
    unsigned int set_stale :1;
    unsigned int no_reply :1;
    unsigned int has_cas :1;
    unsigned int has_cas_in :1;
    unsigned int new_ttl :1;
    unsigned int key_binary:1;
    unsigned int remove_val:1;
    char mode; // single character mode switch, common to ms/ma
    uint8_t key_len; // decoded binary key length
    rel_time_t exptime;
    rel_time_t autoviv_exptime;
    rel_time_t recache_time;
    client_flags_t client_flags;
    const char *key;
    uint64_t req_cas_id;
    uint64_t cas_id_in; // client supplied next-CAS
    uint64_t delta; // ma
    uint64_t initial; // ma
};

int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen);

typedef int (*parser_storage_get_cb)(LIBEVENT_THREAD *t, item *it, mc_resp *resp);
void process_get_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, parser_storage_get_cb storage_cb, bool return_cas, bool should_touch);
void process_update_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas);
void process_arithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, const bool incr);
void process_delete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);
void process_touch_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);

int _meta_flag_preparse(mcp_parser_t *pr, const size_t start,
        struct _meta_flags *of, char *binkey, char **errstr);
void process_mget_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, parser_storage_get_cb storage_cb);
void process_mset_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);
void process_mdelete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);
void process_marithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp);

#endif
