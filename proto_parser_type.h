#ifndef PROTO_PARSER_TYPE_H
#define PROTO_PARSER_TYPE_H

#include "vendor/mcmc/mcmc.h"
#include <stdbool.h>

typedef struct mcp_parser_s mcp_parser_t;

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

#endif // PROTO_PARSER_TYPE_H
