#include "config.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include "vendor/mcmc/mcmc.h"
#include "proto_parser.h"

#define PARSER_MAXLEN USHRT_MAX-1

// TODO: func to just get length of token
static int _process_request_key(mcp_parser_t *pr) {
    // TODO: can klen be int?
    int len = 0;
    mcmc_token_get(pr->request, &pr->tok, pr->keytoken, &len);
    pr->klen = len;

    return 0;
}

// All meta commands are of form: "cm key f l a g S100"
static int _process_request_meta(mcp_parser_t *pr) {
    // TODO: can check result
    mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 2);
    if (pr->tok.ntokens < 2) {
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    return 0;
}

// ms <key> <datalen> <flags>*\r\n
static int _process_request_mset(mcp_parser_t *pr) {
    mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 3);
    if (pr->tok.ntokens < 3) {
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    int vlen = 0;
    if (mcmc_token_get_32(pr->request, &pr->tok, 2, &vlen) != MCMC_OK) {
        return -1;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
       return -1;
    }
    vlen += 2;

    pr->vlen = vlen;

    return 0;
}

// gat[s] <exptime> <key>*\r\n
static int _process_request_gat(mcp_parser_t *pr) {
    mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
    if (pr->tok.ntokens < 3) {
        return -1;
    }

    pr->keytoken = 2;
    _process_request_key(pr);
    return 0;
}

#define NOREPLYSTR "noreply"
#define NOREPLYLEN sizeof(NOREPLYSTR)-1
// given a tokenized parser for a normal ASCII command, checks for noreply
// mode.
static int _process_request_noreply(mcp_parser_t *pr) {
    int len = 0;
    const char *tok = mcmc_token_get(pr->request, &pr->tok, pr->tok.ntokens-1, &len);
    if (len == NOREPLYLEN && strncmp(NOREPLYSTR, tok, NOREPLYLEN) == 0) {
        pr->noreply = true;
    }
    return 0;
}

// we need t find the bytes supplied immediately so we can read the request
// from the client properly.
// set <key> <flags> <exptime> <bytes> [noreply]\r\n
static int _process_request_storage(mcp_parser_t *pr) {
    mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
    if (pr->tok.ntokens < 5) {
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    int vlen = 0;
    if (mcmc_token_get_32(pr->request, &pr->tok, 4, &vlen) != MCMC_OK) {
        return -1;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
       return -1;
    }
    vlen += 2;

    pr->vlen = vlen;

    return _process_request_noreply(pr);
}

// common request with key: <cmd> <key> <args>
static int _process_request_simple(mcp_parser_t *pr, const int min) {
    mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
    if (pr->tok.ntokens < min) {
        return -1;
    }
    pr->keytoken = 1; // second token is usually the key... stupid GAT.

    _process_request_key(pr);
    return _process_request_noreply(pr);
}

// TODO: return code ENUM with error types.
int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen) {
    // we want to "parse in place" as much as possible, which allows us to
    // forward an unmodified request without having to rebuild it.

    const char *cm = command;
    size_t cl = 0;
    // min command length is 2, plus the "\r\n"
    if (cmdlen < 4) {
        return -1;
    }

    // Commands can end with bare '\n's. Depressingly I intended to be strict
    // with a \r\n requirement but never did this and need backcompat.
    // In this case we _know_ \n is at cmdlen because we can't enter this
    // function otherwise.
    size_t endlen = 0;
    if (cm[cmdlen-2] == '\r') {
        endlen = cmdlen - 2;
    } else {
        endlen = cmdlen - 1;
    }

    const char *s = memchr(command, ' ', endlen);
    if (s != NULL) {
        cl = s - command;
    } else {
        cl = endlen;
    }
    pr->keytoken = 0;
    pr->request = command;
    pr->reqlen = cmdlen;

    int cmd = -1;
    int type = CMD_TYPE_GENERIC;
    int ret = 0;

    switch (cl) {
        case 0:
        case 1:
            // falls through with cmd as -1. should error.
            break;
        case 2:
            if (cm[0] == 'm') {
                type = CMD_TYPE_META;
                switch (cm[1]) {
                    case 'g':
                        cmd = CMD_MG;
                        ret = _process_request_meta(pr);
                        break;
                    case 's':
                        cmd = CMD_MS;
                        ret = _process_request_mset(pr);
                        break;
                    case 'd':
                        cmd = CMD_MD;
                        ret = _process_request_meta(pr);
                        break;
                    case 'n':
                        // TODO: do we route/handle NOP's at all?
                        // they should simply reflect to the client.
                        cmd = CMD_MN;
                        break;
                    case 'a':
                        cmd = CMD_MA;
                        ret = _process_request_meta(pr);
                        break;
                    case 'e':
                        cmd = CMD_ME;
                        // TODO: not much special processing here; binary keys
                        ret = _process_request_meta(pr);
                        break;
                }
            }
            break;
        case 3:
            if (cm[0] == 'g') {
                if (cm[1] == 'e' && cm[2] == 't') {
                    cmd = CMD_GET;
                    type = CMD_TYPE_GET;
                    ret = _process_request_simple(pr, 2);
                }
                if (cm[1] == 'a' && cm[2] == 't') {
                    type = CMD_TYPE_GET;
                    cmd = CMD_GAT;
                    ret = _process_request_gat(pr);
                }
            } else if (cm[0] == 's' && cm[1] == 'e' && cm[2] == 't') {
                cmd = CMD_SET;
                ret = _process_request_storage(pr);
            } else if (cm[0] == 'a' && cm[1] == 'd' && cm[2] == 'd') {
                cmd = CMD_ADD;
                ret = _process_request_storage(pr);
            } else if (cm[0] == 'c' && cm[1] == 'a' && cm[2] == 's') {
                cmd = CMD_CAS;
                ret = _process_request_storage(pr);
            }
            break;
        case 4:
            if (strncmp(cm, "gets", 4) == 0) {
                cmd = CMD_GETS;
                type = CMD_TYPE_GET;
                ret = _process_request_simple(pr, 2);
            } else if (strncmp(cm, "incr", 4) == 0) {
                cmd = CMD_INCR;
                ret = _process_request_simple(pr, 3);
            } else if (strncmp(cm, "decr", 4) == 0) {
                cmd = CMD_DECR;
                ret = _process_request_simple(pr, 3);
            } else if (strncmp(cm, "gats", 4) == 0) {
                cmd = CMD_GATS;
                type = CMD_TYPE_GET;
                ret = _process_request_gat(pr);
            } else if (strncmp(cm, "quit", 4) == 0) {
                cmd = CMD_QUIT;
            }
            break;
        case 5:
            if (strncmp(cm, "touch", 5) == 0) {
                cmd = CMD_TOUCH;
                ret = _process_request_simple(pr, 3);
            } else if (strncmp(cm, "stats", 5) == 0) {
                cmd = CMD_STATS;
                // Don't process a key; fetch via arguments.
                mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
            } else if (strncmp(cm, "watch", 5) == 0) {
                cmd = CMD_WATCH;
                mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
            }
            break;
        case 6:
            if (strncmp(cm, "delete", 6) == 0) {
                cmd = CMD_DELETE;
                ret = _process_request_simple(pr, 2);
            } else if (strncmp(cm, "append", 6) == 0) {
                cmd = CMD_APPEND;
                ret = _process_request_storage(pr);
            }
            break;
        case 7:
            if (strncmp(cm, "replace", 7) == 0) {
                cmd = CMD_REPLACE;
                ret = _process_request_storage(pr);
            } else if (strncmp(cm, "prepend", 7) == 0) {
                cmd = CMD_PREPEND;
                ret = _process_request_storage(pr);
            } else if (strncmp(cm, "version", 7) == 0) {
                cmd = CMD_VERSION;
                mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
            }
            break;
    }

    // TODO: log more specific error code.
    if (cmd == -1 || ret != 0) {
        return -1;
    }

    pr->command = cmd;
    pr->cmd_type = type;

    return 0;
}


