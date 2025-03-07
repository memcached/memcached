// TODO: fix the include header nightmare.
#include "memcached.h"
#include "proto_parser.h"

#include <limits.h>
#include <string.h>

#define PARSER_MAXLEN USHRT_MAX-1

/*
 * BEGIN TOKENIZER CODE
 */

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

/*
 * END TOKENIZER CODE
 */

/*
 * BEGIN PROTOCOL HANDLER CODE
 */

// FIXME: REDUNDANT
static void pout_string(mc_resp *resp, const char *str) {
    size_t len;
    bool skip = resp->skip;
    assert(resp != NULL);

    // if response was original filled with something, but we're now writing
    // out an error or similar, have to reset the object first.
    resp_reset(resp);

    // We blank the response "just in case", but if we're not intending on
    // sending it lets not rewrite it.
    if (skip) {
        resp->skip = true;
        return;
    }

    // Fill response object with static string.

    len = strlen(str);
    if ((len + 2) > WRITE_BUFFER_SIZE) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    memcpy(resp->wbuf, str, len);
    memcpy(resp->wbuf + len, "\r\n", 2);
    resp_add_iov(resp, resp->wbuf, len + 2);

    return;
}

// FIXME: REDUNDANT
// For meta commands error strings override the quiet flag.
static void pout_errstring(mc_resp *resp, const char *str) {
    resp->skip = false;
    pout_string(resp, str);
}

// FIXME: use mcmc func!
static int _process_token_len(mcp_parser_t *pr, size_t token) {
  const char *s = pr->request + pr->tok.tokens[token];
  const char *e = pr->request + pr->tok.tokens[token+1];
  // start of next token is after any space delimiters, so back those out.
  while (*(e-1) == ' ') {
      e--;
  }
  return e - s;
}

// FIXME: rename from _meta to pr_meta
int _meta_flag_preparse(mcp_parser_t *pr, const size_t start,
        struct _meta_flags *of, char **errstr) {
    unsigned int i;
    //size_t ret;
    int32_t tmp_int;
    uint8_t seen[127] = {0};
    // Start just past the key token. Look at first character of each token.
    for (i = start; i < pr->tok.ntokens; i++) {
        uint8_t o = (uint8_t)pr->request[pr->tok.tokens[i]];
        // zero out repeat flags so we don't over-parse for return data.
        if (o >= 127 || seen[o] != 0) {
            *errstr = "CLIENT_ERROR duplicate flag";
            return -1;
        }
        seen[o] = 1;
        switch (o) {
            // base64 decode the key in-place, as the binary should always be
            // shorter and the conversion code buffers bytes.
            // TODO: we need temporary space for the binary key decode since
            // request should be const.
            /*case 'b':
                ret = base64_decode((unsigned char *)tokens[KEY_TOKEN].value, tokens[KEY_TOKEN].length,
                            (unsigned char *)tokens[KEY_TOKEN].value, tokens[KEY_TOKEN].length);
                if (ret == 0) {
                    // Failed to decode
                    *errstr = "CLIENT_ERROR error decoding key";
                    of->has_error = 1;
                }
                tokens[KEY_TOKEN].length = ret;
                of->key_binary = 1;
                break;*/
            /* Negative exptimes can underflow and end up immortal. realtime() will
               immediately expire values that are greater than REALTIME_MAXDELTA, but less
               than process_started, so lets aim for that. */
            case 'N':
                of->locked = 1;
                of->vivify = 1;
                if (!safe_strtol(&pr->request[pr->tok.tokens[i]+1], &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->autoviv_exptime = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                }
                break;
            case 'T':
                of->locked = 1;
                if (!safe_strtol(&pr->request[pr->tok.tokens[i]+1], &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->exptime = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                    of->new_ttl = true;
                }
                break;
            case 'R':
                of->locked = 1;
                if (!safe_strtol(&pr->request[pr->tok.tokens[i]+1], &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->recache_time = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                }
                break;
            case 'l':
                of->la = 1;
                of->locked = 1; // need locked to delay LRU bump
                break;
            case 'O':
            case 'P':
            case 'L':
                break;
            case 'k': // known but no special handling
            case 's':
            case 't':
            case 'c':
            case 'f':
                break;
            case 'v':
                of->value = 1;
                break;
            case 'h':
                of->locked = 1; // need locked to delay LRU bump
                break;
            case 'u':
                of->no_update = 1;
                break;
            case 'q':
                of->no_reply = 1;
                break;
            case 'x':
                of->remove_val = 1;
                break;
            // mset-related.
            case 'F':
                if (!safe_strtoflags(&pr->request[pr->tok.tokens[i]+1], &of->client_flags)) {
                    of->has_error = true;
                }
                break;
            case 'C': // mset, mdelete, marithmetic
                if (!safe_strtoull(&pr->request[pr->tok.tokens[i]+1], &of->req_cas_id)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = true;
                } else {
                    of->has_cas = true;
                }
                break;
            case 'E': // ms, md, ma
                if (!safe_strtoull(&pr->request[pr->tok.tokens[i]+1], &of->cas_id_in)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = true;
                } else {
                    of->has_cas_in = true;
                }
                break;
            case 'M': // mset and marithmetic mode switch
                // FIXME: this used to error if the token isn't a single byte.
                // It probably should still?
                of->mode = pr->request[pr->tok.tokens[i]+1];
                break;
            case 'J': // marithmetic initial value
                if (!safe_strtoull(&pr->request[pr->tok.tokens[i]+1], &of->initial)) {
                    *errstr = "CLIENT_ERROR invalid numeric initial value";
                    of->has_error = 1;
                }
                break;
            case 'D': // marithmetic delta value
                if (!safe_strtoull(&pr->request[pr->tok.tokens[i]+1], &of->delta)) {
                    *errstr = "CLIENT_ERROR invalid numeric delta value";
                    of->has_error = 1;
                }
                break;
            case 'I':
                of->set_stale = 1;
                break;
            default: // unknown flag, bail.
                *errstr = "CLIENT_ERROR invalid flag";
                return -1;
        }
    }

    return of->has_error ? -1 : 0;
}

void process_marithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = MCP_PARSER_KEY(pr);
    size_t nkey = pr->klen;
    int i;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(t != NULL);
    // no reservation (like del/set) since we post-process the status line.
    char *p = resp->wbuf;
    int tlen = 0;

    // If no argument supplied, incr or decr by one.
    of.delta = 1;
    of.initial = 0; // redundant, for clarity.
    bool incr = true; // default mode is to increment.
    bool locked = false;
    uint32_t hv = 0;
    item *it = NULL; // item returned by do_add_delta.

    //WANT_TOKENS_MIN(ntokens, 3);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (pr->tok.ntokens > MFLAG_MAX_OPT_LENGTH) {
        // TODO: ensure the command tokenizer gives us at least this many
        pout_errstring(resp, "CLIENT_ERROR options flags are too long");
        return;
    }

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 2, &of, &errstr) != 0) {
        pout_errstring(resp, "CLIENT_ERROR invalid or duplicate flag");
        return;
    }

    // "mode switch" to alternative commands
    switch (of.mode) {
        case 0: // no switch supplied.
            break;
        case 'I': // Incr (default)
        case '+':
            incr = true;
            break;
        case 'D': // Decr.
        case '-':
            incr = false;
            break;
        default:
            errstr = "CLIENT_ERROR invalid mode for ma M token";
            goto error;
            break;
    }

    // take hash value and manually lock item... hold lock during store phase
    // on miss and avoid recalculating the hash multiple times.
    hv = hash(key, nkey);
    item_lock(hv);
    locked = true;
    char tmpbuf[INCR_MAX_STORAGE_LEN];

    // return a referenced item if it exists, so we can modify it here, rather
    // than adding even more parameters to do_add_delta.
    bool item_created = false;
    uint64_t cas = 0;
    switch(do_add_delta(t, key, nkey, incr, of.delta, tmpbuf, &of.req_cas_id, hv, &it)) {
    case OK:
        if (of.no_reply)
            resp->skip = true;
        // *it was filled, set the status below.
        if (of.has_cas_in) {
            // override the CAS. slightly inefficient but fixing that can wait
            // until the next time do_add_delta is changed.
            ITEM_set_cas(it, of.cas_id_in);
        }
        cas = ITEM_get_cas(it);
        break;
    case NON_NUMERIC:
        errstr = "CLIENT_ERROR cannot increment or decrement non-numeric value";
        goto error;
        break;
    case EOM:
        errstr = "SERVER_ERROR out of memory";
        goto error;
        break;
    case DELTA_ITEM_NOT_FOUND:
        if (of.vivify) {
            itoa_u64(of.initial, tmpbuf);
            int vlen = strlen(tmpbuf);

            it = item_alloc(key, nkey, 0, 0, vlen+2);
            if (it != NULL) {
                memcpy(ITEM_data(it), tmpbuf, vlen);
                memcpy(ITEM_data(it) + vlen, "\r\n", 2);
                if (do_store_item(it, NREAD_ADD, t, hv, NULL, &cas,
                            of.has_cas_in ? of.cas_id_in : get_cas_id(), CAS_NO_STALE)) {
                    item_created = true;
                } else {
                    // Not sure how we can get here if we're holding the lock.
                    memcpy(resp->wbuf, "NS", 2);
                }
            } else {
                errstr = "SERVER_ERROR Out of memory allocating new item";
                goto error;
            }
        } else {
            pthread_mutex_lock(&t->stats.mutex);
            if (incr) {
                t->stats.incr_misses++;
            } else {
                t->stats.decr_misses++;
            }
            pthread_mutex_unlock(&t->stats.mutex);
            // won't have a valid it here.
            memcpy(p, "NF", 2);
            p += 2;
        }
        break;
    case DELTA_ITEM_CAS_MISMATCH:
        // also returns without a valid it.
        memcpy(p, "EX", 2);
        p += 2;
        break;
    }

    // final loop
    // allows building the response with information after vivifying from a
    // miss, or returning a new CAS value after add_delta().
    if (it) {
        size_t vlen = strlen(tmpbuf);
        if (of.value) {
            memcpy(p, "VA ", 3);
            p = itoa_u32(vlen, p+3);
        } else {
            memcpy(p, "HD", 2);
            p += 2;
        }

        for (i = pr->keytoken+1; i < pr->tok.ntokens; i++) {
            switch (pr->request[pr->tok.tokens[i]]) {
                case 'c':
                    META_CHAR(p, 'c');
                    p = itoa_u64(cas, p);
                    break;
                case 't':
                    META_CHAR(p, 't');
                    if (it->exptime == 0) {
                        *p = '-';
                        *(p+1) = '1';
                        p += 2;
                    } else {
                        p = itoa_u32(it->exptime - current_time, p);
                    }
                    break;
                case 'T':
                    it->exptime = of.exptime;
                    break;
                case 'N':
                    if (item_created) {
                        it->exptime = of.autoviv_exptime;
                    }
                    break;
                case 'O':
                    tlen = _process_token_len(pr, i);
                    if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, &pr->request[pr->tok.tokens[i]], tlen);
                    p += tlen;
                    break;
                case 'k':
                    META_KEY(p, key, nkey, of.key_binary);
                    break;
            }
        }

        if (of.value) {
            *p = '\r';
            *(p+1) = '\n';
            p += 2;
            memcpy(p, tmpbuf, vlen);
            p += vlen;
        }

        do_item_remove(it);
    } else {
        // No item to handle. still need to return opaque/key tokens
        for (i = pr->keytoken+1; i < pr->tok.ntokens; i++) {
            switch (pr->request[pr->tok.tokens[i]]) {
                case 'O':
                    tlen = _process_token_len(pr, i);
                    if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, &pr->request[pr->tok.tokens[i]], tlen);
                    p += tlen;
                    break;
                case 'k':
                    META_KEY(p, key, nkey, of.key_binary);
                    break;
            }
        }
    }

    item_unlock(hv);

    resp->wbytes = p - resp->wbuf;
    memcpy(resp->wbuf + resp->wbytes, "\r\n", 2);
    resp->wbytes += 2;
    resp_add_iov(resp, resp->wbuf, resp->wbytes);
    return;
error:
    if (it != NULL)
        do_item_remove(it);
    if (locked)
        item_unlock(hv);
    pout_errstring(resp, errstr);
}


