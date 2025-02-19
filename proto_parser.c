// TODO: fix the include header nightmare.
#include "memcached.h"
#include "proto_parser.h"
#include "storage.h"
#include "base64.h"

#include <limits.h>
#include <string.h>

#define PARSER_MAXLEN USHRT_MAX-1

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

static int _meta_flag_preparse(mcp_parser_t *pr, const size_t start,
        struct _meta_flags *of, char *binkey, char **errstr);

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

static int _process_request_unknown(mcp_parser_t *pr) {
    mcmc_tokenize(pr->request, pr->reqlen, &pr->tok, 255);
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
    assert(cm[cmdlen-1] == '\n');
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
    if (cmd == -1) {
        _process_request_unknown(pr);
        return PROCESS_REQUEST_CMD_NOT_FOUND;
    }

    pr->command = cmd;
    pr->cmd_type = type;

    return ret;
}

/*
 * END TOKENIZER CODE
 */

/*
 * PARSER UTIL CODE
 */

// TODO:
// - the safe_strto calls in here are still "string-y" - they're going to
// parse until a space or newline. This is perfectly safe for any time we're
// in this code; since we can't get here without a \n or a space (ie;
// non-digit)
// - I'm not converting these to tokto*'s right now, because what they're
// pulling the flag while in a loop. So we need yet another interface (or
// refactor of existing interface). This code is safe, just not consistent.

int mc_prcmp(mcp_parser_t *pr, int token, const char *s) {
    int len = 0;
    const char *t = mcmc_token_get(pr->request, &pr->tok, token, &len);
    return strncmp(t, s, len);
}

bool mc_toktou32(mcp_parser_t *pr, int token, uint32_t *val) {
    if (mcmc_token_get_u32(pr->request, &pr->tok, token, val) != MCMC_OK) {
        return false;
    }
    return true;
}

bool mc_tokto32(mcp_parser_t *pr, int token, int32_t *val) {
    if (mcmc_token_get_32(pr->request, &pr->tok, token, val) != MCMC_OK) {
        return false;
    }
    return true;
}

bool mc_toktod(mcp_parser_t *pr, int token, double *val) {
    char buffer[32];
    int len = 0;
    const char *t = mcmc_token_get(pr->request, &pr->tok, token, &len);
    if (len > sizeof(buffer)-1) {
        return false;
    }
    memcpy(buffer, t, len);
    buffer[len] = '\0';

    return safe_strtod(buffer, val);
}

/*
 * BEGIN PROTOCOL HANDLER CODE
 */

// FIXME: REDUNDANT
static void pout_string(mc_resp *resp, const char *str) {
    size_t len;
    bool skip = resp->skip;
    assert(resp != NULL);

    // if response was originally filled with something, but we're now writing
    // out an error or similar, have to reset the object first.
    resp_reset(resp);

    // We blank the response "just in case", but if we're not intending on
    // sending it lets not rewrite it.
    if (skip || resp->noreply) {
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

bool mc_parse_exptime(mc_resp *resp, mcp_parser_t *pr, int token, rel_time_t *exptime) {
    int32_t exptime_int = 0;
    if (!safe_strtol(&pr->request[pr->tok.tokens[1]], &exptime_int)) {
        pout_string(resp, "CLIENT_ERROR invalid exptime argument");
        return false;
    }
    *exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));
    return true;
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

static int _store_item_copy_from_buf(item *d_it, char *buf, const int len) {
    if (d_it->it_flags & ITEM_CHUNKED) {
        item_chunk *dch = (item_chunk *) ITEM_schunk(d_it);
        int done = 0;
        // Fill dch's via a flat data buffer
        while (len > done && dch) {
            int todo = (dch->size - dch->used < len - done)
                ? dch->size - dch->used : len - done;
            memcpy(dch->data + dch->used, buf + done, todo);
            done += todo;
            dch->used += todo;
            assert(dch->used <= dch->size);

            if (dch->size == dch->used) {
                item_chunk *tch = do_item_alloc_chunk(dch, len - done);
                if (tch) {
                    dch = tch;
                } else {
                    return -1;
                }
            }
        }
        assert(len == done);
    } else {
        memcpy(ITEM_data(d_it), buf, len);
    }

    return 0;
}

// FIXME: rename from _meta to pr_meta
static int _meta_flag_preparse(mcp_parser_t *pr, const size_t start,
        struct _meta_flags *of, char *binkey, char **errstr) {
    unsigned int i;
    size_t ret;
    int32_t tmp_int;
    uint8_t seen[127] = {0};
    of->key = MCP_PARSER_KEY(pr);
    of->key_len = pr->klen;

    if (pr->klen > KEY_MAX_LENGTH) {
        *errstr = "CLIENT_ERROR bad command line format";
        return -1;
    }

    if (pr->tok.ntokens > MFLAG_MAX_OPT_LENGTH) {
        // TODO: ensure the command tokenizer gives us at least this many
        *errstr = "CLIENT_ERROR options flags are too long";
        return -1;
    }

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
            // base64 decode the key in stack memory, as the binary should always be
            // shorter and the conversion code buffers bytes.
            case 'b':
                ret = base64_decode((unsigned char *)MCP_PARSER_KEY(pr), pr->klen,
                            (unsigned char *)binkey, pr->klen);
                if (ret == 0) {
                    // Failed to decode
                    *errstr = "CLIENT_ERROR error decoding key";
                    of->has_error = 1;
                }
                of->key = binkey;
                of->key_len = ret;
                of->key_binary = 1;
                break;
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

/* client flags == 0 means use no storage for client flags */
static inline int make_ascii_get_suffix(char *suffix, item *it, bool return_cas, int nbytes) {
    char *p = suffix;
    *p = ' ';
    p++;
    if (FLAGS_SIZE(it) == 0) {
        *p = '0';
        p++;
    } else {
        p = itoa_u64(*((client_flags_t *) ITEM_suffix(it)), p);
    }
    *p = ' ';
    p = itoa_u32(nbytes-2, p+1);

    if (return_cas) {
        *p = ' ';
        p = itoa_u64(ITEM_get_cas(it), p+1);
    }

    *p = '\r';
    *(p+1) = '\n';
    *(p+2) = '\0';
    return (p - suffix) + 2;
}

int process_get_cmd(LIBEVENT_THREAD *t, const char *key, const int nkey, mc_resp *resp, parser_storage_get_cb storage_cb, rel_time_t exptime, bool return_cas, bool should_touch) {
    bool overflow = false; // unused.

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return -1;
    }

    item *it = limited_get(key, nkey, t, exptime, should_touch, DO_UPDATE, &overflow);
    if (settings.detail_enabled) {
        stats_prefix_record_get(key, nkey, NULL != it);
    }
    if (it) {
      int nbytes = it->nbytes;;
      nbytes = it->nbytes;
      char *p = resp->wbuf;
      memcpy(p, "VALUE ", 6);
      p += 6;
      memcpy(p, ITEM_key(it), it->nkey);
      p += it->nkey;
      p += make_ascii_get_suffix(p, it, return_cas, nbytes);
      resp_add_iov(resp, resp->wbuf, p - resp->wbuf);

#ifdef EXTSTORE
      if (it->it_flags & ITEM_HDR) {
          if (storage_cb(t, it, resp) != 0) {
              pthread_mutex_lock(&t->stats.mutex);
              t->stats.get_oom_extstore++;
              pthread_mutex_unlock(&t->stats.mutex);

              item_remove(it);
              pout_errstring(resp, "SERVER_ERROR out of memory writing get response");
              return -1;
          }
      } else if ((it->it_flags & ITEM_CHUNKED) == 0) {
          resp_add_iov(resp, ITEM_data(it), it->nbytes);
      } else {
          resp_add_chunked_iov(resp, it, it->nbytes);
      }
#else
      if ((it->it_flags & ITEM_CHUNKED) == 0) {
          resp_add_iov(resp, ITEM_data(it), it->nbytes);
      } else {
          resp_add_chunked_iov(resp, it, it->nbytes);
      }
#endif

        /* item_get() has incremented it->refcount for us */
        pthread_mutex_lock(&t->stats.mutex);
        if (should_touch) {
            t->stats.touch_cmds++;
            t->stats.slab_stats[ITEM_clsid(it)].touch_hits++;
        } else {
            t->stats.lru_hits[it->slabs_clsid]++;
            t->stats.get_cmds++;
        }
        pthread_mutex_unlock(&t->stats.mutex);
#ifdef EXTSTORE
        /* If ITEM_HDR, an io_wrap owns the reference. */
        if ((it->it_flags & ITEM_HDR) == 0) {
            resp->item = it;
        }
#else
        resp->item = it;
#endif

        if (settings.verbose > 1) {
            int ii;
            fprintf(stderr, ">%d sending key ", t->cur_sfd);
            for (ii = 0; ii < it->nkey; ++ii) {
                fprintf(stderr, "%c", key[ii]);
            }
            fprintf(stderr, "\n");
        }
    } else {
        pthread_mutex_lock(&t->stats.mutex);
        if (should_touch) {
            t->stats.touch_cmds++;
            t->stats.touch_misses++;
        } else {
            t->stats.get_misses++;
            t->stats.get_cmds++;
        }
        pthread_mutex_unlock(&t->stats.mutex);
    }

    return 0;
}

item *process_update_cmd_start(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas) {
    const char *key = MCP_PARSER_KEY(pr);
    size_t nkey = pr->klen;
    client_flags_t flags;
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    uint64_t req_cas_id = 0;
    item *it;

    assert(resp != NULL);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return NULL;
    }

    if (! (safe_strtoflags(&pr->request[pr->tok.tokens[2]], &flags)
           && safe_strtol(&pr->request[pr->tok.tokens[3]], &exptime_int))) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return NULL;
    }

    exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));

    // does cas value exist?
    if (handle_cas) {
        if (!safe_strtoull(&pr->request[pr->tok.tokens[5]], &req_cas_id)) {
            pout_string(resp, "CLIENT_ERROR bad command line format");
            return NULL;
        }
    }

    // vlen is validated from the main parser.

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    it = item_alloc(key, nkey, flags, exptime, pr->vlen);

    if (it == 0) {
        enum store_item_type status;
        if (! item_size_ok(nkey, flags, pr->vlen)) {
            pout_string(resp, "SERVER_ERROR object too large for cache");
            status = TOO_LARGE;
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_too_large++;
            pthread_mutex_unlock(&t->stats.mutex);
        } else {
            pout_string(resp, "SERVER_ERROR out of memory storing object");
            status = NO_MEMORY;
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_no_memory++;
            pthread_mutex_unlock(&t->stats.mutex);
        }
        LOGGER_LOG(t->l, LOG_MUTATIONS, LOGGER_ITEM_STORE,
                NULL, status, comm, key, nkey, 0, 0, t->cur_sfd);

        /* Avoid stale data persisting in cache because we failed alloc.
         * Unacceptable for SET. Anywhere else too? */
        if (comm == NREAD_SET) {
            it = item_get(key, nkey, t, DONT_UPDATE);
            if (it) {
                item_unlink(it);
                STORAGE_delete(t->storage, it);
                item_remove(it);
            }
        }

        return NULL;
    }
    ITEM_set_cas(it, req_cas_id);

    pthread_mutex_lock(&t->stats.mutex);
    t->stats.slab_stats[ITEM_clsid(it)].set_cmds++;
    pthread_mutex_unlock(&t->stats.mutex);

    return it;
}

void process_update_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas) {
    item *it = process_update_cmd_start(t, pr, resp, comm, handle_cas);
    if (it == NULL) {
        return;
    }
    // complete_nread_proxy() does the data chunk check so all we need to do
    // is copy the data.
    if (_store_item_copy_from_buf(it, pr->vbuf, it->nbytes) != 0) {
        pout_string(resp, "SERVER_ERROR out of memory storing object");
        item_remove(it);
        return;
    }

    int ret = store_item(it, comm, t, NULL, NULL, (settings.use_cas) ? get_cas_id() : 0, CAS_NO_STALE);
    switch (ret) {
    case STORED:
      pout_string(resp, "STORED");
      break;
    case EXISTS:
      pout_string(resp, "EXISTS");
      break;
    case NOT_FOUND:
      pout_string(resp, "NOT_FOUND");
      break;
    case NOT_STORED:
      pout_string(resp, "NOT_STORED");
      break;
    default:
      pout_string(resp, "SERVER_ERROR Unhandled storage type.");
    }

    // We don't need to hold a reference since the item was fully read.
    item_remove(it);
}

void process_arithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, const bool incr) {
    char temp[INCR_MAX_STORAGE_LEN];
    uint64_t delta;
    const char *key = MCP_PARSER_KEY(pr);
    size_t nkey = pr->klen;

    assert(t != NULL);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (!safe_strtoull(&pr->request[pr->tok.tokens[2]], &delta)) {
        pout_string(resp, "CLIENT_ERROR invalid numeric delta argument");
        return;
    }

    switch(add_delta(t, key, nkey, incr, delta, temp, NULL)) {
    case OK:
        pout_string(resp, temp);
        break;
    case NON_NUMERIC:
        pout_string(resp, "CLIENT_ERROR cannot increment or decrement non-numeric value");
        break;
    case EOM:
        pout_string(resp, "SERVER_ERROR out of memory");
        break;
    case DELTA_ITEM_NOT_FOUND:
        pthread_mutex_lock(&t->stats.mutex);
        if (incr) {
            t->stats.incr_misses++;
        } else {
            t->stats.decr_misses++;
        }
        pthread_mutex_unlock(&t->stats.mutex);

        pout_string(resp, "NOT_FOUND");
        break;
    case DELTA_ITEM_CAS_MISMATCH:
        break; /* Should never get here */
    }
}

void process_delete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = MCP_PARSER_KEY(pr);
    size_t nkey = pr->klen;
    item *it;
    uint32_t hv;

    assert(t != NULL);

    // NOTE: removed a compatibility bodge from a decade ago.
    // delete used to take a "delay" argument, which was removed, but some
    // ancient php clients always sent a 0 argument, which would then fail.
    // It's been long enough that I don't want to carry this forward into the
    // new parser.

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (settings.detail_enabled) {
        stats_prefix_record_delete(key, nkey);
    }

    it = item_get_locked(key, nkey, t, DONT_UPDATE, &hv);
    if (it) {
        //MEMCACHED_COMMAND_DELETE(c->sfd, ITEM_key(it), it->nkey);

        pthread_mutex_lock(&t->stats.mutex);
        t->stats.slab_stats[ITEM_clsid(it)].delete_hits++;
        pthread_mutex_unlock(&t->stats.mutex);
        LOGGER_LOG(t->l, LOG_DELETIONS, LOGGER_DELETIONS, it, LOG_TYPE_DELETE);
        do_item_unlink(it, hv);
        STORAGE_delete(t->storage, it);
        do_item_remove(it);      /* release our reference */
        pout_string(resp, "DELETED");
    } else {
        pthread_mutex_lock(&t->stats.mutex);
        t->stats.delete_misses++;
        pthread_mutex_unlock(&t->stats.mutex);

        pout_string(resp, "NOT_FOUND");
    }
    item_unlock(hv);
}

void process_touch_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = MCP_PARSER_KEY(pr);
    size_t nkey = pr->klen;
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    item *it;

    assert(t != NULL);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (!safe_strtol(&pr->request[pr->tok.tokens[2]], &exptime_int)) {
        pout_string(resp, "CLIENT_ERROR invalid exptime argument");
        return;
    }

    exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));
    it = item_touch(key, nkey, exptime, t);
    if (it) {
        pthread_mutex_lock(&t->stats.mutex);
        t->stats.touch_cmds++;
        t->stats.slab_stats[ITEM_clsid(it)].touch_hits++;
        pthread_mutex_unlock(&t->stats.mutex);

        pout_string(resp, "TOUCHED");
        item_remove(it);
    } else {
        pthread_mutex_lock(&t->stats.mutex);
        t->stats.touch_cmds++;
        t->stats.touch_misses++;
        pthread_mutex_unlock(&t->stats.mutex);

        pout_string(resp, "NOT_FOUND");
    }
}

void process_mget_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp,
        parser_storage_get_cb storage_cb) {
    char binkey[KEY_MAX_LENGTH]; // if we decode a binary key, put it here.
    item *it;
    unsigned int i = 0;
    struct _meta_flags of = {0}; // option bitflags.
    uint32_t hv; // cached hash value for unlocking an item.
    bool failed = false;
    bool item_created = false;
    bool won_token = false;
    bool ttl_set = false;
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(t != NULL);
    char *p = resp->wbuf;
    int tlen = 0;

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 2, &of, binkey, &errstr) != 0) {
        pout_errstring(resp, errstr);
        return;
    }

    // indirect key access, in case of binary key.
    const char *key = of.key;
    size_t nkey = of.key_len;

    bool overflow = false;
    if (!of.locked) {
        it = limited_get(key, nkey, t, 0, false, !of.no_update, &overflow);
    } else {
        // If we had to lock the item, we're doing our own bump later.
        it = limited_get_locked(key, nkey, t, DONT_UPDATE, &hv, &overflow);
    }

    // Since we're a new protocol, we can actually inform users that refcount
    // overflow is happening by straight up throwing an error.
    // We definitely don't want to re-autovivify by accident.
    if (overflow) {
        assert(it == NULL);
        pout_errstring(resp, "SERVER_ERROR refcount overflow during fetch");
        return;
    }

    if (it == NULL && of.vivify) {
        // Fill in the exptime during parsing later.
        it = item_alloc(key, nkey, 0, realtime(0), 2);
        // We don't actually need any of do_store_item's logic:
        // - already fetched and missed an existing item.
        // - lock is still held.
        // - not append/prepend/replace
        // - not testing CAS
        if (it != NULL) {
            // I look forward to the day I get rid of this :)
            memcpy(ITEM_data(it), "\r\n", 2);
            // NOTE: This initializes the CAS value.
            do_item_link(it, hv, of.has_cas_in ? of.cas_id_in : get_cas_id());
            item_created = true;
        }
    }

    // don't have to check result of add_iov() since the iov size defaults are
    // enough.
    if (it) {
        if (of.value) {
            memcpy(p, "VA ", 3);
            p = itoa_u32(it->nbytes-2, p+3);
        } else {
            memcpy(p, "HD", 2);
            p += 2;
        }

        for (i = pr->keytoken+1; i < pr->tok.ntokens; i++) {
            switch (pr->request[pr->tok.tokens[i]]) {
                case 'T':
                    ttl_set = true;
                    it->exptime = of.exptime;
                    break;
                case 'N':
                    if (item_created) {
                        it->exptime = of.autoviv_exptime;
                        won_token = true;
                    }
                    break;
                case 'R':
                    // If we haven't autovivified and supplied token is less
                    // than current TTL, mark a win.
                    if ((it->it_flags & ITEM_TOKEN_SENT) == 0
                            && !item_created
                            && it->exptime != 0
                            && it->exptime < of.recache_time) {
                        won_token = true;
                    }
                    break;
                case 's':
                    META_CHAR(p, 's');
                    p = itoa_u32(it->nbytes-2, p);
                    break;
                case 't':
                    // TTL remaining as of this request.
                    // needs to be relative because server clocks may not be in sync.
                    META_CHAR(p, 't');
                    if (it->exptime == 0) {
                        *p = '-';
                        *(p+1) = '1';
                        p += 2;
                    } else {
                        p = itoa_u32(it->exptime - current_time, p);
                    }
                    break;
                case 'c':
                    META_CHAR(p, 'c');
                    p = itoa_u64(ITEM_get_cas(it), p);
                    break;
                case 'f':
                    META_CHAR(p, 'f');
                    if (FLAGS_SIZE(it) == 0) {
                        *p = '0';
                        p++;
                    } else {
                        p = itoa_u64(*((client_flags_t *) ITEM_suffix(it)), p);
                    }
                    break;
                case 'l':
                    META_CHAR(p, 'l');
                    p = itoa_u32(current_time - it->time, p);
                    break;
                case 'h':
                    META_CHAR(p, 'h');
                    if (it->it_flags & ITEM_FETCHED) {
                        *p = '1';
                    } else {
                        *p = '0';
                    }
                    p++;
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
                    META_KEY(p, ITEM_key(it), it->nkey, (it->it_flags & ITEM_KEY_BINARY));
                    break;
            }
        }

        // Has this item already sent a token?
        // Important to do this here so we don't send W with Z.
        // Isn't critical, but easier for client authors to understand.
        if (it->it_flags & ITEM_TOKEN_SENT) {
            META_CHAR(p, 'Z');
        }
        if (it->it_flags & ITEM_STALE) {
            META_CHAR(p, 'X');
            // FIXME: think hard about this. is this a default, or a flag?
            if ((it->it_flags & ITEM_TOKEN_SENT) == 0) {
                // If we're stale but no token already sent, now send one.
                won_token = true;
            }
        }

        if (won_token) {
            // Mark a win into the flag buffer.
            META_CHAR(p, 'W');
            it->it_flags |= ITEM_TOKEN_SENT;
        }

        *p = '\r';
        *(p+1) = '\n';
        *(p+2) = '\0';
        p += 2;
        // finally, chain in the buffer.
        resp_add_iov(resp, resp->wbuf, p - resp->wbuf);

        if (of.value) {
#ifdef EXTSTORE
            if (it->it_flags & ITEM_HDR) {
                if (storage_cb(t, it, resp) != 0) {
                    pthread_mutex_lock(&t->stats.mutex);
                    t->stats.get_oom_extstore++;
                    pthread_mutex_unlock(&t->stats.mutex);

                    failed = true;
                }
            } else if ((it->it_flags & ITEM_CHUNKED) == 0) {
                resp_add_iov(resp, ITEM_data(it), it->nbytes);
            } else {
                resp_add_chunked_iov(resp, it, it->nbytes);
            }
#else
            if ((it->it_flags & ITEM_CHUNKED) == 0) {
                resp_add_iov(resp, ITEM_data(it), it->nbytes);
            } else {
                resp_add_chunked_iov(resp, it, it->nbytes);
            }
#endif
        }

        // need to hold the ref at least because of the key above.
#ifdef EXTSTORE
        if (!failed) {
            if ((it->it_flags & ITEM_HDR) != 0 && of.value) {
                // Only have extstore clean if header and returning value.
                resp->item = NULL;
            } else {
                resp->item = it;
            }
        } else {
            // Failed to set up extstore fetch.
            if (of.locked) {
                do_item_remove(it);
            } else {
                item_remove(it);
            }
        }
#else
        resp->item = it;
#endif
    } else {
        failed = true;
    }

    if (of.locked) {
        // Delayed bump so we could get fetched/last access time pre-update.
        if (!of.no_update && it != NULL) {
            do_item_bump(t, it, hv);
        }
        item_unlock(hv);
    }

    // we count this command as a normal one if we've gotten this far.
    // TODO: for autovivify case, miss never happens. Is this okay?
    if (!failed) {
        pthread_mutex_lock(&t->stats.mutex);
        if (ttl_set) {
            t->stats.touch_cmds++;
            t->stats.slab_stats[ITEM_clsid(it)].touch_hits++;
        } else {
            t->stats.lru_hits[it->slabs_clsid]++;
            t->stats.get_cmds++;
        }
        pthread_mutex_unlock(&t->stats.mutex);
    } else {
        pthread_mutex_lock(&t->stats.mutex);
        if (ttl_set) {
            t->stats.touch_cmds++;
            t->stats.touch_misses++;
        } else {
            t->stats.get_misses++;
            t->stats.get_cmds++;
        }
        pthread_mutex_unlock(&t->stats.mutex);

        // This gets elided in noreply mode.
        if (of.no_reply)
            resp->skip = true;
        memcpy(p, "EN", 2);
        p += 2;
        for (i = pr->keytoken+1; i < pr->tok.ntokens; i++) {
            switch (pr->request[pr->tok.tokens[i]]) {
                // TODO: macro perhaps?
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
        resp->wbytes = p - resp->wbuf;
        memcpy(resp->wbuf + resp->wbytes, "\r\n", 2);
        resp->wbytes += 2;
        resp_add_iov(resp, resp->wbuf, resp->wbytes);
    }
    return;
error:
    if (it) {
        do_item_remove(it);
        if (of.locked) {
            item_unlock(hv);
        }
    }
    pout_errstring(resp, errstr);
}

item *process_mset_cmd_start(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp,
        uint64_t *cas_in, bool *has_cas_in, short *comm) {
    char binkey[KEY_MAX_LENGTH]; // if we decode a binary key, put it here.
    item *it;
    *comm = NREAD_SET;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    uint32_t hv; // cached hash value.
    int vlen = pr->vlen; // value from data line.
    assert(t != NULL);

    if (pr->tok.ntokens < 3) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return NULL;
    }

    // We need to at least try to get the size to properly slurp bad bytes
    // after an error.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 3, &of, binkey, &errstr) != 0) {
        goto error;
    }

    // indirect key access, in case of binary key.
    const char *key = of.key;
    size_t nkey = of.key_len;

    rel_time_t exptime = of.exptime;
    // "mode switch" to alternative commands
    switch (of.mode) {
        case 0:
            break; // no mode supplied.
        case 'E': // Add...
            *comm = NREAD_ADD;
            break;
        case 'A': // Append.
            if (of.vivify) {
                *comm = NREAD_APPENDVIV;
                exptime = of.autoviv_exptime;
            } else {
                *comm = NREAD_APPEND;
            }
            break;
        case 'P': // Prepend.
            if (of.vivify) {
                *comm = NREAD_PREPENDVIV;
                exptime = of.autoviv_exptime;
            } else {
                *comm = NREAD_PREPEND;
            }
            break;
        case 'R': // Replace.
            *comm = NREAD_REPLACE;
            break;
        case 'S': // Set. Default.
            *comm = NREAD_SET;
            break;
        default:
            errstr = "CLIENT_ERROR invalid mode for ms M token";
            goto error;
    }

    // The item storage function doesn't exactly map to mset.
    // If a CAS value is supplied, upgrade default SET mode to CAS mode.
    // Also allows REPLACE to work, as REPLACE + CAS works the same as CAS.
    // add-with-cas works the same as add; but could only LRU bump if match..
    // APPEND/PREPEND allow a simplified CAS check.
    if (of.has_cas && (*comm == NREAD_SET || *comm == NREAD_REPLACE)) {
        *comm = NREAD_CAS;
    }

    it = item_alloc(key, nkey, of.client_flags, exptime, vlen);

    if (it == 0) {
        enum store_item_type status;
        if (! item_size_ok(nkey, of.client_flags, vlen)) {
            errstr = "SERVER_ERROR object too large for cache";
            status = TOO_LARGE;
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_too_large++;
            pthread_mutex_unlock(&t->stats.mutex);
        } else {
            errstr = "SERVER_ERROR out of memory storing object";
            status = NO_MEMORY;
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_no_memory++;
            pthread_mutex_unlock(&t->stats.mutex);
        }
        // FIXME: LOGGER_LOG specific to mset, include options.
        LOGGER_LOG(t->l, LOG_MUTATIONS, LOGGER_ITEM_STORE,
                NULL, status, comm, key, nkey, 0, t->cur_sfd);

        /* Avoid stale data persisting in cache because we failed alloc. */
        // NOTE: only if SET mode?
        it = item_get_locked(key, nkey, t, DONT_UPDATE, &hv);
        if (it) {
            do_item_unlink(it, hv);
            STORAGE_delete(t->storage, it);
            do_item_remove(it);
        }
        item_unlock(hv);

        goto error;
    }
    ITEM_set_cas(it, of.req_cas_id);

    // data should already be read into the request.

    // Prevent printing back the key in meta commands as garbage.
    if (of.key_binary) {
        it->it_flags |= ITEM_KEY_BINARY;
    }

    resp->set_stale = CAS_NO_STALE;
    if (of.set_stale && *comm == NREAD_CAS) {
        resp->set_stale = CAS_ALLOW_STALE;
    }
    resp->noreply = of.no_reply;

    pthread_mutex_lock(&t->stats.mutex);
    t->stats.slab_stats[ITEM_clsid(it)].set_cmds++;
    pthread_mutex_unlock(&t->stats.mutex);

    if (of.has_cas_in) {
        *cas_in = of.cas_id_in;
        *has_cas_in = true;
    }
    return it;
error:
    // Note: no errors possible after the item was successfully allocated.
    // So we're just looking at dumping error codes and returning.
    pout_errstring(resp, errstr);
    return NULL;
}

void process_mset_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    bool has_cas_in = false;
    uint64_t cas_in = 0;
    short comm = 0;
    item *it = process_mset_cmd_start(t, pr, resp, &cas_in, &has_cas_in, &comm);
    char *errstr = "CLIENT_ERROR bad command line format";

    if (it == NULL)
        return;

    // complete_nread_proxy() does the data chunk check so all we need to do
    // is copy the data.
    if (_store_item_copy_from_buf(it, pr->vbuf, it->nbytes) != 0) {
        pout_string(resp, "SERVER_ERROR out of memory storing object");
        item_remove(it);
        return;
    }

    char *p = resp->wbuf;
    uint64_t cas = 0;
    int nbytes = 0;
    int ret = store_item(it, comm, t, &nbytes, &cas, has_cas_in ? cas_in : get_cas_id(), resp->set_stale);
    switch (ret) {
        case STORED:
          memcpy(p, "HD", 2);
          // Only place noreply is used for meta cmds is a nominal response.
          if (resp->noreply) {
              resp->skip = true;
          }
          break;
        case EXISTS:
          memcpy(p, "EX", 2);
          break;
        case NOT_FOUND:
          memcpy(p, "NF", 2);
          break;
        case NOT_STORED:
          memcpy(p, "NS", 2);
          break;
        default:
          pout_errstring(resp, "SERVER_ERROR Unhandled storage type.");
          return;

    }
    p += 2;

    for (int i = pr->keytoken+1; i < pr->tok.ntokens; i++) {
        int tlen;
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
                META_KEY(p, ITEM_key(it), it->nkey, (it->it_flags & ITEM_KEY_BINARY));
                break;
            case 'c':
                META_CHAR(p, 'c');
                p = itoa_u64(cas, p);
                break;
            case 's':
                // Get final item size, ie from append/prepend
                META_CHAR(p, 's');
                // If the size changed during append/prepend
                if (nbytes != 0) {
                    p = itoa_u32(nbytes-2, p);
                } else {
                    p = itoa_u32(it->nbytes-2, p);
                }
                break;
        }
    }

    // We don't need to free pr->vbuf as that is owned by *rq
    // either way, there's no c->item or resp->item reference right now.

    memcpy(p, "\r\n", 2);
    p += 2;
    // we're offset into wbuf, but good convention to track wbytes.
    resp->wbytes = p - resp->wbuf;
    resp_add_iov(resp, resp->wbuf, resp->wbytes);

    item_remove(it);

    return;
error:
    // Note: no errors possible after the item was successfully allocated.
    // So we're just looking at dumping error codes and returning.
    pout_errstring(resp, errstr);
}

void process_mdelete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    char binkey[KEY_MAX_LENGTH]; // if we decode a binary key, put it here.
    item *it = NULL;
    int i;
    uint32_t hv = 0;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(t != NULL);
    // reserve bytes for status code
    char *p = resp->wbuf + 2;
    int tlen = 0;

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 2, &of, binkey, &errstr) != 0) {
        pout_errstring(resp, errstr);
        return;
    }

    // indirect key access, in case of binary key.
    const char *key = of.key;
    size_t nkey = of.key_len;

    for (i = pr->keytoken+1; i < pr->tok.ntokens; i++) {
        switch (pr->request[pr->tok.tokens[i]]) {
            // TODO: macro perhaps?
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

    it = item_get_locked(key, nkey, t, DONT_UPDATE, &hv);
    if (it) {
        // allow only deleting/marking if a CAS value matches.
        if (of.has_cas && ITEM_get_cas(it) != of.req_cas_id) {
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.delete_misses++;
            pthread_mutex_unlock(&t->stats.mutex);

            memcpy(resp->wbuf, "EX", 2);
            goto cleanup;
        }

        // If requested, create a new empty tombstone item.
        if (of.remove_val) {
            item *new_it = item_alloc(key, nkey, of.client_flags, of.exptime, 2);
            if (new_it != NULL) {
                memcpy(ITEM_data(new_it), "\r\n", 2);
                if (do_store_item(new_it, NREAD_SET, t, hv, NULL, NULL,
                            of.has_cas_in ? of.cas_id_in : ITEM_get_cas(it), CAS_NO_STALE)) {
                    do_item_remove(it);
                    it = new_it;
                } else {
                    do_item_remove(new_it);
                    memcpy(resp->wbuf, "NS", 2);
                    goto cleanup;
                }
            } else {
                errstr = "SERVER_ERROR out of memory";
                goto error;
            }
        }

        // If we're to set this item as stale, we don't actually want to
        // delete it. We mark the stale bit, bump CAS, and update exptime if
        // we were supplied a new TTL.
        if (of.set_stale) {
            if (of.new_ttl) {
                it->exptime = of.exptime;
            }
            it->it_flags |= ITEM_STALE;
            // Also need to remove TOKEN_SENT, so next client can win.
            it->it_flags &= ~ITEM_TOKEN_SENT;

            ITEM_set_cas(it, of.has_cas_in ? of.cas_id_in : get_cas_id());
            if (of.no_reply)
                resp->skip = true;

            memcpy(resp->wbuf, "HD", 2);
        } else {
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.slab_stats[ITEM_clsid(it)].delete_hits++;
            pthread_mutex_unlock(&t->stats.mutex);
            LOGGER_LOG(t->l, LOG_DELETIONS, LOGGER_DELETIONS, it, LOG_TYPE_META_DELETE);

            if (!of.remove_val) {
                do_item_unlink(it, hv);
                STORAGE_delete(t->storage, it);
            }
            if (of.no_reply)
                resp->skip = true;
            memcpy(resp->wbuf, "HD", 2);
        }
        goto cleanup;
    } else {
        pthread_mutex_lock(&t->stats.mutex);
        t->stats.delete_misses++;
        pthread_mutex_unlock(&t->stats.mutex);

        memcpy(resp->wbuf, "NF", 2);
        goto cleanup;
    }
cleanup:
    if (it) {
        do_item_remove(it);
    }
    // Item is always returned locked, even if missing.
    item_unlock(hv);
    resp->wbytes = p - resp->wbuf;
    memcpy(resp->wbuf + resp->wbytes, "\r\n", 2);
    resp->wbytes += 2;
    resp_add_iov(resp, resp->wbuf, resp->wbytes);
    //conn_set_state(c, conn_new_cmd);
    return;
error:
    // cleanup if an error happens after we fetched an item.
    if (it) {
        do_item_remove(it);
        item_unlock(hv);
    }
    pout_errstring(resp, errstr);
}

void process_marithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    char binkey[KEY_MAX_LENGTH]; // if we decode a binary key, put it here.
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

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 2, &of, binkey, &errstr) != 0) {
        pout_errstring(resp, "CLIENT_ERROR invalid or duplicate flag");
        return;
    }

    // indirect key access, in case of binary key.
    const char *key = of.key;
    size_t nkey = of.key_len;

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
                    if (of.no_reply)
                        resp->skip = true;
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


