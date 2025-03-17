/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Functions for handling the text related protocols, original and meta.
 */

#include "memcached.h"
#include "proto_text.h"
// FIXME: only for process_proxy_stats()
// - some better/different structure for stats subcommands
// would remove this abstraction leak.
#include "proto_proxy.h"
#include "proto_parser.h"
#include "authfile.h"
#include "storage.h"
#include "base64.h"
#ifdef TLS
#include "tls.h"
#endif
#include <string.h>
#include <stdlib.h>

#define _DO_CAS true
#define _NO_CAS false
#define _DO_TOUCH true
#define _NO_TOUCH false

#define META_SPACE(p) { \
    *p = ' '; \
    p++; \
}

#define META_CHAR(p, c) { \
    *p = ' '; \
    *(p+1) = c; \
    p += 2; \
}

typedef struct token_s {
    char *value;
    size_t length;
} token_t;

static void _finalize_mset(conn *c, int nbytes, enum store_item_type ret, uint64_t cas) {
    mc_resp *resp = c->resp;
    item *it = c->item;
    conn_set_state(c, conn_new_cmd);

    // information about the response line has been stashed in wbuf.
    char *p = resp->wbuf + resp->wbytes;
    char *end = p; // end of the stashed data portion.

    switch (ret) {
    case STORED:
      memcpy(p, "HD", 2);
      // Only place noreply is used for meta cmds is a nominal response.
      if (c->resp->noreply) {
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
      out_errstring(c, "SERVER_ERROR Unhandled storage type.");
      return;
    }
    p += 2;

    for (char *fp = resp->wbuf; fp < end; fp++) {
        switch (*fp) {
            case 'O':
                // Copy stashed opaque.
                META_SPACE(p);
                while (fp < end && *fp != ' ') {
                    *p = *fp;
                    p++;
                    fp++;
                }
                break;
            case 'k':
                // Encode the key here instead of earlier to minimize copying.
                META_KEY(p, ITEM_key(it), it->nkey, (it->it_flags & ITEM_KEY_BINARY));
                break;
            case 'c':
                // We don't have the CAS until this point, which is why we
                // generate this line so late.
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
            default:
                break;
        }
    }

    memcpy(p, "\r\n", 2);
    p += 2;
    // we're offset into wbuf, but good convention to track wbytes.
    resp->wbytes = p - resp->wbuf;
    resp_add_iov(resp, end, p - end);
}

/*
 * we get here after reading the value in set/add/replace commands. The command
 * has been stored in c->cmd, and the item is ready in c->item.
 */
void complete_nread_ascii(conn *c) {
    assert(c != NULL);

    item *it = c->item;
    int comm = c->cmd;
    enum store_item_type ret;
    bool is_valid = false;
    int nbytes = 0;

    if ((it->it_flags & ITEM_CHUNKED) == 0) {
        if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2) == 0) {
            is_valid = true;
        }
    } else {
        char buf[2];
        /* should point to the final item chunk */
        item_chunk *ch = (item_chunk *) c->ritem;
        assert(ch->used != 0);
        /* :( We need to look at the last two bytes. This could span two
         * chunks.
         */
        if (ch->used > 1) {
            buf[0] = ch->data[ch->used - 2];
            buf[1] = ch->data[ch->used - 1];
        } else {
            assert(ch->prev);
            assert(ch->used == 1);
            buf[0] = ch->prev->data[ch->prev->used - 1];
            buf[1] = ch->data[ch->used - 1];
        }
        if (strncmp(buf, "\r\n", 2) == 0) {
            is_valid = true;
        } else {
            assert(1 == 0);
        }
    }

    if (!is_valid) {
        // metaset mode always returns errors.
        if (c->resp->mset_res) {
            c->resp->noreply = false;
        }
        out_string(c, "CLIENT_ERROR bad data chunk");
    } else {
      uint64_t cas = 0;
      c->thread->cur_sfd = c->sfd; // cuddle sfd for logging.
      ret = store_item(it, comm, c->thread, &nbytes, &cas, c->cas ? c->cas : get_cas_id(), c->resp->set_stale);
      c->cas = 0;

#ifdef ENABLE_DTRACE
      switch (c->cmd) {
      case NREAD_ADD:
          MEMCACHED_COMMAND_ADD(c->sfd, ITEM_key(it), it->nkey,
                                (ret == 1) ? it->nbytes : -1, cas);
          break;
      case NREAD_REPLACE:
          MEMCACHED_COMMAND_REPLACE(c->sfd, ITEM_key(it), it->nkey,
                                    (ret == 1) ? it->nbytes : -1, cas);
          break;
      case NREAD_APPEND:
          MEMCACHED_COMMAND_APPEND(c->sfd, ITEM_key(it), it->nkey,
                                   (ret == 1) ? it->nbytes : -1, cas);
          break;
      case NREAD_PREPEND:
          MEMCACHED_COMMAND_PREPEND(c->sfd, ITEM_key(it), it->nkey,
                                    (ret == 1) ? it->nbytes : -1, cas);
          break;
      case NREAD_SET:
          MEMCACHED_COMMAND_SET(c->sfd, ITEM_key(it), it->nkey,
                                (ret == 1) ? it->nbytes : -1, cas);
          break;
      case NREAD_CAS:
          MEMCACHED_COMMAND_CAS(c->sfd, ITEM_key(it), it->nkey, it->nbytes,
                                cas);
          break;
      }
#endif

      if (c->resp->mset_res) {
          _finalize_mset(c, nbytes, ret, cas);
      } else {
          switch (ret) {
          case STORED:
              out_string(c, "STORED");
              break;
          case EXISTS:
              out_string(c, "EXISTS");
              break;
          case NOT_FOUND:
              out_string(c, "NOT_FOUND");
              break;
          case NOT_STORED:
              out_string(c, "NOT_STORED");
              break;
          default:
              out_string(c, "SERVER_ERROR Unhandled storage type.");
          }
      }

    }

    item_remove(c->item);       /* release the c->item reference */
    c->item = 0;
}

#define COMMAND_TOKEN 0
#define SUBCOMMAND_TOKEN 1
#define KEY_TOKEN 1

#define MAX_TOKENS 24

#define WANT_TOKENS(ntokens, min, max) \
    do { \
        if ((min != -1 && ntokens < min) || (max != -1 && ntokens > max)) { \
            out_string(c, "ERROR"); \
            return; \
        } \
    } while (0)

#define WANT_TOKENS_OR(ntokens, a, b) \
    do { \
        if (ntokens != a && ntokens != b) { \
            out_string(c, "ERROR"); \
            return; \
        } \
    } while (0)

#define WANT_TOKENS_MIN(ntokens, min) \
    do { \
        if (ntokens < min) { \
            out_string(c, "ERROR"); \
            return; \
        } \
    } while (0)

/*
 * Tokenize the command string by replacing whitespace with '\0' and update
 * the token array tokens with pointer to start of each token and length.
 * Returns total number of tokens.  The last valid token is the terminal
 * token (value points to the first unprocessed character of the string and
 * length zero).
 *
 * Usage example:
 *
 *  while(tokenize_command(command, ncommand, tokens, max_tokens) > 0) {
 *      for(int ix = 0; tokens[ix].length != 0; ix++) {
 *          ...
 *      }
 *      ncommand = tokens[ix].value - command;
 *      command  = tokens[ix].value;
 *   }
 */
static size_t tokenize_command(char *command, token_t *tokens, const size_t max_tokens) {
    char *s, *e;
    size_t ntokens = 0;
    assert(command != NULL && tokens != NULL && max_tokens > 1);
    size_t len = strlen(command);
    unsigned int i = 0;

    s = e = command;
    for (i = 0; i < len; i++) {
        if (*e == ' ') {
            if (s != e) {
                tokens[ntokens].value = s;
                tokens[ntokens].length = e - s;
                ntokens++;
                *e = '\0';
                if (ntokens == max_tokens - 1) {
                    e++;
                    s = e; /* so we don't add an extra token */
                    break;
                }
            }
            s = e + 1;
        }
        e++;
    }

    if (s != e) {
        tokens[ntokens].value = s;
        tokens[ntokens].length = e - s;
        ntokens++;
    }

    /*
     * If we scanned the whole string, the terminal value pointer is null,
     * otherwise it is the first unprocessed character.
     */
    tokens[ntokens].value =  *e == '\0' ? NULL : e;
    tokens[ntokens].length = 0;
    ntokens++;

    return ntokens;
}

int try_read_command_asciiauth(conn *c) {
    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    char *cont = NULL;

    // TODO: move to another function.
    if (!c->sasl_started) {
        char *el;
        uint32_t size = 0;

        // impossible for the auth command to be this short.
        if (c->rbytes < 2)
            return 0;

        el = memchr(c->rcurr, '\n', c->rbytes);

        // If no newline after 1k, getting junk data, close out.
        if (!el) {
            if (c->rbytes > 2048) {
                conn_set_state(c, conn_closing);
                return 1;
            }
            return 0;
        }

        // Looking for: "set foo 0 0 N\r\nuser pass\r\n"
        // key, flags, and ttl are ignored. N is used to see if we have the rest.

        // so tokenize doesn't walk past into the value.
        // it's fine to leave the \r in, as strtoul will stop at it.
        *el = '\0';

        ntokens = tokenize_command(c->rcurr, tokens, MAX_TOKENS);
        // ensure the buffer is consumed.
        c->rbytes -= (el - c->rcurr) + 1;
        c->rcurr += (el - c->rcurr) + 1;

        // final token is a NULL ender, so we have one more than expected.
        if (ntokens < 6
                || strcmp(tokens[0].value, "set") != 0
                || !safe_strtoul(tokens[4].value, &size)) {
            if (!c->resp) {
                if (!resp_start(c)) {
                    conn_set_state(c, conn_closing);
                    return 1;
                }
            }
            out_string(c, "CLIENT_ERROR unauthenticated");
            return 1;
        }

        // we don't actually care about the key at all; it can be anything.
        // we do care about the size of the remaining read.
        c->rlbytes = size + 2;

        c->sasl_started = true; // reuse from binprot sasl, but not sasl :)
    }

    if (c->rbytes < c->rlbytes) {
        // need more bytes.
        return 0;
    }

    // Going to respond at this point, so attach a response object.
    if (!c->resp) {
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return 1;
        }
    }

    cont = c->rcurr;
    // advance buffer. no matter what we're stopping.
    c->rbytes -= c->rlbytes;
    c->rcurr += c->rlbytes;
    c->sasl_started = false;

    // must end with \r\n
    // NB: I thought ASCII sets also worked with just \n, but according to
    // complete_nread_ascii only \r\n is valid.
    if (strncmp(cont + c->rlbytes - 2, "\r\n", 2) != 0) {
        out_string(c, "CLIENT_ERROR bad command line termination");
        return 1;
    }

    // payload should be "user pass", so we can use the tokenizer.
    cont[c->rlbytes - 2] = '\0';
    ntokens = tokenize_command(cont, tokens, MAX_TOKENS);

    if (ntokens < 3) {
        out_string(c, "CLIENT_ERROR bad authentication token format");
        return 1;
    }

    if (authfile_check(tokens[0].value, tokens[1].value) == 1) {
        out_string(c, "STORED");
        c->authenticated = true;
        c->try_read_command = try_read_command_ascii;
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.auth_cmds++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
    } else {
        out_string(c, "CLIENT_ERROR authentication failure");
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.auth_cmds++;
        c->thread->stats.auth_errors++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
    }

    return 1;
}

int try_read_command_ascii(conn *c) {
    char *el, *cont;

    if (c->rbytes == 0)
        return 0;

    el = memchr(c->rcurr, '\n', c->rbytes);
    if (!el) {
        if (c->rbytes > 2048) {
            /*
             * We didn't have a '\n' in the first few k. This _has_ to be a
             * large multiget, if not we should just nuke the connection.
             */
            char *ptr = c->rcurr;
            while (*ptr == ' ') { /* ignore leading whitespaces */
                ++ptr;
            }

            if (ptr - c->rcurr > 100 ||
                (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {

                conn_set_state(c, conn_closing);
                return 1;
            }

            // ASCII multigets are unbound, so our fixed size rbuf may not
            // work for this particular workload... For backcompat we'll use a
            // malloc/realloc/free routine just for this.
            if (!c->rbuf_malloced) {
                if (!rbuf_switch_to_malloc(c)) {
                    conn_set_state(c, conn_closing);
                    return 1;
                }
            }
        }

        return 0;
    }
    cont = el + 1;

    assert(cont <= (c->rcurr + c->rbytes));

    c->last_cmd_time = current_time;
    process_command_ascii(c, c->rcurr, el);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    assert(c->rcurr <= (c->rbuf + c->rsize));

    return 1;
}


static inline bool set_noreply_maybe(conn *c, token_t *tokens, size_t ntokens)
{
    int noreply_index = ntokens - 2;

    /*
      NOTE: this function is not the first place where we are going to
      send the reply.  We could send it instead from process_command()
      if the request line has wrong number of tokens.  However parsing
      malformed line for "noreply" option is not reliable anyway, so
      it can't be helped.
    */
    if (tokens[noreply_index].value
        && strcmp(tokens[noreply_index].value, "noreply") == 0) {
        c->resp->noreply = true;
    }
    return c->resp->noreply;
}

static void process_get_command_err(conn *c, const char *errstr) {
    // Use passed in error or rescue the last error while processing.
    char wbuf[WRITE_BUFFER_SIZE];
    if (errstr) {
        memcpy(wbuf, errstr, strlen(errstr));
    } else {
        size_t l = c->resp->iov[0].iov_len;
        memcpy(wbuf, c->resp->wbuf, l);
        wbuf[l] = '\0';
    }
    conn_release_items(c);
    if (!resp_start(c)) {
        conn_set_state(c, conn_closing);
        return;
    }
    out_string(c, wbuf);
}

static void process_get_command(conn *c, LIBEVENT_THREAD *t, mcp_parser_t *pr, parser_storage_get_cb storage_cb, bool return_cas, bool should_touch) {
    uint32_t keyoff = pr->tok.tokens[pr->keytoken];
    const char *curkey = pr->request + keyoff;
    int klen = pr->klen;
    const char *kend = NULL;
    rel_time_t exptime = 0;

    if (should_touch) {
        int32_t exptime_int = 0;
        if (!safe_strtol(&pr->request[pr->tok.tokens[1]], &exptime_int)) {
            out_string(c, "CLIENT_ERROR invalid exptime argument");
            return;
        }
        exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));
    }

    if (pr->request[pr->reqlen-2] == '\r') {
        kend = pr->request + pr->reqlen - 2;
    } else {
        kend = pr->request + pr->reqlen - 1;
    }

    while (klen != 0) {
        mc_resp *resp = c->resp;
        if (process_get_cmd(t, curkey, klen, c->resp, storage_get_item, exptime, return_cas, should_touch) != 0) {
            process_get_command_err(c, NULL);
            return;
        }
        if (resp->io_pending) {
            resp->io_pending->c = c;
            conn_resp_suspend(c, resp);
        }
        curkey += klen;
        klen = 0;
        while (curkey != kend) {
            if (*curkey == ' ') {
                curkey++;
            } else {
                const char *s = memchr(curkey, ' ', kend - curkey);
                if (s != NULL) {
                    klen = s - curkey;
                } else {
                    klen = kend - curkey;
                }
                break;
            }
        }

        if (klen && !resp_start(c)) {
            // This may succeed because it first frees existing resp objects.
            process_get_command_err(c, "SERVER_ERROR out of memory writing get response");
            return;
        }
    }
    resp_add_iov(c->resp, "END\r\n", 5);
    conn_set_state(c, conn_new_cmd);
    return;
}

inline static void process_stats_detail(conn *c, const char *command) {
    assert(c != NULL);

    if (strcmp(command, "on") == 0) {
        settings.detail_enabled = 1;
        out_string(c, "OK");
    }
    else if (strcmp(command, "off") == 0) {
        settings.detail_enabled = 0;
        out_string(c, "OK");
    }
    else if (strcmp(command, "dump") == 0) {
        int len;
        char *stats = stats_prefix_dump(&len);
        write_and_free(c, stats, len);
    }
    else {
        out_string(c, "CLIENT_ERROR usage: stats detail on|off|dump");
    }
}

static void process_stat(conn *c, token_t *tokens, const size_t ntokens) {
    const char *subcommand = tokens[SUBCOMMAND_TOKEN].value;
    assert(c != NULL);

    if (ntokens < 2) {
        out_string(c, "CLIENT_ERROR bad command line");
        return;
    }

    if (ntokens == 2) {
        server_stats(&append_stats, c);
        (void)get_stats(NULL, 0, &append_stats, c);
    } else if (strcmp(subcommand, "reset") == 0) {
        stats_reset();
        out_string(c, "RESET");
        return;
    } else if (strcmp(subcommand, "detail") == 0) {
        if (!settings.dump_enabled) {
            out_string(c, "CLIENT_ERROR stats detail not allowed");
            return;
        }

        /* NOTE: how to tackle detail with binary? */
        if (ntokens < 4)
            process_stats_detail(c, "");  /* outputs the error message */
        else
            process_stats_detail(c, tokens[2].value);
        /* Output already generated */
        return;
    } else if (strcmp(subcommand, "settings") == 0) {
        process_stat_settings(&append_stats, c);
    } else if (strcmp(subcommand, "cachedump") == 0) {
        char *buf;
        unsigned int bytes, id, limit = 0;

        if (!settings.dump_enabled) {
            out_string(c, "CLIENT_ERROR stats cachedump not allowed");
            return;
        }

        if (ntokens < 5) {
            out_string(c, "CLIENT_ERROR bad command line");
            return;
        }

        if (!safe_strtoul(tokens[2].value, &id) ||
            !safe_strtoul(tokens[3].value, &limit)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        if (id >= MAX_NUMBER_OF_SLAB_CLASSES) {
            out_string(c, "CLIENT_ERROR Illegal slab id");
            return;
        }

        buf = item_cachedump(id, limit, &bytes);
        write_and_free(c, buf, bytes);
        return;
    } else if (strcmp(subcommand, "conns") == 0) {
        process_stats_conns(&append_stats, c);
#ifdef EXTSTORE
    } else if (strcmp(subcommand, "extstore") == 0) {
        process_extstore_stats(&append_stats, c);
#endif
#ifdef PROXY
    } else if (strcmp(subcommand, "proxy") == 0) {
        process_proxy_stats(settings.proxy_ctx, &append_stats, c);
    } else if (strcmp(subcommand, "proxyfuncs") == 0) {
        process_proxy_funcstats(settings.proxy_ctx, &append_stats, c);
    } else if (strcmp(subcommand, "proxybe") == 0) {
        process_proxy_bestats(settings.proxy_ctx, &append_stats, c);
#endif
    } else {
        /* getting here means that the subcommand is either engine specific or
           is invalid. query the engine and see. */
        if (get_stats(subcommand, strlen(subcommand), &append_stats, c)) {
            if (c->stats.buffer == NULL) {
                out_of_memory(c, "SERVER_ERROR out of memory writing stats");
            } else {
                write_and_free(c, c->stats.buffer, c->stats.offset);
                c->stats.buffer = NULL;
            }
        } else {
            out_string(c, "ERROR");
        }
        return;
    }

    /* append terminator and start the transfer */
    append_stats(NULL, 0, NULL, 0, c);

    if (c->stats.buffer == NULL) {
        out_of_memory(c, "SERVER_ERROR out of memory writing stats");
    } else {
        write_and_free(c, c->stats.buffer, c->stats.offset);
        c->stats.buffer = NULL;
    }
}

// slow snprintf for debugging purposes.
static void process_meta_command(conn *c, token_t *tokens, const size_t ntokens) {
    assert(c != NULL);

    if (ntokens < 3 || tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    char *key = tokens[KEY_TOKEN].value;
    size_t nkey = tokens[KEY_TOKEN].length;

    if (ntokens >= 4 && tokens[2].length == 1 && tokens[2].value[0] == 'b') {
        size_t ret = base64_decode((unsigned char *)key, nkey,
                    (unsigned char *)key, nkey);
        if (ret == 0) {
            // failed to decode.
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
        nkey = ret;
    }

    bool overflow; // not used here.
    item *it = limited_get(key, nkey, c->thread, 0, false, DONT_UPDATE, &overflow);
    if (it) {
        mc_resp *resp = c->resp;
        size_t total = 0;
        size_t ret;
        // similar to out_string().
        memcpy(resp->wbuf, "ME ", 3);
        total += 3;
        if (it->it_flags & ITEM_KEY_BINARY) {
            // re-encode from memory rather than copy the original key;
            // to help give confidence that what in memory is what we asked
            // for.
            total += base64_encode((unsigned char *) ITEM_key(it), it->nkey, (unsigned char *)resp->wbuf + total, WRITE_BUFFER_SIZE - total);
        } else {
            memcpy(resp->wbuf + total, ITEM_key(it), it->nkey);
            total += it->nkey;
        }
        resp->wbuf[total] = ' ';
        total++;

        ret = snprintf(resp->wbuf + total, WRITE_BUFFER_SIZE - (it->nkey + 12),
                "exp=%d la=%llu cas=%llu fetch=%s cls=%u size=%lu\r\n",
                (it->exptime == 0) ? -1 : (it->exptime - current_time),
                (unsigned long long)(current_time - it->time),
                (unsigned long long)ITEM_get_cas(it),
                (it->it_flags & ITEM_FETCHED) ? "yes" : "no",
                ITEM_clsid(it),
                (unsigned long) ITEM_ntotal(it));

        item_remove(it);
        resp->wbytes = total + ret;
        resp_add_iov(resp, resp->wbuf, resp->wbytes);
        conn_set_state(c, conn_new_cmd);
    } else {
        out_string(c, "EN");
    }
    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.meta_cmds++;
    pthread_mutex_unlock(&c->thread->stats.mutex);
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

// Text handler requires some custom code around the update code: we directly
// load buffer data into the allocated item, meaning we can drop back to the
// event system for a network read, meaning we lose the request context
// inbetween now and when a store command is finalized.
//
// The meta parsing code was abstracted out into common code so this should
// just be a relatively small wrapper for the text handler.
static void process_mset_command(conn *c, mcp_parser_t *pr, mc_resp *resp) {
    bool has_cas_in = false;
    uint64_t cas_in = 0;
    short comm = 0;
    item *it;
    char *errstr = "CLIENT_ERROR bad command line format";
    c->item = it = process_mset_cmd_start(c->thread, pr, resp, &cas_in, &has_cas_in, &comm);
    if (it == NULL) {
        c->sbytes = pr->vlen;
        conn_set_state(c, conn_swallow);
        return;
    }
    c->cas = has_cas_in ? cas_in : get_cas_id();
    c->cmd = comm;
#ifdef NEED_ALIGN
    if (it->it_flags & ITEM_CHUNKED) {
        c->ritem = ITEM_schunk(it);
    } else {
        c->ritem = ITEM_data(it);
    }
#else
    c->ritem = ITEM_data(it);
#endif
    c->rlbytes = it->nbytes;
    c->cmd = comm;

    // We note tokens into the front of the write buffer, so we can create the
    // final buffer in complete_nread_ascii.
    // FIXME: maybe move this to proto_parser? it's pretty specialized...
    char *p = resp->wbuf;
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
                META_CHAR(p, 'k');
                break;
            case 'c':
                // need to set the cas value post-assignment.
                META_CHAR(p, 'c');
                break;
            case 's':
                // get the final size post-fill
                META_CHAR(p, 's');
                break;
        }
    }

    resp->wbytes = p - resp->wbuf;
    // we don't set up the iov here, instead after complete_nread_ascii when
    // we have the full status code and item data.
    resp->mset_res = true;
    conn_set_state(c, conn_nread);
    return;
error:
    /* swallow the data line */
    c->sbytes = pr->vlen;

    // Note: no errors possible after the item was successfully allocated.
    // So we're just looking at dumping error codes and returning.
    out_errstring(c, errstr);
    // TODO: pass state in? else switching twice meh.
    conn_set_state(c, conn_swallow);
}

static void process_update_command(conn *c, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas) {
    item *it = process_update_cmd_start(c->thread, pr, resp, comm, handle_cas);
    if (it == NULL) {
        conn_set_state(c, conn_swallow);
        c->sbytes = pr->vlen;
        return;
    }
    c->item = it;
#ifdef NEED_ALIGN
    if (it->it_flags & ITEM_CHUNKED) {
        c->ritem = ITEM_schunk(it);
    } else {
        c->ritem = ITEM_data(it);
    }
#else
    c->ritem = ITEM_data(it);
#endif
    c->rlbytes = it->nbytes;
    c->cmd = comm;
    conn_set_state(c, conn_nread);
}

static void process_verbosity_command(conn *c, token_t *tokens, const size_t ntokens) {
    unsigned int level;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (!safe_strtoul(tokens[1].value, (uint32_t*)&level)) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }
    settings.verbose = level > MAX_VERBOSITY_LEVEL ? MAX_VERBOSITY_LEVEL : level;
    out_string(c, "OK");
    return;
}

#ifdef MEMCACHED_DEBUG
static void process_misbehave_command(conn *c) {
    int allowed = 0;

    // try opening new TCP socket
    int i = socket(AF_INET, SOCK_STREAM, 0);
    if (i != -1) {
        allowed++;
        close(i);
    }

    // try executing new commands
    i = system("sleep 0");
    if (i != -1) {
        allowed++;
    }

    if (allowed) {
        out_string(c, "ERROR");
    } else {
        out_string(c, "OK");
    }
}

static void process_debugtime_command(conn *c, token_t *tokens, const size_t ntokens) {
    if (strcmp(tokens[1].value, "p") == 0) {
        if (!is_paused) {
            is_paused = true;
        }
    } else if (strcmp(tokens[1].value, "r") == 0) {
        if (is_paused) {
            is_paused = false;
        }
    } else {
        int64_t time_delta = 0;
        if (!safe_strtoll(tokens[1].value, &time_delta)) {
            out_string(c, "ERROR");
            return;
        }
        delta += time_delta;
        current_time += delta;
    }
    out_string(c, "OK");
}

static void process_debugitem_command(conn *c, token_t *tokens, const size_t ntokens) {
    if (strcmp(tokens[1].value, "lock") == 0) {
        uint32_t hv = hash(tokens[2].value, tokens[2].length);
        item_lock(hv);
    } else if (strcmp(tokens[1].value, "unlock") == 0) {
        uint32_t hv = hash(tokens[2].value, tokens[2].length);
        item_unlock(hv);
    } else if (strcmp(tokens[1].value, "ref") == 0) {
        // intentionally leak a reference.
        item *it = item_get(tokens[2].value, tokens[2].length, c->thread, DONT_UPDATE);
        if (it == NULL) {
            out_string(c, "MISS");
            return;
        }
    } else if (strcmp(tokens[1].value, "unref") == 0) {
        // double unlink. debugger must have already ref'ed it or this
        // underflows.
        item *it = item_get(tokens[2].value, tokens[2].length, c->thread, DONT_UPDATE);
        if (it == NULL) {
            out_string(c, "MISS");
            return;
        }
        do_item_remove(it);
        do_item_remove(it);
    } else {
        out_string(c, "ERROR");
        return;
    }
    out_string(c, "OK");
}
#endif

static void process_slabs_automove_command(conn *c, token_t *tokens, const size_t ntokens) {
    unsigned int level;
    double ratio;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (strcmp(tokens[2].value, "ratio") == 0) {
        if (ntokens < 5 || !safe_strtod(tokens[3].value, &ratio)) {
            out_string(c, "ERROR");
            return;
        }
        // TODO: settings needs an overhaul... no locks/etc.
        settings.slab_automove_ratio = ratio;
        settings.slab_automove_version++;
    } else if (strcmp(tokens[2].value, "freeratio") == 0) {
        if (ntokens < 5 || !safe_strtod(tokens[3].value, &ratio)) {
            out_string(c, "ERROR");
            return;
        }
        settings.slab_automove_freeratio = ratio;
        settings.slab_automove_version++;
    } else if (strcmp(tokens[2].value, "window") == 0) {
        if (ntokens < 5 || !safe_strtoul(tokens[3].value, (uint32_t*)&level)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        settings.slab_automove_window = level;
        settings.slab_automove_version++;
    } else {
        if (!safe_strtoul(tokens[2].value, (uint32_t*)&level)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
        if (level == 0) {
            settings.slab_automove = 0;
        } else if (level == 1 || level == 2) {
            settings.slab_automove = level;
        } else {
            out_string(c, "ERROR");
            return;
        }
    }
    out_string(c, "OK");
    return;
}

/* TODO: decide on syntax for sampling? */
static void process_watch_command(conn *c, token_t *tokens, const size_t ntokens) {
    uint16_t f = 0;
    int x;
    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);
    if (!settings.watch_enabled) {
        out_string(c, "CLIENT_ERROR watch commands not allowed");
        return;
    }

    if (resp_has_stack(c)) {
        out_string(c, "ERROR cannot pipeline other commands before watch");
        return;
    }

    if (ntokens > 2) {
        for (x = COMMAND_TOKEN + 1; x < ntokens - 1; x++) {
            if ((strcmp(tokens[x].value, "rawcmds") == 0)) {
                f |= LOG_RAWCMDS;
            } else if ((strcmp(tokens[x].value, "evictions") == 0)) {
                f |= LOG_EVICTIONS;
            } else if ((strcmp(tokens[x].value, "fetchers") == 0)) {
                f |= LOG_FETCHERS;
            } else if ((strcmp(tokens[x].value, "mutations") == 0)) {
                f |= LOG_MUTATIONS;
            } else if ((strcmp(tokens[x].value, "sysevents") == 0)) {
                f |= LOG_SYSEVENTS;
            } else if ((strcmp(tokens[x].value, "connevents") == 0)) {
                f |= LOG_CONNEVENTS;
            } else if ((strcmp(tokens[x].value, "proxyreqs") == 0)) {
                f |= LOG_PROXYREQS;
            } else if ((strcmp(tokens[x].value, "proxyevents") == 0)) {
                f |= LOG_PROXYEVENTS;
            } else if ((strcmp(tokens[x].value, "proxyuser") == 0)) {
                f |= LOG_PROXYUSER;
            } else if ((strcmp(tokens[x].value, "deletions") == 0)) {
                f |= LOG_DELETIONS;
            } else {
                out_string(c, "ERROR");
                return;
            }
        }
    } else {
        f |= LOG_FETCHERS;
    }

    switch(logger_add_watcher(c, c->sfd, f)) {
        case LOGGER_ADD_WATCHER_TOO_MANY:
            out_string(c, "WATCHER_TOO_MANY log watcher limit reached");
            break;
        case LOGGER_ADD_WATCHER_FAILED:
            out_string(c, "WATCHER_FAILED failed to add log watcher");
            break;
        case LOGGER_ADD_WATCHER_OK:
            conn_set_state(c, conn_watch);
            event_del(&c->event);
            break;
    }
}

static void process_memlimit_command(conn *c, token_t *tokens, const size_t ntokens) {
    uint32_t memlimit;
    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (!safe_strtoul(tokens[1].value, &memlimit)) {
        out_string(c, "ERROR");
    } else {
        if (memlimit < 8) {
            out_string(c, "MEMLIMIT_TOO_SMALL cannot set maxbytes to less than 8m");
        } else {
            if (memlimit > 1000000000) {
                out_string(c, "MEMLIMIT_ADJUST_FAILED input value is megabytes not bytes");
            } else if (slabs_adjust_mem_limit((size_t) memlimit * 1024 * 1024)) {
                if (settings.verbose > 0) {
                    fprintf(stderr, "maxbytes adjusted to %llum\n", (unsigned long long)memlimit);
                }

                out_string(c, "OK");
            } else {
                out_string(c, "MEMLIMIT_ADJUST_FAILED out of bounds or unable to adjust");
            }
        }
    }
}

static void process_lru_command(conn *c, token_t *tokens, const size_t ntokens) {
    uint32_t pct_hot;
    uint32_t pct_warm;
    double hot_factor;
    int32_t ttl;
    double factor;

    set_noreply_maybe(c, tokens, ntokens);

    if (strcmp(tokens[1].value, "tune") == 0 && ntokens >= 7) {
        if (!safe_strtoul(tokens[2].value, &pct_hot) ||
            !safe_strtoul(tokens[3].value, &pct_warm) ||
            !safe_strtod(tokens[4].value, &hot_factor) ||
            !safe_strtod(tokens[5].value, &factor)) {
            out_string(c, "ERROR");
        } else {
            if (pct_hot + pct_warm > 80) {
                out_string(c, "ERROR hot and warm pcts must not exceed 80");
            } else if (factor <= 0 || hot_factor <= 0) {
                out_string(c, "ERROR hot/warm age factors must be greater than 0");
            } else {
                settings.hot_lru_pct = pct_hot;
                settings.warm_lru_pct = pct_warm;
                settings.hot_max_factor = hot_factor;
                settings.warm_max_factor = factor;
                out_string(c, "OK");
            }
        }
    } else if (strcmp(tokens[1].value, "mode") == 0 && ntokens >= 4 &&
               settings.lru_maintainer_thread) {
        if (strcmp(tokens[2].value, "flat") == 0) {
            settings.lru_segmented = false;
            out_string(c, "OK");
        } else if (strcmp(tokens[2].value, "segmented") == 0) {
            settings.lru_segmented = true;
            out_string(c, "OK");
        } else {
            out_string(c, "ERROR");
        }
    } else if (strcmp(tokens[1].value, "temp_ttl") == 0 && ntokens >= 4 &&
               settings.lru_maintainer_thread) {
        if (!safe_strtol(tokens[2].value, &ttl)) {
            out_string(c, "ERROR");
        } else {
            if (ttl < 0) {
                settings.temp_lru = false;
            } else {
                settings.temp_lru = true;
                settings.temporary_ttl = ttl;
            }
            out_string(c, "OK");
        }
    } else {
        out_string(c, "ERROR");
    }
}
#ifdef EXTSTORE
static void process_extstore_command(conn *c, token_t *tokens, const size_t ntokens) {
    set_noreply_maybe(c, tokens, ntokens);
    bool ok = true;
    if (ntokens < 4) {
        ok = false;
    } else if (strcmp(tokens[1].value, "free_memchunks") == 0 && ntokens > 4) {
        // setting is deprecated and ignored, but accepted for backcompat
        unsigned int clsid = 0;
        unsigned int limit = 0;
        if (!safe_strtoul(tokens[2].value, &clsid) ||
                !safe_strtoul(tokens[3].value, &limit)) {
            ok = false;
        } else {
            if (clsid < MAX_NUMBER_OF_SLAB_CLASSES) {
                ok = true;
            } else {
                ok = false;
            }
        }
    } else if (strcmp(tokens[1].value, "item_size") == 0) {
        if (safe_strtoul(tokens[2].value, &settings.ext_item_size)) {
            settings.slab_automove_version++;
        } else {
            ok = false;
        }
    } else if (strcmp(tokens[1].value, "item_age") == 0) {
        if (!safe_strtoul(tokens[2].value, &settings.ext_item_age))
            ok = false;
    } else if (strcmp(tokens[1].value, "low_ttl") == 0) {
        if (!safe_strtoul(tokens[2].value, &settings.ext_low_ttl))
            ok = false;
    } else if (strcmp(tokens[1].value, "recache_rate") == 0) {
        if (!safe_strtoul(tokens[2].value, &settings.ext_recache_rate))
            ok = false;
    } else if (strcmp(tokens[1].value, "compact_under") == 0) {
        if (!safe_strtoul(tokens[2].value, &settings.ext_compact_under))
            ok = false;
    } else if (strcmp(tokens[1].value, "drop_under") == 0) {
        if (!safe_strtoul(tokens[2].value, &settings.ext_drop_under))
            ok = false;
    } else if (strcmp(tokens[1].value, "max_sleep") == 0) {
        if (!safe_strtoul(tokens[2].value, &settings.ext_max_sleep))
            ok = false;
    } else if (strcmp(tokens[1].value, "max_frag") == 0) {
        if (!safe_strtod(tokens[2].value, &settings.ext_max_frag))
            ok = false;
    } else if (strcmp(tokens[1].value, "drop_unread") == 0) {
        unsigned int v;
        if (!safe_strtoul(tokens[2].value, &v)) {
            ok = false;
        } else {
            settings.ext_drop_unread = v == 0 ? false : true;
        }
    } else {
        ok = false;
    }
    if (!ok) {
        out_string(c, "ERROR");
    } else {
        out_string(c, "OK");
    }
}
#endif
static void process_flush_all_command(conn *c, token_t *tokens, const size_t ntokens) {
    int32_t exptime = 0;
    rel_time_t new_oldest = 0;

    set_noreply_maybe(c, tokens, ntokens);

    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.flush_cmds++;
    pthread_mutex_unlock(&c->thread->stats.mutex);

    if (!settings.flush_enabled) {
        // flush_all is not allowed but we log it on stats
        out_string(c, "CLIENT_ERROR flush_all not allowed");
        return;
    }

    if (ntokens != (c->resp->noreply ? 3 : 2)) {
        if (!safe_strtol(tokens[1].value, &exptime)) {
            out_string(c, "CLIENT_ERROR invalid exptime argument");
            return;
        }
    }

    /*
      If exptime is zero realtime() would return zero too, and
      realtime(exptime) - 1 would overflow to the max unsigned
      value.  So we process exptime == 0 the same way we do when
      no delay is given at all.
    */
    if (exptime > 0) {
        new_oldest = realtime(exptime) - 1;
    } else { /* exptime == 0 */
        new_oldest = current_time - 1;
    }

    settings.oldest_live = new_oldest;
    item_flush_expired();
    out_string(c, "OK");
}

static void process_version_command(conn *c) {
    out_string(c, "VERSION " VERSION);
}

static void process_quit_command(conn *c) {
    conn_set_state(c, conn_mwrite);
    c->close_after_write = true;
    c->close_reason = NORMAL_CLOSE;
}

static void process_shutdown_command(conn *c, token_t *tokens, const size_t ntokens) {
    if (!settings.shutdown_command) {
        out_string(c, "ERROR: shutdown not enabled");
        return;
    }

    if (ntokens == 2) {
        c->close_reason = SHUTDOWN_CLOSE;
        conn_set_state(c, conn_closing);
        raise(SIGINT);
    } else if (ntokens == 3 && strcmp(tokens[SUBCOMMAND_TOKEN].value, "graceful") == 0) {
        c->close_reason = SHUTDOWN_CLOSE;
        conn_set_state(c, conn_closing);
        raise(SIGUSR1);
    } else {
        out_string(c, "CLIENT_ERROR invalid shutdown mode");
    }
}

static void process_slabs_command(conn *c, token_t *tokens, const size_t ntokens) {
    if (ntokens == 5 && strcmp(tokens[COMMAND_TOKEN + 1].value, "reassign") == 0) {
        int src, dst, rv;

        if (settings.slab_reassign == false) {
            out_string(c, "CLIENT_ERROR slab reassignment disabled");
            return;
        }

        if (! (safe_strtol(tokens[2].value, (int32_t*)&src)
               && safe_strtol(tokens[3].value, (int32_t*)&dst))) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        rv = slabs_reassign(settings.slab_rebal, src, dst, SLABS_REASSIGN_ALLOW_EVICTIONS);
        switch (rv) {
        case REASSIGN_OK:
            out_string(c, "OK");
            break;
        case REASSIGN_RUNNING:
            out_string(c, "BUSY currently processing reassign request");
            break;
        case REASSIGN_BADCLASS:
            out_string(c, "BADCLASS invalid src or dst class id");
            break;
        case REASSIGN_NOSPARE:
            out_string(c, "NOSPARE source class has no spare pages");
            break;
        case REASSIGN_SRC_DST_SAME:
            out_string(c, "SAME src and dst class are identical");
            break;
        }
        return;
    } else if (ntokens >= 4 &&
        (strcmp(tokens[COMMAND_TOKEN + 1].value, "automove") == 0)) {
        process_slabs_automove_command(c, tokens, ntokens);
    } else {
        out_string(c, "ERROR");
    }
}

static void process_lru_crawler_command(conn *c, token_t *tokens, const size_t ntokens) {
    if (ntokens == 4 && strcmp(tokens[COMMAND_TOKEN + 1].value, "crawl") == 0) {
        int rv;
        if (settings.lru_crawler == false) {
            out_string(c, "CLIENT_ERROR lru crawler disabled");
            return;
        }

        rv = lru_crawler_crawl(tokens[2].value, CRAWLER_EXPIRED, NULL, 0,
                settings.lru_crawler_tocrawl);
        switch(rv) {
        case CRAWLER_OK:
            out_string(c, "OK");
            break;
        case CRAWLER_RUNNING:
            out_string(c, "BUSY currently processing crawler request");
            break;
        case CRAWLER_BADCLASS:
            out_string(c, "BADCLASS invalid class id");
            break;
        case CRAWLER_NOTSTARTED:
            out_string(c, "NOTSTARTED no items to crawl");
            break;
        case CRAWLER_ERROR:
            out_string(c, "ERROR an unknown error happened");
            break;
        }
        return;
    } else if (ntokens == 4 && strcmp(tokens[COMMAND_TOKEN + 1].value, "metadump") == 0) {
        if (settings.lru_crawler == false) {
            out_string(c, "CLIENT_ERROR lru crawler disabled");
            return;
        }
        if (!settings.dump_enabled) {
            out_string(c, "ERROR metadump not allowed");
            return;
        }
        if (resp_has_stack(c)) {
            out_string(c, "ERROR cannot pipeline other commands before metadump");
            return;
        }

        int rv = lru_crawler_crawl(tokens[2].value, CRAWLER_METADUMP,
                c, c->sfd, LRU_CRAWLER_CAP_REMAINING);
        switch(rv) {
            case CRAWLER_OK:
                // TODO: documentation says this string is returned, but
                // it never was before. We never switch to conn_write so
                // this o_s call never worked. Need to talk to users and
                // decide if removing the OK from docs is fine.
                //out_string(c, "OK");
                // TODO: Don't reuse conn_watch here.
                conn_set_state(c, conn_watch);
                event_del(&c->event);
                break;
            case CRAWLER_RUNNING:
                out_string(c, "BUSY currently processing crawler request");
                break;
            case CRAWLER_BADCLASS:
                out_string(c, "BADCLASS invalid class id");
                break;
            case CRAWLER_NOTSTARTED:
                out_string(c, "NOTSTARTED no items to crawl");
                break;
            case CRAWLER_ERROR:
                out_string(c, "ERROR an unknown error happened");
                break;
        }
        return;
    } else if (ntokens == 4 && strcmp(tokens[COMMAND_TOKEN + 1].value, "mgdump") == 0) {
        if (settings.lru_crawler == false) {
            out_string(c, "CLIENT_ERROR lru crawler disabled");
            return;
        }
        if (!settings.dump_enabled) {
            out_string(c, "ERROR key dump not allowed");
            return;
        }
        if (resp_has_stack(c)) {
            out_string(c, "ERROR cannot pipeline other commands before mgdump");
            return;
        }

        int rv = lru_crawler_crawl(tokens[2].value, CRAWLER_MGDUMP,
                c, c->sfd, LRU_CRAWLER_CAP_REMAINING);
        switch(rv) {
            case CRAWLER_OK:
                conn_set_state(c, conn_watch);
                event_del(&c->event);
                break;
            case CRAWLER_RUNNING:
                out_string(c, "BUSY currently processing crawler request");
                break;
            case CRAWLER_BADCLASS:
                out_string(c, "BADCLASS invalid class id");
                break;
            case CRAWLER_NOTSTARTED:
                out_string(c, "NOTSTARTED no items to crawl");
                break;
            case CRAWLER_ERROR:
                out_string(c, "ERROR an unknown error happened");
                break;
        }
        return;
    } else if (ntokens == 4 && strcmp(tokens[COMMAND_TOKEN + 1].value, "tocrawl") == 0) {
        uint32_t tocrawl;
         if (!safe_strtoul(tokens[2].value, &tocrawl)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
        settings.lru_crawler_tocrawl = tocrawl;
        out_string(c, "OK");
        return;
    } else if (ntokens == 4 && strcmp(tokens[COMMAND_TOKEN + 1].value, "sleep") == 0) {
        uint32_t tosleep;
        if (!safe_strtoul(tokens[2].value, &tosleep)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
        if (tosleep > 1000000) {
            out_string(c, "CLIENT_ERROR sleep must be one second or less");
            return;
        }
        settings.lru_crawler_sleep = tosleep;
        out_string(c, "OK");
        return;
    } else if (ntokens == 3) {
        if ((strcmp(tokens[COMMAND_TOKEN + 1].value, "enable") == 0)) {
            if (start_item_crawler_thread() == 0) {
                out_string(c, "OK");
            } else {
                out_string(c, "ERROR failed to start lru crawler thread");
            }
        } else if ((strcmp(tokens[COMMAND_TOKEN + 1].value, "disable") == 0)) {
            if (stop_item_crawler_thread(CRAWLER_NOWAIT) == 0) {
                out_string(c, "OK");
            } else {
                out_string(c, "ERROR failed to stop lru crawler thread");
            }
        } else {
            out_string(c, "ERROR");
        }
        return;
    } else {
        out_string(c, "ERROR");
    }
}
#ifdef TLS
static void process_refresh_certs_command(conn *c, token_t *tokens, const size_t ntokens) {
    set_noreply_maybe(c, tokens, ntokens);
    char *errmsg = NULL;
    if (refresh_certs(&errmsg)) {
        out_string(c, "OK");
    } else {
        write_and_free(c, errmsg, strlen(errmsg));
    }
    return;
}
#endif

// TODO: pipelined commands are incompatible with shifting connections to a
// side thread. Given this only happens in two instances (watch and
// lru_crawler metadump) it should be fine for things to bail. It _should_ be
// unusual for these commands.
// This is hard to fix since tokenize_command() mutilates the read buffer, so
// we can't drop out and back in again.
// Leaving this note here to spend more time on a fix when necessary, or if an
// opportunity becomes obvious.
static void _process_command_ascii(conn *c, char *command) {

    token_t tokens[MAX_TOKENS];
    size_t ntokens;

    assert(c != NULL);

    MEMCACHED_PROCESS_COMMAND_START(c->sfd, c->rcurr, c->rbytes);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d %s\n", c->sfd, command);

    /*
     * for commands set/add/replace, we build an item and read the data
     * directly into it, then continue in nread_complete().
     */

    c->thread->cur_sfd = c->sfd; // cuddle sfd for logging.
    ntokens = tokenize_command(command, tokens, MAX_TOKENS);
    // All commands need a minimum of two tokens: cmd and NULL finalizer
    // There are also no valid commands shorter than two bytes.
    if (ntokens < 2 || tokens[COMMAND_TOKEN].length < 2) {
        out_string(c, "ERROR");
        return;
    }

    // Meta commands are all 2-char in length.
    char first = tokens[COMMAND_TOKEN].value[0];
    if (first == 'm' && tokens[COMMAND_TOKEN].length == 2) {
        switch (tokens[COMMAND_TOKEN].value[1]) {
            case 'e':
                process_meta_command(c, tokens, ntokens);
                break;
            default:
                out_string(c, "ERROR");
                break;
        }
    } else if (first == 's') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "stats") == 0) {

            process_stat(c, tokens, ntokens);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "shutdown") == 0) {

            process_shutdown_command(c, tokens, ntokens);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "slabs") == 0) {

            process_slabs_command(c, tokens, ntokens);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 'c') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "cache_memlimit") == 0) {

            WANT_TOKENS_OR(ntokens, 3, 4);
            process_memlimit_command(c, tokens, ntokens);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 'd') {
#ifdef MEMCACHED_DEBUG
       if (strcmp(tokens[COMMAND_TOKEN].value, "debugtime") == 0) {
            WANT_TOKENS_MIN(ntokens, 2);
            process_debugtime_command(c, tokens, ntokens);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "debugitem") == 0) {
            WANT_TOKENS_MIN(ntokens, 2);
            process_debugitem_command(c, tokens, ntokens);
        } else {
            out_string(c, "ERROR");
        }
#else
       out_string(c, "ERROR");
#endif
    } else if (strcmp(tokens[COMMAND_TOKEN].value, "flush_all") == 0) {

        WANT_TOKENS(ntokens, 2, 4);
        process_flush_all_command(c, tokens, ntokens);

    } else if (strcmp(tokens[COMMAND_TOKEN].value, "version") == 0) {

        process_version_command(c);

    } else if (strcmp(tokens[COMMAND_TOKEN].value, "quit") == 0) {

        process_quit_command(c);

    } else if (strcmp(tokens[COMMAND_TOKEN].value, "lru_crawler") == 0) {

        process_lru_crawler_command(c, tokens, ntokens);

    } else if (strcmp(tokens[COMMAND_TOKEN].value, "watch") == 0) {

        process_watch_command(c, tokens, ntokens);

    } else if (strcmp(tokens[COMMAND_TOKEN].value, "verbosity") == 0) {
        WANT_TOKENS_OR(ntokens, 3, 4);
        process_verbosity_command(c, tokens, ntokens);
    } else if (strcmp(tokens[COMMAND_TOKEN].value, "lru") == 0) {
        WANT_TOKENS_MIN(ntokens, 3);
        process_lru_command(c, tokens, ntokens);
#ifdef MEMCACHED_DEBUG
    // commands which exist only for testing the memcached's security protection
    } else if (strcmp(tokens[COMMAND_TOKEN].value, "misbehave") == 0) {
        process_misbehave_command(c);
#endif
#ifdef EXTSTORE
    } else if (strcmp(tokens[COMMAND_TOKEN].value, "extstore") == 0) {
        WANT_TOKENS_MIN(ntokens, 3);
        process_extstore_command(c, tokens, ntokens);
#endif
#ifdef TLS
    } else if (strcmp(tokens[COMMAND_TOKEN].value, "refresh_certs") == 0) {
        process_refresh_certs_command(c, tokens, ntokens);
#endif
    } else {
        if (strncmp(tokens[ntokens - 2].value, "HTTP/", 5) == 0) {
            conn_set_state(c, conn_closing);
        } else {
            out_string(c, "ERROR");
        }
    }
    return;
}

void process_command_ascii(conn *c, char *command, char *el) {
    mcp_parser_t pr = {0};
    // Prep the response object for this query.
    if (!resp_start(c)) {
        conn_set_state(c, conn_closing);
        return;
    }

    size_t cmdlen = el - command + 1;
    int ret = process_request(&pr, command, cmdlen);
    if (ret == PROCESS_REQUEST_OK) {
        LIBEVENT_THREAD *t = c->thread;
        mc_resp *resp = c->resp;
        bool handled = false;
        switch (pr.command) {
            case CMD_MA:
                process_marithmetic_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                handled = true;
                break;
             case CMD_MD:
                process_mdelete_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                handled = true;
                break;
             case CMD_MG:
                process_mget_cmd(t, &pr, resp, storage_get_item);
                if (resp->io_pending) {
                    resp->io_pending->c = c;
                    conn_resp_suspend(c, resp);
                } else {
                    conn_set_state(c, conn_new_cmd);
                }
                handled = true;
                break;
            case CMD_MN:
                out_string(c, "MN");
                // mn command forces immediate writeback flush.
                conn_set_state(c, conn_mwrite);
                handled = true;
                break;
             case CMD_MS:
                process_mset_command(c, &pr, resp);
                handled = true;
                break;
            case CMD_GET:
                process_get_command(c, t, &pr, storage_get_item, _NO_CAS, _NO_TOUCH);
                handled = true;
                break;
            case CMD_GETS:
                process_get_command(c, t, &pr, storage_get_item, _DO_CAS, _NO_TOUCH);
                handled = true;
                break;
            case CMD_GAT:
                process_get_command(c, t, &pr, storage_get_item, _NO_CAS, _DO_TOUCH);
                handled = true;
                break;
            case CMD_GATS:
                process_get_command(c, t, &pr, storage_get_item, _DO_CAS, _DO_TOUCH);
                handled = true;
                break;
             case CMD_DELETE:
                process_delete_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                handled = true;
                break;
             case CMD_INCR:
                process_arithmetic_cmd(t, &pr, resp, true);
                conn_set_state(c, conn_new_cmd);
                handled = true;
                break;
             case CMD_DECR:
                process_arithmetic_cmd(t, &pr, resp, false);
                conn_set_state(c, conn_new_cmd);
                handled = true;
                break;
             case CMD_TOUCH:
                process_touch_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                handled = true;
                break;
             case CMD_SET:
                process_update_command(c, &pr, resp, NREAD_SET, false);
                handled = true;
                break;
            case CMD_ADD:
                process_update_command(c, &pr, resp, NREAD_ADD, false);
                handled = true;
                break;
            case CMD_APPEND:
                process_update_command(c, &pr, resp, NREAD_APPEND, false);
                handled = true;
                break;
            case CMD_PREPEND:
                process_update_command(c, &pr, resp, NREAD_PREPEND, false);
                handled = true;
                break;
            case CMD_REPLACE:
                process_update_command(c, &pr, resp, NREAD_REPLACE, false);
                handled = true;
                break;
            case CMD_CAS:
                process_update_command(c, &pr, resp, NREAD_CAS, true);
                handled = true;
                break;
        }

        if (handled)
            return;
    } else if (ret == PROCESS_REQUEST_BAD_FORMAT) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if ((el - command) > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    // Fallback parser.
    _process_command_ascii(c, command);
}
