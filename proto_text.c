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
#include "authfile.h"
#include "storage.h"
#include "base64.h"
#ifdef TLS
#include "tls.h"
#endif
#include <string.h>
#include <stdlib.h>

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

typedef struct token_s {
    char *value;
    size_t length;
} token_t;

static void _finalize_mset(conn *c, enum store_item_type ret) {
    mc_resp *resp = c->resp;
    item *it = c->item;
    conn_set_state(c, conn_new_cmd);

    // information about the response line has been stashed in wbuf.
    char *p = resp->wbuf + resp->wbytes;
    char *end = p; // end of the stashed data portion.

    switch (ret) {
    case STORED:
      if (settings.meta_response_old) {
          memcpy(p, "OK", 2);
      } else {
          memcpy(p, "HD", 2);
      }
      // Only place noreply is used for meta cmds is a nominal response.
      if (c->noreply) {
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
      c->noreply = false;
      out_string(c, "SERVER_ERROR Unhandled storage type.");
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
                p = itoa_u64(c->cas, p);
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

    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.slab_stats[ITEM_clsid(it)].set_cmds++;
    pthread_mutex_unlock(&c->thread->stats.mutex);

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
        if (c->mset_res) {
            c->noreply = false;
        }
        out_string(c, "CLIENT_ERROR bad data chunk");
    } else {
      ret = store_item(it, comm, c);

#ifdef ENABLE_DTRACE
      uint64_t cas = ITEM_get_cas(it);
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

      if (c->mset_res) {
          _finalize_mset(c, ret);
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

    c->set_stale = false; /* force flag to be off just in case */
    c->mset_res = false;
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
    if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    assert(cont <= (c->rcurr + c->rbytes));

    c->last_cmd_time = current_time;
    process_command_ascii(c, c->rcurr);

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
        c->noreply = true;
    }
    return c->noreply;
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
        p = itoa_u32(*((uint32_t *) ITEM_suffix(it)), p);
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

/* ntokens is overwritten here... shrug.. */
static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas, bool should_touch) {
    char *key;
    size_t nkey;
    item *it;
    token_t *key_token = &tokens[KEY_TOKEN];
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    bool fail_length = false;
    assert(c != NULL);
    mc_resp *resp = c->resp;

    if (should_touch) {
        // For get and touch commands, use first token as exptime
        if (!safe_strtol(tokens[1].value, &exptime_int)) {
            out_string(c, "CLIENT_ERROR invalid exptime argument");
            return;
        }
        key_token++;
        exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));
    }

    do {
        while(key_token->length != 0) {
            bool overflow; // not used here.
            key = key_token->value;
            nkey = key_token->length;

            if (nkey > KEY_MAX_LENGTH) {
                fail_length = true;
                goto stop;
            }

            it = limited_get(key, nkey, c, exptime, should_touch, DO_UPDATE, &overflow);
            if (settings.detail_enabled) {
                stats_prefix_record_get(key, nkey, NULL != it);
            }
            if (it) {
                /*
                 * Construct the response. Each hit adds three elements to the
                 * outgoing data list:
                 *   "VALUE "
                 *   key
                 *   " " + flags + " " + data length + "\r\n" + data (with \r\n)
                 */

                {
                  MEMCACHED_COMMAND_GET(c->sfd, ITEM_key(it), it->nkey,
                                        it->nbytes, ITEM_get_cas(it));
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
                      if (storage_get_item(c, it, resp) != 0) {
                          pthread_mutex_lock(&c->thread->stats.mutex);
                          c->thread->stats.get_oom_extstore++;
                          pthread_mutex_unlock(&c->thread->stats.mutex);

                          item_remove(it);
                          goto stop;
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

                if (settings.verbose > 1) {
                    int ii;
                    fprintf(stderr, ">%d sending key ", c->sfd);
                    for (ii = 0; ii < it->nkey; ++ii) {
                        fprintf(stderr, "%c", key[ii]);
                    }
                    fprintf(stderr, "\n");
                }

                /* item_get() has incremented it->refcount for us */
                pthread_mutex_lock(&c->thread->stats.mutex);
                if (should_touch) {
                    c->thread->stats.touch_cmds++;
                    c->thread->stats.slab_stats[ITEM_clsid(it)].touch_hits++;
                } else {
                    c->thread->stats.lru_hits[it->slabs_clsid]++;
                    c->thread->stats.get_cmds++;
                }
                pthread_mutex_unlock(&c->thread->stats.mutex);
#ifdef EXTSTORE
                /* If ITEM_HDR, an io_wrap owns the reference. */
                if ((it->it_flags & ITEM_HDR) == 0) {
                    resp->item = it;
                }
#else
                resp->item = it;
#endif
            } else {
                pthread_mutex_lock(&c->thread->stats.mutex);
                if (should_touch) {
                    c->thread->stats.touch_cmds++;
                    c->thread->stats.touch_misses++;
                } else {
                    c->thread->stats.get_misses++;
                    c->thread->stats.get_cmds++;
                }
                MEMCACHED_COMMAND_GET(c->sfd, key, nkey, -1, 0);
                pthread_mutex_unlock(&c->thread->stats.mutex);
            }

            key_token++;
            if (key_token->length != 0) {
                if (!resp_start(c)) {
                    goto stop;
                }
                resp = c->resp;
            }
        }

        /*
         * If the command string hasn't been fully processed, get the next set
         * of tokens.
         */
        if (key_token->value != NULL) {
            ntokens = tokenize_command(key_token->value, tokens, MAX_TOKENS);
            key_token = tokens;
            if (!resp_start(c)) {
                goto stop;
            }
            resp = c->resp;
        }
    } while(key_token->value != NULL);
stop:

    if (settings.verbose > 1)
        fprintf(stderr, ">%d END\n", c->sfd);

    /*
        If the loop was terminated because of out-of-memory, it is not
        reliable to add END\r\n to the buffer, because it might not end
        in \r\n. So we send SERVER_ERROR instead.
    */
    if (key_token->value != NULL) {
        // Kill any stacked responses we had.
        conn_release_items(c);
        // Start a new response object for the error message.
        if (!resp_start(c)) {
            // severe out of memory error.
            conn_set_state(c, conn_closing);
            return;
        }
        if (fail_length) {
            out_string(c, "CLIENT_ERROR bad command line format");
        } else {
            out_of_memory(c, "SERVER_ERROR out of memory writing get response");
        }
    } else {
        // Tag the end token onto the most recent response object.
        resp_add_iov(resp, "END\r\n", 5);
        conn_set_state(c, conn_mwrite);
    }
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
        process_proxy_stats(&append_stats, c);
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
    item *it = limited_get(key, nkey, c, 0, false, DONT_UPDATE, &overflow);
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
                (it->exptime == 0) ? -1 : (current_time - it->exptime),
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
    unsigned int new_ttl :1;
    unsigned int key_binary:1;
    char mode; // single character mode switch, common to ms/ma
    rel_time_t exptime;
    rel_time_t autoviv_exptime;
    rel_time_t recache_time;
    uint32_t client_flags;
    uint64_t req_cas_id;
    uint64_t delta; // ma
    uint64_t initial; // ma
};

static int _meta_flag_preparse(token_t *tokens, const size_t start,
        struct _meta_flags *of, char **errstr) {
    unsigned int i;
    size_t ret;
    int32_t tmp_int;
    uint8_t seen[127] = {0};
    // Start just past the key token. Look at first character of each token.
    for (i = start; tokens[i].length != 0; i++) {
        uint8_t o = (uint8_t)tokens[i].value[0];
        // zero out repeat flags so we don't over-parse for return data.
        if (o >= 127 || seen[o] != 0) {
            *errstr = "CLIENT_ERROR duplicate flag";
            return -1;
        }
        seen[o] = 1;
        switch (o) {
            // base64 decode the key in-place, as the binary should always be
            // shorter and the conversion code buffers bytes.
            case 'b':
                ret = base64_decode((unsigned char *)tokens[KEY_TOKEN].value, tokens[KEY_TOKEN].length,
                            (unsigned char *)tokens[KEY_TOKEN].value, tokens[KEY_TOKEN].length);
                if (ret == 0) {
                    // Failed to decode
                    *errstr = "CLIENT_ERROR error decoding key";
                    of->has_error = 1;
                }
                tokens[KEY_TOKEN].length = ret;
                of->key_binary = 1;
                break;
            /* Negative exptimes can underflow and end up immortal. realtime() will
               immediately expire values that are greater than REALTIME_MAXDELTA, but less
               than process_started, so lets aim for that. */
            case 'N':
                of->locked = 1;
                of->vivify = 1;
                if (!safe_strtol(tokens[i].value+1, &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->autoviv_exptime = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                }
                break;
            case 'T':
                of->locked = 1;
                if (!safe_strtol(tokens[i].value+1, &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->exptime = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                    of->new_ttl = true;
                }
                break;
            case 'R':
                of->locked = 1;
                if (!safe_strtol(tokens[i].value+1, &tmp_int)) {
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
            // mset-related.
            case 'F':
                if (!safe_strtoul(tokens[i].value+1, &of->client_flags)) {
                    of->has_error = true;
                }
                break;
            case 'C': // mset, mdelete, marithmetic
                if (!safe_strtoull(tokens[i].value+1, &of->req_cas_id)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = true;
                } else {
                    of->has_cas = true;
                }
                break;
            case 'M': // mset and marithmetic mode switch
                if (tokens[i].length != 2) {
                    *errstr = "CLIENT_ERROR incorrect length for M token";
                    of->has_error = 1;
                } else {
                    of->mode = tokens[i].value[1];
                }
                break;
            case 'J': // marithmetic initial value
                if (!safe_strtoull(tokens[i].value+1, &of->initial)) {
                    *errstr = "CLIENT_ERROR invalid numeric initial value";
                    of->has_error = 1;
                }
                break;
            case 'D': // marithmetic delta value
                if (!safe_strtoull(tokens[i].value+1, &of->delta)) {
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

static void process_mget_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    item *it;
    unsigned int i = 0;
    struct _meta_flags of = {0}; // option bitflags.
    uint32_t hv; // cached hash value for unlocking an item.
    bool failed = false;
    bool item_created = false;
    bool won_token = false;
    bool ttl_set = false;
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(c != NULL);
    mc_resp *resp = c->resp;
    char *p = resp->wbuf;

    WANT_TOKENS_MIN(ntokens, 3);

    // FIXME: do we move this check to after preparse?
    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_errstring(c, "CLIENT_ERROR bad command line format");
        return;
    }

    // NOTE: final token has length == 0.
    // KEY_TOKEN == 1. 0 is command.

    if (ntokens == 3) {
        // TODO: any way to fix this?
        out_errstring(c, "CLIENT_ERROR bad command line format");
        return;
    } else if (ntokens > MFLAG_MAX_OPT_LENGTH) {
        // TODO: ensure the command tokenizer gives us at least this many
        out_errstring(c, "CLIENT_ERROR options flags are too long");
        return;
    }

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(tokens, 2, &of, &errstr) != 0) {
        out_errstring(c, errstr);
        return;
    }
    c->noreply = of.no_reply;

    // Grab key and length after meta preparsing in case it was decoded.
    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    // TODO: need to indicate if the item was overflowed or not?
    // I think we do, since an overflow shouldn't trigger an alloc/replace.
    bool overflow = false;
    if (!of.locked) {
        it = limited_get(key, nkey, c, 0, false, !of.no_update, &overflow);
    } else {
        // If we had to lock the item, we're doing our own bump later.
        it = limited_get_locked(key, nkey, c, DONT_UPDATE, &hv, &overflow);
    }

    // Since we're a new protocol, we can actually inform users that refcount
    // overflow is happening by straight up throwing an error.
    // We definitely don't want to re-autovivify by accident.
    if (overflow) {
        assert(it == NULL);
        out_errstring(c, "SERVER_ERROR refcount overflow during fetch");
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
            do_item_link(it, hv);
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
            if (settings.meta_response_old) {
                memcpy(p, "OK", 2);
            } else {
                memcpy(p, "HD", 2);
            }
            p += 2;
        }

        for (i = KEY_TOKEN+1; i < ntokens-1; i++) {
            switch (tokens[i].value[0]) {
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
                        p = itoa_u32(*((uint32_t *) ITEM_suffix(it)), p);
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
                    if (tokens[i].length > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, tokens[i].value, tokens[i].length);
                    p += tokens[i].length;
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
                if (storage_get_item(c, it, resp) != 0) {
                    pthread_mutex_lock(&c->thread->stats.mutex);
                    c->thread->stats.get_oom_extstore++;
                    pthread_mutex_unlock(&c->thread->stats.mutex);

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
            do_item_bump(c, it, hv);
        }
        item_unlock(hv);
    }

    // we count this command as a normal one if we've gotten this far.
    // TODO: for autovivify case, miss never happens. Is this okay?
    if (!failed) {
        pthread_mutex_lock(&c->thread->stats.mutex);
        if (ttl_set) {
            c->thread->stats.touch_cmds++;
            c->thread->stats.slab_stats[ITEM_clsid(it)].touch_hits++;
        } else {
            c->thread->stats.lru_hits[it->slabs_clsid]++;
            c->thread->stats.get_cmds++;
        }
        pthread_mutex_unlock(&c->thread->stats.mutex);

        conn_set_state(c, conn_new_cmd);
    } else {
        pthread_mutex_lock(&c->thread->stats.mutex);
        if (ttl_set) {
            c->thread->stats.touch_cmds++;
            c->thread->stats.touch_misses++;
        } else {
            c->thread->stats.get_misses++;
            c->thread->stats.get_cmds++;
        }
        MEMCACHED_COMMAND_GET(c->sfd, key, nkey, -1, 0);
        pthread_mutex_unlock(&c->thread->stats.mutex);

        // This gets elided in noreply mode.
        out_string(c, "EN");
    }
    return;
error:
    if (it) {
        do_item_remove(it);
        if (of.locked) {
            item_unlock(hv);
        }
    }
    out_errstring(c, errstr);
}

static void process_mset_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    item *it;
    int i;
    short comm = NREAD_SET;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    uint32_t hv; // cached hash value.
    int vlen = 0; // value from data line.
    assert(c != NULL);
    mc_resp *resp = c->resp;
    char *p = resp->wbuf;

    WANT_TOKENS_MIN(ntokens, 3);

    // TODO: most of this is identical to mget.
    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_errstring(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (ntokens == 3) {
        out_errstring(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (ntokens > MFLAG_MAX_OPT_LENGTH) {
        out_errstring(c, "CLIENT_ERROR options flags too long");
        return;
    }

    // We note tokens into the front of the write buffer, so we can create the
    // final buffer in complete_nread_ascii.
    p = resp->wbuf;

    if (!safe_strtol(tokens[KEY_TOKEN + 1].value, (int32_t*)&vlen)) {
        out_errstring(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
        out_errstring(c, "CLIENT_ERROR bad command line format");
        return;
    }
    vlen += 2;

    // We need to at least try to get the size to properly slurp bad bytes
    // after an error.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(tokens, 3, &of, &errstr) != 0) {
        goto error;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    // Set noreply after tokens are understood.
    c->noreply = of.no_reply;
    // Clear cas return value
    c->cas = 0;

    bool has_error = false;
    for (i = KEY_TOKEN+1; i < ntokens-1; i++) {
        switch (tokens[i].value[0]) {
            // TODO: macro perhaps?
            case 'O':
                if (tokens[i].length > MFLAG_MAX_OPAQUE_LENGTH) {
                    errstr = "CLIENT_ERROR opaque token too long";
                    has_error = true;
                    break;
                }
                META_SPACE(p);
                memcpy(p, tokens[i].value, tokens[i].length);
                p += tokens[i].length;
                break;
            case 'k':
                META_CHAR(p, 'k');
                break;
            case 'c':
                // need to set the cas value post-assignment.
                META_CHAR(p, 'c');
                break;
        }
    }

    // "mode switch" to alternative commands
    switch (of.mode) {
        case 0:
            break; // no mode supplied.
        case 'E': // Add...
            comm = NREAD_ADD;
            break;
        case 'A': // Append.
            comm = NREAD_APPEND;
            break;
        case 'P': // Prepend.
            comm = NREAD_PREPEND;
            break;
        case 'R': // Replace.
            comm = NREAD_REPLACE;
            break;
        case 'S': // Set. Default.
            comm = NREAD_SET;
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
    if (of.has_cas && (comm == NREAD_SET || comm == NREAD_REPLACE)) {
        comm = NREAD_CAS;
    }

    // We attempt to process as much as we can in hopes of getting a valid and
    // adjusted vlen, or else the data swallowed after error will be for 0b.
    if (has_error)
        goto error;

    it = item_alloc(key, nkey, of.client_flags, of.exptime, vlen);

    if (it == 0) {
        enum store_item_type status;
        // TODO: These could be normalized codes (TL and OM). Need to
        // reorganize the output stuff a bit though.
        if (! item_size_ok(nkey, of.client_flags, vlen)) {
            errstr = "SERVER_ERROR object too large for cache";
            status = TOO_LARGE;
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.store_too_large++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
        } else {
            errstr = "SERVER_ERROR out of memory storing object";
            status = NO_MEMORY;
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.store_no_memory++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
        }
        // FIXME: LOGGER_LOG specific to mset, include options.
        LOGGER_LOG(c->thread->l, LOG_MUTATIONS, LOGGER_ITEM_STORE,
                NULL, status, comm, key, nkey, 0, 0);

        /* Avoid stale data persisting in cache because we failed alloc. */
        // NOTE: only if SET mode?
        it = item_get_locked(key, nkey, c, DONT_UPDATE, &hv);
        if (it) {
            do_item_unlink(it, hv);
            STORAGE_delete(c->thread->storage, it);
            do_item_remove(it);
        }
        item_unlock(hv);

        goto error;
    }
    ITEM_set_cas(it, of.req_cas_id);

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

    // Prevent printing back the key in meta commands as garbage.
    if (of.key_binary) {
        it->it_flags |= ITEM_KEY_BINARY;
    }

    if (of.set_stale && comm == NREAD_CAS) {
        c->set_stale = true;
    }
    resp->wbytes = p - resp->wbuf;
    // we don't set up the iov here, instead after complete_nread_ascii when
    // we have the full status code and item data.
    c->mset_res = true;
    conn_set_state(c, conn_nread);
    return;
error:
    /* swallow the data line */
    c->sbytes = vlen;

    // Note: no errors possible after the item was successfully allocated.
    // So we're just looking at dumping error codes and returning.
    out_errstring(c, errstr);
    // TODO: pass state in? else switching twice meh.
    conn_set_state(c, conn_swallow);
}

static void process_mdelete_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    item *it = NULL;
    int i;
    uint32_t hv;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(c != NULL);
    mc_resp *resp = c->resp;
    // reserve 3 bytes for status code
    char *p = resp->wbuf + 3;

    WANT_TOKENS_MIN(ntokens, 3);

    // TODO: most of this is identical to mget.
    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (ntokens > MFLAG_MAX_OPT_LENGTH) {
        out_string(c, "CLIENT_ERROR options flags too long");
        return;
    }

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    // FIXME: not using the preparse errstr?
    if (_meta_flag_preparse(tokens, 2, &of, &errstr) != 0) {
        out_errstring(c, "CLIENT_ERROR invalid or duplicate flag");
        return;
    }
    assert(c != NULL);
    c->noreply = of.no_reply;

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    for (i = KEY_TOKEN+1; i < ntokens-1; i++) {
        switch (tokens[i].value[0]) {
            // TODO: macro perhaps?
            case 'O':
                if (tokens[i].length > MFLAG_MAX_OPAQUE_LENGTH) {
                    errstr = "CLIENT_ERROR opaque token too long";
                    goto error;
                }
                META_SPACE(p);
                memcpy(p, tokens[i].value, tokens[i].length);
                p += tokens[i].length;
                break;
            case 'k':
                META_KEY(p, key, nkey, of.key_binary);
                break;
        }
    }

    it = item_get_locked(key, nkey, c, DONT_UPDATE, &hv);
    if (it) {
        MEMCACHED_COMMAND_DELETE(c->sfd, ITEM_key(it), it->nkey);

        // allow only deleting/marking if a CAS value matches.
        if (of.has_cas && ITEM_get_cas(it) != of.req_cas_id) {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.delete_misses++;
            pthread_mutex_unlock(&c->thread->stats.mutex);

            memcpy(resp->wbuf, "EX ", 3);
            goto cleanup;
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

            ITEM_set_cas(it, (settings.use_cas) ? get_cas_id() : 0);

            // Clients can noreply nominal responses.
            if (c->noreply)
                resp->skip = true;
            if (settings.meta_response_old) {
                memcpy(resp->wbuf, "OK ", 3);
            } else {
                memcpy(resp->wbuf, "HD ", 3);
            }
        } else {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[ITEM_clsid(it)].delete_hits++;
            pthread_mutex_unlock(&c->thread->stats.mutex);

            do_item_unlink(it, hv);
            STORAGE_delete(c->thread->storage, it);
            if (c->noreply)
                resp->skip = true;
            if (settings.meta_response_old) {
                memcpy(resp->wbuf, "OK ", 3);
            } else {
                memcpy(resp->wbuf, "HD ", 3);
            }
        }
        goto cleanup;
    } else {
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.delete_misses++;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        memcpy(resp->wbuf, "NF ", 3);
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
    conn_set_state(c, conn_new_cmd);
    return;
error:
    out_errstring(c, errstr);
}

static void process_marithmetic_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    int i;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(c != NULL);
    mc_resp *resp = c->resp;
    // no reservation (like del/set) since we post-process the status line.
    char *p = resp->wbuf;

    // If no argument supplied, incr or decr by one.
    of.delta = 1;
    of.initial = 0; // redundant, for clarity.
    bool incr = true; // default mode is to increment.
    bool locked = false;
    uint32_t hv = 0;
    item *it = NULL; // item returned by do_add_delta.

    WANT_TOKENS_MIN(ntokens, 3);

    // TODO: most of this is identical to mget.
    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (ntokens > MFLAG_MAX_OPT_LENGTH) {
        out_string(c, "CLIENT_ERROR options flags too long");
        return;
    }

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(tokens, 2, &of, &errstr) != 0) {
        out_errstring(c, "CLIENT_ERROR invalid or duplicate flag");
        return;
    }
    assert(c != NULL);
    c->noreply = of.no_reply;

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

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
    switch(do_add_delta(c, key, nkey, incr, of.delta, tmpbuf, &of.req_cas_id, hv, &it)) {
    case OK:
        if (c->noreply)
            resp->skip = true;
        if (settings.meta_response_old) {
            memcpy(resp->wbuf, "OK ", 3);
        } else {
            memcpy(resp->wbuf, "HD ", 3);
        }
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
                if (do_store_item(it, NREAD_ADD, c, hv)) {
                    item_created = true;
                } else {
                    // Not sure how we can get here if we're holding the lock.
                    memcpy(resp->wbuf, "NS ", 3);
                }
            } else {
                errstr = "SERVER_ERROR Out of memory allocating new item";
                goto error;
            }
        } else {
            pthread_mutex_lock(&c->thread->stats.mutex);
            if (incr) {
                c->thread->stats.incr_misses++;
            } else {
                c->thread->stats.decr_misses++;
            }
            pthread_mutex_unlock(&c->thread->stats.mutex);
            // won't have a valid it here.
            memcpy(p, "NF ", 3);
            p += 3;
        }
        break;
    case DELTA_ITEM_CAS_MISMATCH:
        // also returns without a valid it.
        memcpy(p, "EX ", 3);
        p += 3;
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
            if (settings.meta_response_old) {
                memcpy(p, "OK", 2);
            } else {
                memcpy(p, "HD", 2);
            }
            p += 2;
        }

        for (i = KEY_TOKEN+1; i < ntokens-1; i++) {
            switch (tokens[i].value[0]) {
                case 'c':
                    META_CHAR(p, 'c');
                    p = itoa_u64(ITEM_get_cas(it), p);
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
                // TODO: macro perhaps?
                case 'O':
                    if (tokens[i].length > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, tokens[i].value, tokens[i].length);
                    p += tokens[i].length;
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
        for (i = KEY_TOKEN+1; i < ntokens-1; i++) {
            switch (tokens[i].value[0]) {
                // TODO: macro perhaps?
                case 'O':
                    if (tokens[i].length > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, tokens[i].value, tokens[i].length);
                    p += tokens[i].length;
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
    conn_set_state(c, conn_new_cmd);
    return;
error:
    if (it != NULL)
        do_item_remove(it);
    if (locked)
        item_unlock(hv);
    out_errstring(c, errstr);
}


static void process_update_command(conn *c, token_t *tokens, const size_t ntokens, int comm, bool handle_cas) {
    char *key;
    size_t nkey;
    unsigned int flags;
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    int vlen;
    uint64_t req_cas_id=0;
    item *it;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if (! (safe_strtoul(tokens[2].value, (uint32_t *)&flags)
           && safe_strtol(tokens[3].value, &exptime_int)
           && safe_strtol(tokens[4].value, (int32_t *)&vlen))) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));

    // does cas value exist?
    if (handle_cas) {
        if (!safe_strtoull(tokens[5].value, &req_cas_id)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }
    vlen += 2;

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    it = item_alloc(key, nkey, flags, exptime, vlen);

    if (it == 0) {
        enum store_item_type status;
        if (! item_size_ok(nkey, flags, vlen)) {
            out_string(c, "SERVER_ERROR object too large for cache");
            status = TOO_LARGE;
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.store_too_large++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
        } else {
            out_of_memory(c, "SERVER_ERROR out of memory storing object");
            status = NO_MEMORY;
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.store_no_memory++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
        }
        LOGGER_LOG(c->thread->l, LOG_MUTATIONS, LOGGER_ITEM_STORE,
                NULL, status, comm, key, nkey, 0, 0, c->sfd);
        /* swallow the data line */
        conn_set_state(c, conn_swallow);
        c->sbytes = vlen;

        /* Avoid stale data persisting in cache because we failed alloc.
         * Unacceptable for SET. Anywhere else too? */
        if (comm == NREAD_SET) {
            it = item_get(key, nkey, c, DONT_UPDATE);
            if (it) {
                item_unlink(it);
                STORAGE_delete(c->thread->storage, it);
                item_remove(it);
            }
        }

        return;
    }
    ITEM_set_cas(it, req_cas_id);

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

static void process_touch_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    item *it;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if (!safe_strtol(tokens[2].value, &exptime_int)) {
        out_string(c, "CLIENT_ERROR invalid exptime argument");
        return;
    }

    exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));
    it = item_touch(key, nkey, exptime, c);
    if (it) {
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.touch_cmds++;
        c->thread->stats.slab_stats[ITEM_clsid(it)].touch_hits++;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        out_string(c, "TOUCHED");
        item_remove(it);
    } else {
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.touch_cmds++;
        c->thread->stats.touch_misses++;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        out_string(c, "NOT_FOUND");
    }
}

static void process_arithmetic_command(conn *c, token_t *tokens, const size_t ntokens, const bool incr) {
    char temp[INCR_MAX_STORAGE_LEN];
    uint64_t delta;
    char *key;
    size_t nkey;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if (!safe_strtoull(tokens[2].value, &delta)) {
        out_string(c, "CLIENT_ERROR invalid numeric delta argument");
        return;
    }

    switch(add_delta(c, key, nkey, incr, delta, temp, NULL)) {
    case OK:
        out_string(c, temp);
        break;
    case NON_NUMERIC:
        out_string(c, "CLIENT_ERROR cannot increment or decrement non-numeric value");
        break;
    case EOM:
        out_of_memory(c, "SERVER_ERROR out of memory");
        break;
    case DELTA_ITEM_NOT_FOUND:
        pthread_mutex_lock(&c->thread->stats.mutex);
        if (incr) {
            c->thread->stats.incr_misses++;
        } else {
            c->thread->stats.decr_misses++;
        }
        pthread_mutex_unlock(&c->thread->stats.mutex);

        out_string(c, "NOT_FOUND");
        break;
    case DELTA_ITEM_CAS_MISMATCH:
        break; /* Should never get here */
    }
}


static void process_delete_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    item *it;
    uint32_t hv;

    assert(c != NULL);

    if (ntokens > 3) {
        bool hold_is_zero = strcmp(tokens[KEY_TOKEN+1].value, "0") == 0;
        bool sets_noreply = set_noreply_maybe(c, tokens, ntokens);
        bool valid = (ntokens == 4 && (hold_is_zero || sets_noreply))
            || (ntokens == 5 && hold_is_zero && sets_noreply);
        if (!valid) {
            out_string(c, "CLIENT_ERROR bad command line format.  "
                       "Usage: delete <key> [noreply]");
            return;
        }
    }


    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if(nkey > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (settings.detail_enabled) {
        stats_prefix_record_delete(key, nkey);
    }

    it = item_get_locked(key, nkey, c, DONT_UPDATE, &hv);
    if (it) {
        MEMCACHED_COMMAND_DELETE(c->sfd, ITEM_key(it), it->nkey);

        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.slab_stats[ITEM_clsid(it)].delete_hits++;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        do_item_unlink(it, hv);
        STORAGE_delete(c->thread->storage, it);
        do_item_remove(it);      /* release our reference */
        out_string(c, "DELETED");
    } else {
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.delete_misses++;
        pthread_mutex_unlock(&c->thread->stats.mutex);

        out_string(c, "NOT_FOUND");
    }
    item_unlock(hv);
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
        settings.slab_automove_ratio = ratio;
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
        if (!safe_strtoul(tokens[2].value, &settings.ext_item_size))
            ok = false;
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

    if (ntokens != (c->noreply ? 3 : 2)) {
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
        new_oldest = realtime(exptime);
    } else { /* exptime == 0 */
        new_oldest = current_time;
    }

    if (settings.use_cas) {
        settings.oldest_live = new_oldest - 1;
        if (settings.oldest_live <= current_time)
            settings.oldest_cas = get_cas_id();
    } else {
        settings.oldest_live = new_oldest;
    }
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

        rv = slabs_reassign(src, dst);
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
void process_command_ascii(conn *c, char *command) {

    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    int comm;

    assert(c != NULL);

    MEMCACHED_PROCESS_COMMAND_START(c->sfd, c->rcurr, c->rbytes);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d %s\n", c->sfd, command);

    /*
     * for commands set/add/replace, we build an item and read the data
     * directly into it, then continue in nread_complete().
     */

    // Prep the response object for this query.
    if (!resp_start(c)) {
        conn_set_state(c, conn_closing);
        return;
    }

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
            case 'g':
                process_mget_command(c, tokens, ntokens);
                break;
            case 's':
                process_mset_command(c, tokens, ntokens);
                break;
            case 'd':
                process_mdelete_command(c, tokens, ntokens);
                break;
            case 'n':
                out_string(c, "MN");
                // mn command forces immediate writeback flush.
                conn_set_state(c, conn_mwrite);
                break;
            case 'a':
                process_marithmetic_command(c, tokens, ntokens);
                break;
            case 'e':
                process_meta_command(c, tokens, ntokens);
                break;
            default:
                out_string(c, "ERROR");
                break;
        }
    } else if (first == 'g') {
        // Various get commands are very common.
        WANT_TOKENS_MIN(ntokens, 3);
        if (strcmp(tokens[COMMAND_TOKEN].value, "get") == 0) {

            process_get_command(c, tokens, ntokens, false, false);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "gets") == 0) {

            process_get_command(c, tokens, ntokens, true, false);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "gat") == 0) {

            process_get_command(c, tokens, ntokens, false, true);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "gats") == 0) {

            process_get_command(c, tokens, ntokens, true, true);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 's') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = NREAD_SET)) {

            WANT_TOKENS_OR(ntokens, 6, 7);
            process_update_command(c, tokens, ntokens, comm, false);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "stats") == 0) {

            process_stat(c, tokens, ntokens);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "shutdown") == 0) {

            process_shutdown_command(c, tokens, ntokens);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "slabs") == 0) {

            process_slabs_command(c, tokens, ntokens);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 'a') {
        if ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = NREAD_ADD)) ||
            (strcmp(tokens[COMMAND_TOKEN].value, "append") == 0 && (comm = NREAD_APPEND)) ) {

            WANT_TOKENS_OR(ntokens, 6, 7);
            process_update_command(c, tokens, ntokens, comm, false);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 'c') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "cas") == 0 && (comm = NREAD_CAS)) {

            WANT_TOKENS_OR(ntokens, 7, 8);
            process_update_command(c, tokens, ntokens, comm, true);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "cache_memlimit") == 0) {

            WANT_TOKENS_OR(ntokens, 3, 4);
            process_memlimit_command(c, tokens, ntokens);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 'i') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "incr") == 0) {

            WANT_TOKENS_OR(ntokens, 4, 5);
            process_arithmetic_command(c, tokens, ntokens, 1);
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 'd') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "delete") == 0) {

            WANT_TOKENS(ntokens, 3, 5);
            process_delete_command(c, tokens, ntokens);
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "decr") == 0) {

            WANT_TOKENS_OR(ntokens, 4, 5);
            process_arithmetic_command(c, tokens, ntokens, 0);
#ifdef MEMCACHED_DEBUG
        } else if (strcmp(tokens[COMMAND_TOKEN].value, "debugtime") == 0) {
            WANT_TOKENS_MIN(ntokens, 2);
            process_debugtime_command(c, tokens, ntokens);
#endif
        } else {
            out_string(c, "ERROR");
        }
    } else if (first == 't') {
        if (strcmp(tokens[COMMAND_TOKEN].value, "touch") == 0) {

            WANT_TOKENS_OR(ntokens, 4, 5);
            process_touch_command(c, tokens, ntokens);
        } else {
            out_string(c, "ERROR");
        }
    } else if (
                (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = NREAD_REPLACE)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "prepend") == 0 && (comm = NREAD_PREPEND)) ) {

        WANT_TOKENS_OR(ntokens, 6, 7);
        process_update_command(c, tokens, ntokens, comm, false);

    } else if (strcmp(tokens[COMMAND_TOKEN].value, "bget") == 0) {
        // ancient "binary get" command which isn't in any documentation, was
        // removed > 10 years ago, etc. Keeping for compatibility reasons but
        // we should look deeper into client code and remove this.
        WANT_TOKENS_MIN(ntokens, 3);
        process_get_command(c, tokens, ntokens, false, false);

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


