/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Functions for handling the text related protocols, original and meta.
 */

#include "memcached.h"
// FIXME: only for process_proxy_stats()
// - some better/different structure for stats subcommands
// would remove this abstraction leak.
#include "proto_proxy.h"
#include "proto_parser.h"
#include "proto_text.h"
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
      ret = store_item(it, comm, c->thread, &nbytes, &cas, c->cas ? c->cas : get_cas_id(), c->resp->set_stale, c->resp->set_lww);
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

int try_read_command_asciiauth(conn *c) {
    mcmc_tokenizer_t tok;
    memset(&tok, 0, sizeof(tok));
    char *cont = NULL;
    char *mid = NULL;

    // TODO: move to another function.
    if (!c->sasl_started) {
        char *el, *st;
        uint32_t size = 0;

        // impossible for the auth command to be this short.
        if (c->rbytes < 3)
            return 0;

        st = c->rcurr;
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

        if (mcmc_tokenize(st, el - st, &tok, 255) != MCMC_OK) {
            conn_set_state(c, conn_closing);
            return 1;
        }
        // ensure the buffer is consumed.
        c->rbytes -= (el - c->rcurr) + 1;
        c->rcurr += (el - c->rcurr) + 1;

        // final token is a NULL ender, so we have one more than expected.
        if (tok.ntokens < 5
                || strncmp(st, "set", 3) != 0
                || mcmc_token_get_u32(st, &tok, 4, &size) != MCMC_OK) {
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
    mid = memchr(cont, ' ', c->rlbytes);

    if (!mid) {
        out_string(c, "CLIENT_ERROR bad authentication token format");
        return 1;
    }

    if (authfile_check(cont, mid-cont, mid+1, c->rlbytes-2 - (mid+1-cont)) == 1) {
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
    process_command_ascii(c, c->rcurr, cont - c->rcurr);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    assert(c->rcurr <= (c->rbuf + c->rsize));

    return 1;
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
        if (!mc_tokto32(pr, 1, &exptime_int)) {
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
    if (settings.verbose > 1)
        fprintf(stderr, ">%d END\n", t->cur_sfd);

    resp_add_iov(c->resp, "END\r\n", 5);
    conn_set_state(c, conn_new_cmd);
    return;
}

inline static void process_stats_detail(conn *c, mcp_parser_t *pr, int token) {
    assert(c != NULL);
    int len = 0;
    const char *command = mcmc_token_get(pr->request, &pr->tok, token, &len);

    if (strncmp(command, "on", len) == 0) {
        settings.detail_enabled = 1;
        out_string(c, "OK");
    }
    else if (strncmp(command, "off", len) == 0) {
        settings.detail_enabled = 0;
        out_string(c, "OK");
    }
    else if (strncmp(command, "dump", len) == 0) {
        int l;
        char *stats = stats_prefix_dump(&l);
        write_and_free(c, stats, l);
    }
    else {
        out_string(c, "CLIENT_ERROR usage: stats detail on|off|dump");
    }
}

static void process_stat(conn *c, mcp_parser_t *pr) {
    int len = 0;
    int ntokens = pr->tok.ntokens;
    const char *subcommand = mcmc_token_get(pr->request, &pr->tok, SUBCOMMAND_TOKEN, &len);
    assert(c != NULL);

    if (ntokens < 1) {
        out_string(c, "CLIENT_ERROR bad command line");
        return;
    }

    if (ntokens == 1) {
        server_stats(&append_stats, c);
        (void)get_stats(NULL, 0, &append_stats, c);
    } else if (strncmp(subcommand, "reset", len) == 0) {
        stats_reset();
        out_string(c, "RESET");
        return;
    } else if (strncmp(subcommand, "detail", len) == 0) {
        if (!settings.dump_enabled) {
            out_string(c, "CLIENT_ERROR stats detail not allowed");
            return;
        }

        /* NOTE: how to tackle detail with binary? */
        if (ntokens < 3)
            process_stats_detail(c, pr, 0);  /* outputs the error message */
        else
            process_stats_detail(c, pr, 2);
        /* Output already generated */
        return;
    } else if (strncmp(subcommand, "settings", len) == 0) {
        process_stat_settings(&append_stats, c);
    } else if (strncmp(subcommand, "cachedump", len) == 0) {
        char *buf;
        unsigned int bytes, id, limit = 0;

        if (!settings.dump_enabled) {
            out_string(c, "CLIENT_ERROR stats cachedump not allowed");
            return;
        }

        if (ntokens < 4) {
            out_string(c, "CLIENT_ERROR bad command line");
            return;
        }

        if ((mcmc_token_get_u32(pr->request, &pr->tok, 2, &id) != MCMC_OK) ||
            (mcmc_token_get_u32(pr->request, &pr->tok, 3, &limit) != MCMC_OK)) {
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
    } else if (strncmp(subcommand, "conns", len) == 0) {
        process_stats_conns(&append_stats, c);
#ifdef EXTSTORE
    } else if (strncmp(subcommand, "extstore", len) == 0) {
        process_extstore_stats(&append_stats, c);
#endif
#ifdef PROXY
    } else if (strncmp(subcommand, "proxy", len) == 0) {
        process_proxy_stats(settings.proxy_ctx, &append_stats, c);
    } else if (strncmp(subcommand, "proxyfuncs", len) == 0) {
        process_proxy_funcstats(settings.proxy_ctx, &append_stats, c);
    } else if (strncmp(subcommand, "proxybe", len) == 0) {
        process_proxy_bestats(settings.proxy_ctx, &append_stats, c);
#endif
    } else {
        /* getting here means that the subcommand is either engine specific or
           is invalid. query the engine and see. */
        if (get_stats(subcommand, len, &append_stats, c)) {
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
static void process_meta_command(conn *c, mcp_parser_t *pr) {
    assert(c != NULL);

    int ntokens = pr->tok.ntokens;
    if (ntokens < 2 || pr->klen > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    const char *key = MCP_PARSER_KEY(pr);
    size_t nkey = pr->klen;
    int tlen = 0;
    const char *flag = mcmc_token_get(pr->request, &pr->tok, 2, &tlen);

    if (ntokens >= 4 && tlen == 1 && flag[0] == 'b') {
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

// Text handler requires some custom code around the update code: we directly
// load buffer data into the allocated item, meaning we can drop back to the
// event system for a network read, meaning we lose the request context
// inbetween now and when a store command is finalized.
//
// The meta parsing code was abstracted out into common code.
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

static void process_verbosity_command(conn *c, mcp_parser_t *pr) {
    assert(c != NULL);

    uint32_t level;
    if (mcmc_token_get_u32(pr->request, &pr->tok, 1, &level) != MCMC_OK) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }
    settings.verbose = level > MAX_VERBOSITY_LEVEL ? MAX_VERBOSITY_LEVEL : level;
    out_string(c, "OK");
    return;
}

#ifdef MEMCACHED_DEBUG
static void process_misbehave_command(conn *c, mcp_parser_t *pr) {
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

static void process_debugtime_command(conn *c, mcp_parser_t *pr) {
    int len = 0;
    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, SUBCOMMAND_TOKEN, &len);
    if (subcmd == NULL) {
        out_string(c, "ERROR");
        return;
    }

    if (strncmp(subcmd, "p", len) == 0) {
        if (!is_paused) {
            is_paused = true;
        }
    } else if (strncmp(subcmd, "r", len) == 0) {
        if (is_paused) {
            is_paused = false;
        }
    } else {
        int64_t time_delta = 0;
        if (mcmc_token_get_64(pr->request, &pr->tok, SUBCOMMAND_TOKEN, &time_delta) != MCMC_OK) {
            out_string(c, "ERROR");
            return;
        }
        delta += time_delta;
        current_time += delta;
    }
    out_string(c, "OK");
}

static void process_debugitem_command(conn *c, mcp_parser_t *pr) {
    int len = 0;
    int klen = 0;
    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, 1, &len);
    const char *key = mcmc_token_get(pr->request, &pr->tok, 2, &klen);
    if (subcmd == NULL || key == NULL) {
        out_string(c, "ERROR");
        return;
    }

    if (strncmp(subcmd, "lock", len) == 0) {
        uint32_t hv = hash(key, klen);
        item_lock(hv);
    } else if (strncmp(subcmd, "unlock", len) == 0) {
        uint32_t hv = hash(key, klen);
        item_unlock(hv);
    } else if (strncmp(subcmd, "ref", len) == 0) {
        // intentionally leak a reference.
        item *it = item_get(key, klen, c->thread, DONT_UPDATE);
        if (it == NULL) {
            out_string(c, "MISS");
            return;
        }
    } else if (strncmp(subcmd, "unref", len) == 0) {
        // double unlink. debugger must have already ref'ed it or this
        // underflows.
        item *it = item_get(key, klen, c->thread, DONT_UPDATE);
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

static void process_slabs_automove_command(conn *c, mcp_parser_t *pr) {
    unsigned int level;
    double ratio;
    int len = 0;
    int ntokens = pr->tok.ntokens;

    assert(c != NULL);

    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, 2, &len);
    if (subcmd == NULL) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (strncmp(subcmd, "ratio", len) == 0) {
        if (ntokens < 4 || !mc_toktod(pr, 3, &ratio)) {
            out_string(c, "ERROR");
            return;
        }
        // TODO: settings needs an overhaul... no locks/etc.
        settings.slab_automove_ratio = ratio;
        settings.slab_automove_version++;
    } else if (strncmp(subcmd, "freeratio", len) == 0) {
        if (ntokens < 4 || !mc_toktod(pr, 3, &ratio)) {
            out_string(c, "ERROR");
            return;
        }
        settings.slab_automove_freeratio = ratio;
        settings.slab_automove_version++;
    } else if (strncmp(subcmd, "window", len) == 0) {
        if (ntokens < 4 || mcmc_token_get_u32(pr->request, &pr->tok, 3, &level) != MCMC_OK) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        settings.slab_automove_window = level;
        settings.slab_automove_version++;
    } else {
        if (mcmc_token_get_u32(pr->request, &pr->tok, 2, &level) != MCMC_OK) {
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
static void process_watch_command(conn *c, mcp_parser_t *pr) {
    uint16_t f = 0;
    int x;
    int ntokens = pr->tok.ntokens;
    assert(c != NULL);

    if (!settings.watch_enabled) {
        out_string(c, "CLIENT_ERROR watch commands not allowed");
        return;
    }

    if (resp_has_stack(c)) {
        out_string(c, "ERROR cannot pipeline other commands before watch");
        return;
    }

    if (ntokens > 1) {
        for (x = COMMAND_TOKEN + 1; x < ntokens; x++) {
            int len = 0;
            const char *t = mcmc_token_get(pr->request, &pr->tok, x, &len);
            if ((strncmp(t, "rawcmds", len) == 0)) {
                f |= LOG_RAWCMDS;
            } else if ((strncmp(t, "evictions", len) == 0)) {
                f |= LOG_EVICTIONS;
            } else if ((strncmp(t, "fetchers", len) == 0)) {
                f |= LOG_FETCHERS;
            } else if ((strncmp(t, "mutations", len) == 0)) {
                f |= LOG_MUTATIONS;
            } else if ((strncmp(t, "sysevents", len) == 0)) {
                f |= LOG_SYSEVENTS;
            } else if ((strncmp(t, "connevents", len) == 0)) {
                f |= LOG_CONNEVENTS;
            } else if ((strncmp(t, "proxyreqs", len) == 0)) {
                f |= LOG_PROXYREQS;
            } else if ((strncmp(t, "proxyevents", len) == 0)) {
                f |= LOG_PROXYEVENTS;
            } else if ((strncmp(t, "proxyuser", len) == 0)) {
                f |= LOG_PROXYUSER;
            } else if ((strncmp(t, "deletions", len) == 0)) {
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

static void process_memlimit_command(conn *c, mcp_parser_t *pr) {
    uint32_t memlimit;
    assert(c != NULL);

    if (mcmc_token_get_u32(pr->request, &pr->tok, 1, &memlimit) != MCMC_OK) {
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

static void process_lru_command(conn *c, mcp_parser_t *pr) {
    uint32_t pct_hot;
    uint32_t pct_warm;
    double hot_factor;
    int32_t ttl;
    double factor;
    int len = 0;
    int ntokens = pr->tok.ntokens;
    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, SUBCOMMAND_TOKEN, &len);
    if (subcmd == NULL) {
        out_string(c, "ERROR");
    }

    if (strncmp(subcmd, "tune", len) == 0 && ntokens >= 6) {
        if (!mc_toktou32(pr, 2, &pct_hot) ||
            !mc_toktou32(pr, 3, &pct_warm) ||
            !mc_toktod(pr, 4, &hot_factor) ||
            !mc_toktod(pr, 5, &factor)) {
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
    } else if (strncmp(subcmd, "mode", len) == 0 && ntokens >= 3 &&
               settings.lru_maintainer_thread) {
        if (mc_prcmp(pr, 2, "flat") == 0) {
            settings.lru_segmented = false;
            out_string(c, "OK");
        } else if (mc_prcmp(pr, 2, "segmented") == 0) {
            settings.lru_segmented = true;
            out_string(c, "OK");
        } else {
            out_string(c, "ERROR");
        }
    } else if (strncmp(subcmd, "temp_ttl", len) == 0 && ntokens >= 3 &&
               settings.lru_maintainer_thread) {
        if (!mc_tokto32(pr, 2, &ttl)) {
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
static void process_extstore_command(conn *c, mcp_parser_t *pr) {
    bool ok = true;
    int ntokens = pr->tok.ntokens;
    int len = 0;
    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, SUBCOMMAND_TOKEN, &len);

    if (ntokens < 3 || subcmd == NULL) {
        ok = false;
    } else if (strncmp(subcmd, "free_memchunks", len) == 0 && ntokens > 3) {
        // setting is deprecated and ignored, but accepted for backcompat
        unsigned int clsid = 0;
        unsigned int limit = 0;
        if (!mc_toktou32(pr, 2, &clsid) ||
                !mc_toktou32(pr, 3, &limit)) {
            ok = false;
        } else {
            if (clsid < MAX_NUMBER_OF_SLAB_CLASSES) {
                ok = true;
            } else {
                ok = false;
            }
        }
    } else if (strncmp(subcmd, "item_size", len) == 0) {
        if (mc_toktou32(pr, 2, &settings.ext_item_size)) {
            settings.slab_automove_version++;
        } else {
            ok = false;
        }
    } else if (strncmp(subcmd, "item_age", len) == 0) {
        if (!mc_toktou32(pr, 2, &settings.ext_item_age))
            ok = false;
    } else if (strncmp(subcmd, "low_ttl", len) == 0) {
        if (!mc_toktou32(pr, 2, &settings.ext_low_ttl))
            ok = false;
    } else if (strncmp(subcmd, "recache_rate", len) == 0) {
        if (!mc_toktou32(pr, 2, &settings.ext_recache_rate))
            ok = false;
    } else if (strncmp(subcmd, "compact_under", len) == 0) {
        if (!mc_toktou32(pr, 2, &settings.ext_compact_under))
            ok = false;
    } else if (strncmp(subcmd, "drop_under", len) == 0) {
        if (!mc_toktou32(pr, 2, &settings.ext_drop_under))
            ok = false;
    } else if (strncmp(subcmd, "max_sleep", len) == 0) {
        if (!mc_toktou32(pr, 2, &settings.ext_max_sleep))
            ok = false;
    } else if (strncmp(subcmd, "max_frag", len) == 0) {
        if (!mc_toktod(pr, 2, &settings.ext_max_frag))
            ok = false;
    } else if (strncmp(subcmd, "drop_unread", len) == 0) {
        unsigned int v;
        if (!mc_toktou32(pr, 2, &v)) {
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
static void process_flush_all_command(conn *c, mcp_parser_t *pr) {
    int32_t exptime = 0;
    rel_time_t new_oldest = 0;

    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.flush_cmds++;
    pthread_mutex_unlock(&c->thread->stats.mutex);

    if (!settings.flush_enabled) {
        // flush_all is not allowed but we log it on stats
        out_string(c, "CLIENT_ERROR flush_all not allowed");
        return;
    }

    if (pr->tok.ntokens != (c->resp->noreply ? 2 : 1)) {
        if (!mc_tokto32(pr, 1, &exptime)) {
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

static void process_version_command(conn *c, mcp_parser_t *pr) {
    out_string(c, "VERSION " VERSION);
}

static void process_quit_command(conn *c, mcp_parser_t *pr) {
    conn_set_state(c, conn_mwrite);
    c->close_after_write = true;
    c->close_reason = NORMAL_CLOSE;
}

static void process_shutdown_command(conn *c, mcp_parser_t *pr) {
    if (!settings.shutdown_command) {
        out_string(c, "SERVER_ERROR: shutdown not enabled");
        return;
    }

    if (pr->tok.ntokens == 1) {
        c->close_reason = SHUTDOWN_CLOSE;
        conn_set_state(c, conn_closing);
        raise(SIGINT);
    } else if (pr->tok.ntokens == 2 && mc_prcmp(pr, SUBCOMMAND_TOKEN, "graceful") == 0) {
        c->close_reason = SHUTDOWN_CLOSE;
        conn_set_state(c, conn_closing);
        raise(SIGUSR1);
    } else {
        out_string(c, "CLIENT_ERROR invalid shutdown mode");
    }
}

static void process_slabs_command(conn *c, mcp_parser_t *pr) {
    int ntokens = pr->tok.ntokens;
    int len = 0;
    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, SUBCOMMAND_TOKEN, &len);
    if (ntokens == 4 && strncmp(subcmd, "reassign", len) == 0) {
        int src, dst, rv;

        if (settings.slab_reassign == false) {
            out_string(c, "CLIENT_ERROR slab reassignment disabled");
            return;
        }

        if (!mc_tokto32(pr, 2, &src) || !mc_tokto32(pr, 3, &dst)) {
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
    } else if (ntokens >= 3 &&
        (strncmp(subcmd, "automove", len) == 0)) {
        process_slabs_automove_command(c, pr);
    } else {
        out_string(c, "ERROR");
    }
}

static void process_lru_crawler_command(conn *c, mcp_parser_t *pr) {
    int ntokens = pr->tok.ntokens;
    int len = 0;
    const char *subcmd = mcmc_token_get(pr->request, &pr->tok, 1, &len);
    char sc_buf[512];

    if (ntokens == 3 && strncmp(subcmd, "crawl", len) == 0) {
        int rv;
        if (settings.lru_crawler == false) {
            out_string(c, "CLIENT_ERROR lru crawler disabled");
            return;
        }

        const char *slabclass = mcmc_token_get(pr->request, &pr->tok, 2, &len);
        len = len > sizeof(sc_buf)-1 ? sizeof(sc_buf)-1 : len;
        memcpy(sc_buf, slabclass, len > sizeof(sc_buf)-1 ? sizeof(sc_buf)-1 : len);
        sc_buf[len] = '\0';

        rv = lru_crawler_crawl(sc_buf, CRAWLER_EXPIRED, NULL, 0,
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
    } else if (ntokens == 3 && strncmp(subcmd, "metadump", len) == 0) {
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

        const char *slabclass = mcmc_token_get(pr->request, &pr->tok, 2, &len);
        len = len > sizeof(sc_buf)-1 ? sizeof(sc_buf)-1 : len;
        memcpy(sc_buf, slabclass, len > sizeof(sc_buf)-1 ? sizeof(sc_buf)-1 : len);
        sc_buf[len] = '\0';

        int rv = lru_crawler_crawl(sc_buf, CRAWLER_METADUMP,
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
    } else if (ntokens == 3 && strncmp(subcmd, "mgdump", len) == 0) {
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

        const char *slabclass = mcmc_token_get(pr->request, &pr->tok, 2, &len);
        len = len > sizeof(sc_buf)-1 ? sizeof(sc_buf)-1 : len;
        memcpy(sc_buf, slabclass, len > sizeof(sc_buf)-1 ? sizeof(sc_buf)-1 : len);
        sc_buf[len] = '\0';

        int rv = lru_crawler_crawl(sc_buf, CRAWLER_MGDUMP,
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
    } else if (ntokens == 3 && strncmp(subcmd, "tocrawl", len) == 0) {
        uint32_t tocrawl;
         if (!mc_toktou32(pr, 2, &tocrawl)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
        settings.lru_crawler_tocrawl = tocrawl;
        out_string(c, "OK");
        return;
    } else if (ntokens == 3 && strncmp(subcmd, "sleep", len) == 0) {
        uint32_t tosleep;
        if (!mc_toktou32(pr, 2, &tosleep)) {
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
    } else if (ntokens == 2) {
        if ((strncmp(subcmd, "enable", len) == 0)) {
            if (start_item_crawler_thread() == 0) {
                out_string(c, "OK");
            } else {
                out_string(c, "ERROR failed to start lru crawler thread");
            }
        } else if ((strncmp(subcmd, "disable", len) == 0)) {
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
static void process_refresh_certs_command(conn *c, mcp_parser_t *pr) {
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
// This was hard to fix since tokenize_command() mutilates the read buffer, so
// we can't drop out and back in again.
// Leaving this note here to spend more time on a fix now that
// tokenize_command() is gone and strings are fixed.

// TODO: this isn't a performance sensitive section of the code (these
// commands are all rare), but a hash table could speed things up.
typedef void (*text_cmd_func)(conn *c, mcp_parser_t *pr);

struct text_cmd_entry {
    const char *s; // top level command
    text_cmd_func func; // function to call
};

enum text_cmds {
    text_cmd_shutdown = 0,
    text_cmd_slabs,
    text_cmd_cache_memlimit,
#ifdef MEMCACHED_DEBUG
    text_cmd_debugtime,
    text_cmd_debugitem,
    text_cmd_misbehave,
#endif
    text_cmd_flush_all,
    text_cmd_lru_crawler,
    text_cmd_verbosity,
    text_cmd_lru,
#ifdef EXTSTORE
    text_cmd_extstore,
#endif
#ifdef TLS
    text_cmd_refresh_certs,
#endif
    text_cmd_final,
};

static const struct text_cmd_entry text_cmd_entries[] = {
    [text_cmd_shutdown] = {"shutdown", process_shutdown_command},
    [text_cmd_slabs] = {"slabs",  process_slabs_command},
    [text_cmd_cache_memlimit] = {"cache_memlimit", process_memlimit_command},
#ifdef MEMCACHED_DEBUG
    [text_cmd_debugtime] = {"debugtime", process_debugtime_command},
    [text_cmd_debugitem] = {"debugitem", process_debugitem_command},
    [text_cmd_misbehave] = {"misbehave", process_misbehave_command},
#endif
    [text_cmd_flush_all] = {"flush_all",  process_flush_all_command},
    [text_cmd_lru_crawler] = {"lru_crawler", process_lru_crawler_command},
    [text_cmd_verbosity] = {"verbosity", process_verbosity_command},
    [text_cmd_lru] = {"lru", process_lru_command},
#ifdef EXTSTORE
    [text_cmd_extstore] = {"extstore", process_extstore_command},
#endif
#ifdef TLS
    [text_cmd_refresh_certs] = {"refresh_certs", process_refresh_certs_command},
#endif
    [text_cmd_final] = {NULL, NULL},
};

void process_command_ascii(conn *c, char *command, size_t cmdlen) {
    mcp_parser_t pr = {0};
    LIBEVENT_THREAD *t = c->thread;
    // Prep the response object for this query.
    if (!resp_start(c)) {
        conn_set_state(c, conn_closing);
        return;
    }

    t->cur_sfd = c->sfd; // cuddle sfd for logging.
    int ret = process_request(&pr, command, cmdlen);
    c->resp->noreply = pr.noreply;
    if (settings.verbose > 1) {
        fprintf(stderr, "<%d %.*s\n", t->cur_sfd, (int)cmdlen-2, command);
    }
    if (ret == PROCESS_REQUEST_OK) {
        mc_resp *resp = c->resp;
        switch (pr.command) {
            case CMD_MA:
                process_marithmetic_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                break;
             case CMD_MD:
                process_mdelete_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                break;
             case CMD_MG:
                process_mget_cmd(t, &pr, resp, storage_get_item);
                if (resp->io_pending) {
                    resp->io_pending->c = c;
                    conn_resp_suspend(c, resp);
                } else {
                    conn_set_state(c, conn_new_cmd);
                }
                break;
            case CMD_MN:
                out_string(c, "MN");
                // mn command forces immediate writeback flush.
                conn_set_state(c, conn_mwrite);
                break;
            case CMD_MS:
                process_mset_command(c, &pr, resp);
                break;
            case CMD_ME:
                process_meta_command(c, &pr);
                break;
            case CMD_GET:
                process_get_command(c, t, &pr, storage_get_item, _NO_CAS, _NO_TOUCH);
                break;
            case CMD_GETS:
                process_get_command(c, t, &pr, storage_get_item, _DO_CAS, _NO_TOUCH);
                break;
            case CMD_GAT:
                process_get_command(c, t, &pr, storage_get_item, _NO_CAS, _DO_TOUCH);
                break;
            case CMD_GATS:
                process_get_command(c, t, &pr, storage_get_item, _DO_CAS, _DO_TOUCH);
                break;
             case CMD_DELETE:
                process_delete_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                break;
             case CMD_INCR:
                process_arithmetic_cmd(t, &pr, resp, true);
                conn_set_state(c, conn_new_cmd);
                break;
             case CMD_DECR:
                process_arithmetic_cmd(t, &pr, resp, false);
                conn_set_state(c, conn_new_cmd);
                break;
             case CMD_TOUCH:
                process_touch_cmd(t, &pr, resp);
                conn_set_state(c, conn_new_cmd);
                break;
             case CMD_SET:
                process_update_command(c, &pr, resp, NREAD_SET, false);
                break;
            case CMD_ADD:
                process_update_command(c, &pr, resp, NREAD_ADD, false);
                break;
            case CMD_APPEND:
                process_update_command(c, &pr, resp, NREAD_APPEND, false);
                break;
            case CMD_PREPEND:
                process_update_command(c, &pr, resp, NREAD_PREPEND, false);
                break;
            case CMD_REPLACE:
                process_update_command(c, &pr, resp, NREAD_REPLACE, false);
                break;
            case CMD_CAS:
                process_update_command(c, &pr, resp, NREAD_CAS, true);
                break;
            case CMD_QUIT:
                process_quit_command(c, &pr);
                break;
            case CMD_VERSION:
                process_version_command(c, &pr);
                break;
            case CMD_STATS:
                process_stat(c, &pr);
                break;
            case CMD_WATCH:
                process_watch_command(c, &pr);
                break;
            default:
                fprintf(stderr, "COMMAND: %s\n", command);
                assert(true == false);
                break;
        }

        return;
    } else if (ret == PROCESS_REQUEST_CMD_NOT_FOUND) {
        int len = 0;
        const char *cm = mcmc_token_get(pr.request, &pr.tok, 0, &len);
        for (int x = 0; text_cmd_entries[x].s; x++) {
            const struct text_cmd_entry *e = &text_cmd_entries[x];
            if (strncmp(e->s, cm, len) == 0) {
                e->func(c, &pr);
                return;
            }
        }

        if (pr.tok.ntokens > 1) {
            int len = 0;
            const char *subcm = mcmc_token_get(pr.request, &pr.tok, pr.tok.ntokens-1, &len);
            if (len >= 5 && strncmp(subcm, "HTTP/", 5) == 0) {
                conn_set_state(c, conn_closing);
                c->close_reason = ERROR_CLOSE;
                return;
            }
        }
    } else if (ret == PROCESS_REQUEST_BAD_FORMAT) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    out_string(c, "ERROR");
}
