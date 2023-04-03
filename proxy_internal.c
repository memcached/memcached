/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// Functions related to local command execution.

#include "proxy.h"
#include "storage.h"

#define PROXY_STORAGE_GET 0
#define PROXY_STORAGE_MG 1
#define _DO_CAS true
#define _NO_CAS false
#define _DO_TOUCH true
#define _NO_TOUCH false

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

// TODO (v2): out_string() needs to change to just take a *resp, but I don't
// want to do the huge refactor in this change series. So for now we have a
// custom out_string().
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

// For meta commands error strings override the quiet flag.
static void pout_errstring(mc_resp *resp, const char *str) {
    resp->skip = false;
    pout_string(resp, str);
}

#ifdef EXTSTORE
static void _storage_get_item_cb(void *e, obj_io *eio, int ret) {
    io_pending_proxy_t *io = (io_pending_proxy_t *)eio->data;
    assert(io->active == true);
    mc_resp *resp = io->tresp;
    item *read_it = (item *)eio->buf;
    bool miss = false;

    if (ret < 1) {
        miss = true;
    } else {
        uint32_t crc2;
        uint32_t crc = (uint32_t) read_it->exptime;
        crc2 = crc32c(0, (char *)read_it+STORE_OFFSET, eio->len-STORE_OFFSET);

        if (crc != crc2) {
            miss = true;
            io->badcrc = true;
        }
    }

    if (miss && !resp->skip) {
        resp->iovcnt = 1;
        if (io->gettype == PROXY_STORAGE_GET) {
            resp->iov[0].iov_len = 5;
            resp->iov[0].iov_base = "END\r\n";
            resp->tosend = 5;
        } else if (io->gettype == PROXY_STORAGE_MG) {
            resp->iov[0].iov_len = 4;
            resp->iov[0].iov_base = "EN\r\n";
            resp->tosend = 5;
        } else {
            assert(1 == 0);
        }
    }

    if (!miss) {
        resp->iov[io->iovec_data].iov_base = ITEM_data(read_it);
    }
    io->miss = miss;
    io->active = false;

    // in proxy mode we tend to return IO's as they happen so we can keep
    // latency down more.
    return_io_pending((io_pending_t *)io);
}

// TODO (v2): if the item is smaller than resp->wbuf[] shouldn't we just read
// directly into there? item only necessary for recache.
static int proxy_storage_get(LIBEVENT_THREAD *t, item *it, mc_resp *resp,
        int type) {
#ifdef NEED_ALIGN
    item_hdr hdr;
    memcpy(&hdr, ITEM_data(it), sizeof(hdr));
#else
    item_hdr *hdr = (item_hdr *)ITEM_data(it);
#endif
    size_t ntotal = ITEM_ntotal(it);

    io_pending_proxy_t *io = do_cache_alloc(t->io_cache);
    // this is a re-cast structure, so assert that we never outsize it.
    assert(sizeof(io_pending_t) >= sizeof(io_pending_proxy_t));
    memset(io, 0, sizeof(io_pending_proxy_t));
    io->active = true;
    // io_pending owns the reference for this object now.
    io->hdr_it = it;
    io->tresp = resp; // our mc_resp is a temporary object.
    io->io_queue_type = IO_QUEUE_EXTSTORE;
    io->io_type = IO_PENDING_TYPE_EXTSTORE; // proxy specific sub-type.
    io->gettype = type;
    io->thread = t;
    io->return_cb = proxy_return_cb;
    io->finalize_cb = proxy_finalize_cb;
    obj_io *eio = &io->eio;

    eio->buf = malloc(ntotal);
    if (eio->buf == NULL) {
        do_cache_free(t->io_cache, io);
        return -1;
    }

    io->iovec_data = resp->iovcnt;
    resp_add_iov(resp, "", it->nbytes);

    // We can't bail out anymore, so mc_resp owns the IO from here.
    resp->io_pending = (io_pending_t *)io;

    // reference ourselves for the callback.
    eio->data = (void *)io;

    // Now, fill in io->io based on what was in our header.
#ifdef NEED_ALIGN
    eio->page_version = hdr.page_version;
    eio->page_id = hdr.page_id;
    eio->offset = hdr.offset;
#else
    eio->page_version = hdr->page_version;
    eio->page_id = hdr->page_id;
    eio->offset = hdr->offset;
#endif
    eio->len = ntotal;
    eio->mode = OBJ_IO_READ;
    eio->cb = _storage_get_item_cb;

    pthread_mutex_lock(&t->stats.mutex);
    t->stats.get_extstore++;
    pthread_mutex_unlock(&t->stats.mutex);

    return 0;
}
#endif // EXTSTORE

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

static void process_get_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, bool return_cas, bool should_touch) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    int nkey = pr->klen;
    rel_time_t exptime = 0;
    bool overflow = false; // unused.

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    item *it = limited_get(key, nkey, t, exptime, should_touch, DO_UPDATE, &overflow);
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
          if (proxy_storage_get(t, it, resp, PROXY_STORAGE_GET) != 0) {
              pthread_mutex_lock(&t->stats.mutex);
              t->stats.get_oom_extstore++;
              pthread_mutex_unlock(&t->stats.mutex);

              item_remove(it);
              proxy_out_errstring(resp, PROXY_SERVER_ERROR, "out of memory writing get response");
              return;
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

    resp_add_iov(resp, "END\r\n", 5);
    return;
}

static void process_update_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, int comm, bool handle_cas) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    size_t nkey = pr->klen;
    unsigned int flags;
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    uint64_t req_cas_id = 0;
    item *it;

    assert(resp != NULL);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    // TODO (v2): these safe_str* functions operate on C _strings_, but these
    // tokens simply end with a space or carriage return/newline, so we either
    // need custom functions or validate harder that these calls won't bite us
    // later.
    if (! (safe_strtoul(&pr->request[pr->tokens[2]], (uint32_t *)&flags)
           && safe_strtol(&pr->request[pr->tokens[3]], &exptime_int))) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    exptime = realtime(EXPTIME_TO_POSITIVE_TIME(exptime_int));

    // does cas value exist?
    if (handle_cas) {
        if (!safe_strtoull(&pr->request[pr->tokens[5]], &req_cas_id)) {
            pout_string(resp, "CLIENT_ERROR bad command line format");
            return;
        }
    }

    // vlen is validated from the main parser.

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    it = item_alloc(key, nkey, flags, exptime, pr->vlen);

    if (it == 0) {
        //enum store_item_type status;
        if (! item_size_ok(nkey, flags, pr->vlen)) {
            pout_string(resp, "SERVER_ERROR object too large for cache");
            //status = TOO_LARGE;
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_too_large++;
            pthread_mutex_unlock(&t->stats.mutex);
        } else {
            pout_string(resp, "SERVER_ERROR out of memory storing object");
            //status = NO_MEMORY;
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_no_memory++;
            pthread_mutex_unlock(&t->stats.mutex);
        }
        //LOGGER_LOG(c->thread->l, LOG_MUTATIONS, LOGGER_ITEM_STORE,
        //        NULL, status, comm, key, nkey, 0, 0, c->sfd);

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

        return;
    }
    ITEM_set_cas(it, req_cas_id);

    pthread_mutex_lock(&t->stats.mutex);
    t->stats.slab_stats[ITEM_clsid(it)].set_cmds++;
    pthread_mutex_unlock(&t->stats.mutex);

    // complete_nread_proxy() does the data chunk check so all we need to do
    // is copy the data.
    if (_store_item_copy_from_buf(it, pr->vbuf, it->nbytes) != 0) {
        pout_string(resp, "SERVER_ERROR out of memory storing object");
        item_remove(it);
        return;
    }

    int ret = store_item(it, comm, t, NULL, NULL, CAS_NO_STALE);
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

static void process_arithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, const bool incr) {
    char temp[INCR_MAX_STORAGE_LEN];
    uint64_t delta;
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    size_t nkey = pr->klen;

    assert(t != NULL);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (!safe_strtoull(&pr->request[pr->tokens[2]], &delta)) {
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

static void process_delete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
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

    it = item_get_locked(key, nkey, t, DONT_UPDATE, &hv);
    if (it) {
        //MEMCACHED_COMMAND_DELETE(c->sfd, ITEM_key(it), it->nkey);

        pthread_mutex_lock(&t->stats.mutex);
        t->stats.slab_stats[ITEM_clsid(it)].delete_hits++;
        pthread_mutex_unlock(&t->stats.mutex);

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

static void process_touch_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    size_t nkey = pr->klen;
    int32_t exptime_int = 0;
    rel_time_t exptime = 0;
    item *it;

    assert(t != NULL);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (!safe_strtol(&pr->request[pr->tokens[2]], &exptime_int)) {
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

/*** meta command handlers ***/

// FIXME: macro or public interface, this is copypasted.
static int _process_token_len(mcp_parser_t *pr, size_t token) {
  const char *s = pr->request + pr->tokens[token];
  const char *e = pr->request + pr->tokens[token+1];
  // start of next token is after any space delimiters, so back those out.
  while (*(e-1) == ' ') {
      e--;
  }
  return e - s;
}

#define META_SPACE(p) { \
    *p = ' '; \
    p++; \
}

#define META_CHAR(p, c) { \
    *p = ' '; \
    *(p+1) = c; \
    p += 2; \
}

// FIXME: binary key support.
#define META_KEY(p, key, nkey, bin) { \
    META_CHAR(p, 'k'); \
    memcpy(p, key, nkey); \
    p += nkey; \
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

static int _meta_flag_preparse(mcp_parser_t *pr, const size_t start,
        struct _meta_flags *of, char **errstr) {
    unsigned int i;
    //size_t ret;
    int32_t tmp_int;
    uint8_t seen[127] = {0};
    // Start just past the key token. Look at first character of each token.
    for (i = start; i < pr->ntokens; i++) {
        uint8_t o = (uint8_t)pr->request[pr->tokens[i]];
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
                if (!safe_strtol(&pr->request[pr->tokens[i]+1], &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->autoviv_exptime = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                }
                break;
            case 'T':
                of->locked = 1;
                if (!safe_strtol(&pr->request[pr->tokens[i]+1], &tmp_int)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = 1;
                } else {
                    of->exptime = realtime(EXPTIME_TO_POSITIVE_TIME(tmp_int));
                    of->new_ttl = true;
                }
                break;
            case 'R':
                of->locked = 1;
                if (!safe_strtol(&pr->request[pr->tokens[i]+1], &tmp_int)) {
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
                if (!safe_strtoul(&pr->request[pr->tokens[i]+1], &of->client_flags)) {
                    of->has_error = true;
                }
                break;
            case 'C': // mset, mdelete, marithmetic
                if (!safe_strtoull(&pr->request[pr->tokens[i]+1], &of->req_cas_id)) {
                    *errstr = "CLIENT_ERROR bad token in command line format";
                    of->has_error = true;
                } else {
                    of->has_cas = true;
                }
                break;
            case 'M': // mset and marithmetic mode switch
                // FIXME: this used to error if the token isn't a single byte.
                // It probably should still?
                of->mode = pr->request[pr->tokens[i]];
                break;
            case 'J': // marithmetic initial value
                if (!safe_strtoull(&pr->request[pr->tokens[i]+1], &of->initial)) {
                    *errstr = "CLIENT_ERROR invalid numeric initial value";
                    of->has_error = 1;
                }
                break;
            case 'D': // marithmetic delta value
                if (!safe_strtoull(&pr->request[pr->tokens[i]+1], &of->delta)) {
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

static void process_mget_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    size_t nkey = pr->klen;
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

    // FIXME: still needed?
    //WANT_TOKENS_MIN(ntokens, 3);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (pr->ntokens > MFLAG_MAX_OPT_LENGTH) {
        // TODO: ensure the command tokenizer gives us at least this many
        pout_errstring(resp, "CLIENT_ERROR options flags are too long");
        return;
    }

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 2, &of, &errstr) != 0) {
        pout_errstring(resp, errstr);
        return;
    }

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
            memcpy(p, "HD", 2);
            p += 2;
        }

        for (i = pr->keytoken+1; i < pr->ntokens; i++) {
            switch (pr->request[pr->tokens[i]]) {
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
                    tlen = _process_token_len(pr, i);
                    if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, &pr->request[pr->tokens[i]], tlen);
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
                if (proxy_storage_get(t, it, resp, PROXY_STORAGE_MG) != 0) {
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
        for (i = pr->keytoken+1; i < pr->ntokens; i++) {
            switch (pr->request[pr->tokens[i]]) {
                // TODO: macro perhaps?
                case 'O':
                    tlen = _process_token_len(pr, i);
                    if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, &pr->request[pr->tokens[i]], tlen);
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

static void process_mset_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    size_t nkey = pr->klen;

    item *it;
    int i;
    short comm = NREAD_SET;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    uint32_t hv; // cached hash value.
    int vlen = pr->vlen; // value from data line.
    assert(t != NULL);
    char *p = resp->wbuf;
    int tlen = 0;
    rel_time_t exptime = 0;

    //WANT_TOKENS_MIN(ntokens, 3);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (pr->ntokens > MFLAG_MAX_OPT_LENGTH) {
        // TODO: ensure the command tokenizer gives us at least this many
        pout_errstring(resp, "CLIENT_ERROR options flags are too long");
        return;
    }

    if (pr->ntokens == 3) {
        pout_errstring(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    // We need to at least try to get the size to properly slurp bad bytes
    // after an error.
    // we pass in the first token that should be a flag.
    if (_meta_flag_preparse(pr, 3, &of, &errstr) != 0) {
        goto error;
    }

    // "mode switch" to alternative commands
    switch (of.mode) {
        case 0:
            break; // no mode supplied.
        case 'E': // Add...
            comm = NREAD_ADD;
            break;
        case 'A': // Append.
            if (of.vivify) {
                comm = NREAD_APPENDVIV;
                exptime = of.autoviv_exptime;
            } else {
                comm = NREAD_APPEND;
            }
            break;
        case 'P': // Prepend.
            if (of.vivify) {
                comm = NREAD_PREPENDVIV;
                exptime = of.autoviv_exptime;
            } else {
                comm = NREAD_PREPEND;
            }
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

    it = item_alloc(key, nkey, of.client_flags, exptime, vlen);

    if (it == 0) {
        if (! item_size_ok(nkey, of.client_flags, vlen)) {
            errstr = "SERVER_ERROR object too large for cache";
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_too_large++;
            pthread_mutex_unlock(&t->stats.mutex);
        } else {
            errstr = "SERVER_ERROR out of memory storing object";
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.store_no_memory++;
            pthread_mutex_unlock(&t->stats.mutex);
        }

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

    bool set_stale = CAS_NO_STALE;
    if (of.set_stale && comm == NREAD_CAS) {
        set_stale = CAS_ALLOW_STALE;
    }
    resp->wbytes = p - resp->wbuf;

    pthread_mutex_lock(&t->stats.mutex);
    t->stats.slab_stats[ITEM_clsid(it)].set_cmds++;
    pthread_mutex_unlock(&t->stats.mutex);

    // complete_nread_proxy() does the data chunk check so all we need to do
    // is copy the data.
    if (_store_item_copy_from_buf(it, pr->vbuf, it->nbytes) != 0) {
        pout_string(resp, "SERVER_ERROR out of memory storing object");
        item_remove(it);
        return;
    }

    uint64_t cas = 0;
    int nbytes = 0;
    int ret = store_item(it, comm, t, &nbytes, &cas, set_stale);
    switch (ret) {
        case STORED:
          memcpy(p, "HD", 2);
          // Only place noreply is used for meta cmds is a nominal response.
          if (of.no_reply) {
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

    for (i = pr->keytoken+1; i < pr->ntokens; i++) {
        switch (pr->request[pr->tokens[i]]) {
            case 'O':
                tlen = _process_token_len(pr, i);
                if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                    errstr = "CLIENT_ERROR opaque token too long";
                    goto error;
                }
                META_SPACE(p);
                memcpy(p, &pr->request[pr->tokens[i]], tlen);
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

static void process_mdelete_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    size_t nkey = pr->klen;
    item *it = NULL;
    int i;
    uint32_t hv;
    struct _meta_flags of = {0}; // option bitflags.
    char *errstr = "CLIENT_ERROR bad command line format";
    assert(t != NULL);
    // reserve bytes for status code
    char *p = resp->wbuf + 2;
    int tlen = 0;

    //WANT_TOKENS_MIN(ntokens, 3);

    if (nkey > KEY_MAX_LENGTH) {
        pout_string(resp, "CLIENT_ERROR bad command line format");
        return;
    }

    if (pr->ntokens > MFLAG_MAX_OPT_LENGTH) {
        // TODO: ensure the command tokenizer gives us at least this many
        pout_errstring(resp, "CLIENT_ERROR options flags are too long");
        return;
    }

    // scrubs duplicated options and sets flags for how to load the item.
    // we pass in the first token that should be a flag.
    // FIXME: not using the preparse errstr?
    if (_meta_flag_preparse(pr, 2, &of, &errstr) != 0) {
        pout_errstring(resp, "CLIENT_ERROR invalid or duplicate flag");
        return;
    }

    for (i = pr->keytoken+1; i < pr->ntokens; i++) {
        switch (pr->request[pr->tokens[i]]) {
            // TODO: macro perhaps?
            case 'O':
                tlen = _process_token_len(pr, i);
                if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                    errstr = "CLIENT_ERROR opaque token too long";
                    goto error;
                }
                META_SPACE(p);
                memcpy(p, &pr->request[pr->tokens[i]], tlen);
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
            if (of.no_reply)
                resp->skip = true;
            memcpy(resp->wbuf, "HD", 2);
        } else {
            pthread_mutex_lock(&t->stats.mutex);
            t->stats.slab_stats[ITEM_clsid(it)].delete_hits++;
            pthread_mutex_unlock(&t->stats.mutex);

            do_item_unlink(it, hv);
            STORAGE_delete(t->storage, it);
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
    pout_errstring(resp, errstr);
}

static void process_marithmetic_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp) {
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
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

    if (pr->ntokens > MFLAG_MAX_OPT_LENGTH) {
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
    //c->noreply = of.no_reply;

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
        //if (c->noreply)
        //    resp->skip = true;
        // *it was filled, set the status below.
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
                if (do_store_item(it, NREAD_ADD, t, hv, NULL, &cas, CAS_NO_STALE)) {
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

        for (i = pr->keytoken+1; i < pr->ntokens; i++) {
            switch (pr->request[pr->tokens[i]]) {
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
                    memcpy(p, &pr->request[pr->tokens[i]], tlen);
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
        for (i = pr->keytoken+1; i < pr->ntokens; i++) {
            switch (pr->request[pr->tokens[i]]) {
                case 'O':
                    tlen = _process_token_len(pr, i);
                    if (tlen > MFLAG_MAX_OPAQUE_LENGTH) {
                        errstr = "CLIENT_ERROR opaque token too long";
                        goto error;
                    }
                    META_SPACE(p);
                    memcpy(p, &pr->request[pr->tokens[i]], tlen);
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

/*** Lua and internal handler ***/

int mcplib_internal(lua_State *L) {
    luaL_checkudata(L, 1, "mcp.request");
    mcp_resp_t *r = lua_newuserdatauv(L, sizeof(mcp_resp_t), 0);
    memset(r, 0, sizeof(mcp_resp_t));
    luaL_getmetatable(L, "mcp.response");
    lua_setmetatable(L, -2);

    lua_pushinteger(L, MCP_YIELD_LOCAL);
    return lua_yield(L, 2);
}

// we're pretending to be p_c_ascii(), but reusing our already tokenized code.
// the text parser should eventually move to the new tokenizer and we can
// merge all of this code together.
int mcplib_internal_run(lua_State *L, conn *c, mc_resp *top_resp, int coro_ref) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    mcp_resp_t *r = luaL_checkudata(L, 2, "mcp.response");
    mc_resp *resp = resp_start_unlinked(c);
    LIBEVENT_THREAD *t = c->thread;
    mcp_parser_t *pr = &rq->pr;
    if (resp == NULL) {
        return -1;
    }

    // TODO: meta no-op isn't handled here. haven't decided how yet.
    switch (rq->pr.command) {
        case CMD_MG:
            process_mget_cmd(t, pr, resp);
            break;
        case CMD_MS:
            process_mset_cmd(t, pr, resp);
            break;
        case CMD_MD:
            process_mdelete_cmd(t, pr, resp);
            break;
        case CMD_MA:
            process_marithmetic_cmd(t, pr, resp);
            break;
        case CMD_GET:
            process_get_cmd(t, pr, resp, _NO_CAS, _NO_TOUCH);
            break;
        case CMD_GETS:
            process_get_cmd(t, pr, resp, _DO_CAS, _NO_TOUCH);
            break;
        case CMD_GAT:
            process_get_cmd(t, pr, resp, _NO_CAS, _DO_TOUCH);
            break;
        case CMD_GATS:
            process_get_cmd(t, pr, resp, _DO_CAS, _DO_TOUCH);
            break;
        case CMD_SET:
            process_update_cmd(t, pr, resp, NREAD_SET, _NO_CAS);
            break;
        case CMD_ADD:
            process_update_cmd(t, pr, resp, NREAD_ADD, _NO_CAS);
            break;
        case CMD_APPEND:
            process_update_cmd(t, pr, resp, NREAD_APPEND, _NO_CAS);
            break;
        case CMD_PREPEND:
            process_update_cmd(t, pr, resp, NREAD_PREPEND, _NO_CAS);
            break;
        case CMD_CAS:
            process_update_cmd(t, pr, resp, NREAD_CAS, _DO_CAS);
            break;
        case CMD_REPLACE:
            process_update_cmd(t, pr, resp, NREAD_REPLACE, _DO_CAS);
            break;
        case CMD_INCR:
            process_arithmetic_cmd(t, pr, resp, true);
            break;
        case CMD_DECR:
            process_arithmetic_cmd(t, pr, resp, false);
            break;
        case CMD_DELETE:
            process_delete_cmd(t, pr, resp);
            break;
        case CMD_TOUCH:
            process_touch_cmd(t, pr, resp);
            break;
        default:
            resp_free(t, resp);
            return -1;
    }

    // TODO: I'd like to shortcut the parsing here, but if we want the resp
    // object to have full support (ie: resp:line()/etc) it might be necessary
    // to still do a full parsing. It might be possible to
    // wrap the main commands with something that decorates r->resp directly
    // instead of going through a parser to save some CPU.
    // Either way this is a lot less code.
    mcmc_bare_parse_buf(resp->iov[0].iov_base, resp->iov[0].iov_len, &r->resp);

    // in case someone logs this response it should make sense.
    memcpy(r->be_name, "internal", strlen("internal"));
    memcpy(r->be_port, "0", 1);

    // TODO: r-> will need status/code/mode copied from resp.
    r->cresp = resp;
    r->thread = c->thread;
    r->cmd = rq->pr.command;
    // Always return OK from here as this is signalling an internal error.
    r->status = MCMC_OK;

    if (resp->io_pending) {
        // TODO (v2): here we move the IO from the temporary resp to the top
        // resp, but this feels kludgy so I'm leaving an explicit note to find
        // a better way to do this.
        top_resp->io_pending = resp->io_pending;
        resp->io_pending = NULL;

        // Add io object to extstore submission queue.
        io_queue_t *q = conn_io_queue_get(c, IO_QUEUE_EXTSTORE);
        io_pending_proxy_t *io = (io_pending_proxy_t *)top_resp->io_pending;

        io->eio.next = q->stack_ctx;
        q->stack_ctx = &io->eio;
        assert(q->count >= 0);
        q->count++;

        io->coro_ref = coro_ref;
        io->coro = L;
        io->c  = c;
        // we need to associate the top level mc_resp here so the run routine
        // can fill it in later.
        io->resp = top_resp;
        // mark the buffer into the mcp_resp for freeing later.
        r->buf = io->eio.buf;
        return 1;
    }
    return 0;
}
