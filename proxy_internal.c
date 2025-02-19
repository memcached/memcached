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

// FIXME: func or macro from storage for crc check
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
static int _proxy_storage_get(LIBEVENT_THREAD *t, item *it, mc_resp *resp,
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
    io->io_queue_type = IO_QUEUE_PROXY;
    io->io_sub_type = IO_PENDING_TYPE_EXTSTORE; // proxy specific sub-type.
    io->gettype = type;
    io->thread = t;
    io->return_cb = proxy_return_rctx_cb;
    io->finalize_cb = proxy_finalize_rctx_cb;
    io->payload = offsetof(io_pending_proxy_t, eio);
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

static int proxy_storage_mg(LIBEVENT_THREAD *t, item *it, mc_resp *resp) {
    return _proxy_storage_get(t, it, resp, PROXY_STORAGE_MG);
}

static int proxy_storage_get(LIBEVENT_THREAD *t, item *it, mc_resp *resp) {
    return _proxy_storage_get(t, it, resp, PROXY_STORAGE_GET);
}

static void proxy_get_cmd(LIBEVENT_THREAD *t, mcp_parser_t *pr, mc_resp *resp, bool return_cas, bool should_touch) {
    rel_time_t exptime = 0;
    if (should_touch) {
        if (!mc_parse_exptime(resp, pr, 1, &exptime)) {
            // function fills resp with error.
            return;
        }
    }

    if (process_get_cmd(t, MCP_PARSER_KEY(pr), pr->klen, resp, proxy_storage_get, exptime, return_cas, should_touch) == 0) {
        resp_add_iov(resp, "END\r\n", 5);
    }
}

#endif // EXTSTORE

/*** Lua and internal handler ***/

static inline int _mcplib_internal_run(LIBEVENT_THREAD *t, mcp_request_t *rq, mcp_resp_t *r, mc_resp *resp) {
    mcp_parser_t *pr = &rq->pr;

    resp->noreply = pr->noreply;
    // TODO: meta no-op isn't handled here. haven't decided how yet.
    switch (pr->command) {
        case CMD_MG:
            process_mget_cmd(t, pr, resp, proxy_storage_mg);
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
            proxy_get_cmd(t, pr, resp, _NO_CAS, _NO_TOUCH);
            break;
        case CMD_GETS:
            proxy_get_cmd(t, pr, resp, _DO_CAS, _NO_TOUCH);
            break;
        case CMD_GAT:
            proxy_get_cmd(t, pr, resp, _NO_CAS, _DO_TOUCH);
            break;
        case CMD_GATS:
            proxy_get_cmd(t, pr, resp, _DO_CAS, _DO_TOUCH);
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
    mcmc_parse_buf(resp->iov[0].iov_base, resp->iov[0].iov_len, &r->resp);

    r->cresp = resp;
    r->thread = t;
    r->cmd = rq->pr.command;
    // Always return OK from here as this is signalling an internal error.
    r->status = MCMC_OK;

    return 0;
}

int mcplib_internal(lua_State *L) {
    luaL_checkudata(L, 1, "mcp.request");
    mcp_resp_t *r = lua_newuserdatauv(L, sizeof(mcp_resp_t), 0);
    memset(r, 0, sizeof(mcp_resp_t));
    luaL_getmetatable(L, "mcp.response");
    lua_setmetatable(L, -2);

    lua_pushinteger(L, MCP_YIELD_INTERNAL);
    return lua_yield(L, 2);
}

// V2 API internal handling.
void *mcp_rcontext_internal(mcp_rcontext_t *rctx, mcp_request_t *rq, mcp_resp_t *r) {
    LIBEVENT_THREAD *t = rctx->fgen->thread;
    mc_resp *resp = resp_start_unlinked(rctx->c);
    if (resp == NULL) {
        return NULL;
    }

    // TODO: release resp here instead on error?
    if (_mcplib_internal_run(t, rq, r, resp) != 0) {
        return NULL;
    }

    return resp;
}

// we're pretending to be p_c_ascii(), but reusing our already tokenized code.
// the text parser should eventually move to the new tokenizer and we can
// merge all of this code together.
int mcplib_internal_run(mcp_rcontext_t *rctx) {
    lua_State *L = rctx->Lc;
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    mcp_resp_t *r = luaL_checkudata(L, 2, "mcp.response");
    mc_resp *resp = resp_start_unlinked(rctx->c);
    LIBEVENT_THREAD *t = rctx->c->thread;
    if (resp == NULL) {
        return -1;
    }

    t->cur_sfd = rctx->conn_fd;
    _mcplib_internal_run(t, rq, r, resp);

    // resp object is associated with the
    // response object, which is about a
    // kilobyte.
    t->proxy_vm_extra_kb++;

    if (resp->io_pending) {
        // TODO (v2): here we move the IO from the temporary resp to the top
        // resp, but this feels kludgy so I'm leaving an explicit note to find
        // a better way to do this.
        rctx->resp->io_pending = resp->io_pending;
        resp->io_pending = NULL;

        // Add io object to extstore submission queue.
        io_queue_t *q = thread_io_queue_get(rctx->fgen->thread, IO_QUEUE_EXTSTORE);
        io_pending_proxy_t *io = (io_pending_proxy_t *)rctx->resp->io_pending;

        STAILQ_INSERT_TAIL(&q->stack, (io_pending_t *)io, iop_next);

        io->rctx = rctx;
        io->c = rctx->c;
        // mark the buffer into the mcp_resp for freeing later.
        r->buf = io->eio.buf;
        return 1;
    }

    return 0;
}
