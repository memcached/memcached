/*  Copyright 2016 Netflix.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 */

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <poll.h>

#define LARGEST_ID POWER_LARGEST

typedef struct {
    void *c; /* original connection structure. still with source thread attached. */
    int sfd; /* client fd. */
    bipbuf_t *buf; /* output buffer */
    char *cbuf; /* current buffer */
} crawler_client_t;

typedef struct _crawler_module_t crawler_module_t;

typedef void (*crawler_eval_func)(crawler_module_t *cm, item *it, uint32_t hv, int slab_cls);
typedef int (*crawler_init_func)(crawler_module_t *cm, void *data); // TODO: init args?
typedef void (*crawler_deinit_func)(crawler_module_t *cm); // TODO: extra args?
typedef void (*crawler_doneclass_func)(crawler_module_t *cm, int slab_cls);
typedef void (*crawler_finalize_func)(crawler_module_t *cm);

typedef struct {
    crawler_init_func init; /* run before crawl starts */
    crawler_eval_func eval; /* runs on an item. */
    crawler_doneclass_func doneclass; /* runs once per sub-crawler completion. */
    crawler_finalize_func finalize; /* runs once when all sub-crawlers are done. */
    bool needs_lock; /* whether or not we need the LRU lock held when eval is called */
    bool needs_client; /* whether or not to grab onto the remote client */
} crawler_module_reg_t;

struct _crawler_module_t {
    void *data; /* opaque data pointer */
    crawler_client_t c;
    crawler_module_reg_t *mod;
};

static int crawler_expired_init(crawler_module_t *cm, void *data);
static void crawler_expired_doneclass(crawler_module_t *cm, int slab_cls);
static void crawler_expired_finalize(crawler_module_t *cm);
static void crawler_expired_eval(crawler_module_t *cm, item *search, uint32_t hv, int i);

crawler_module_reg_t crawler_expired_mod = {
    .init = crawler_expired_init,
    .eval = crawler_expired_eval,
    .doneclass = crawler_expired_doneclass,
    .finalize = crawler_expired_finalize,
    .needs_lock = true,
    .needs_client = false
};

static void crawler_metadump_eval(crawler_module_t *cm, item *search, uint32_t hv, int i);

crawler_module_reg_t crawler_metadump_mod = {
    .init = NULL,
    .eval = crawler_metadump_eval,
    .doneclass = NULL,
    .finalize = NULL,
    .needs_lock = false,
    .needs_client = true
};

crawler_module_reg_t *crawler_mod_regs[2] = {
    &crawler_expired_mod,
    &crawler_metadump_mod
};

crawler_module_t active_crawler_mod;

static crawler crawlers[LARGEST_ID];

static int crawler_count = 0;
static volatile int do_run_lru_crawler_thread = 0;
static int lru_crawler_initialized = 0;
static pthread_mutex_t lru_crawler_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  lru_crawler_cond = PTHREAD_COND_INITIALIZER;

/* Will crawl all slab classes a minimum of once per hour */
#define MAX_MAINTCRAWL_WAIT 60 * 60

/*** LRU CRAWLER THREAD ***/

#define LRU_CRAWLER_WRITEBUF 8192

static void lru_crawler_close_client(crawler_client_t *c) {
    //fprintf(stderr, "CRAWLER: Closing client\n");
    sidethread_conn_close(c->c);
    c->c = NULL;
    c->cbuf = NULL;
    bipbuf_free(c->buf);
    c->buf = NULL;
}

static void lru_crawler_release_client(crawler_client_t *c) {
    //fprintf(stderr, "CRAWLER: Closing client\n");
    redispatch_conn(c->c);
    c->c = NULL;
    c->cbuf = NULL;
    bipbuf_free(c->buf);
    c->buf = NULL;
}

static int crawler_expired_init(crawler_module_t *cm, void *data) {
    struct crawler_expired_data *d;
    if (data != NULL) {
        d = data;
        d->is_external = true;
        cm->data = data;
    } else {
        // allocate data.
        d = calloc(1, sizeof(struct crawler_expired_data));
        if (d == NULL) {
            return -1;
        }
        // init lock.
        pthread_mutex_init(&d->lock, NULL);
        d->is_external = false;
        d->start_time = current_time;

        cm->data = d;
    }
    pthread_mutex_lock(&d->lock);
    memset(&d->crawlerstats, 0, sizeof(crawlerstats_t) * MAX_NUMBER_OF_SLAB_CLASSES);
    for (int x = 0; x < MAX_NUMBER_OF_SLAB_CLASSES; x++) {
        d->crawlerstats[x].start_time = current_time;
        d->crawlerstats[x].run_complete = false;
    }
    pthread_mutex_unlock(&d->lock);
    return 0;
}

static void crawler_expired_doneclass(crawler_module_t *cm, int slab_cls) {
    struct crawler_expired_data *d = (struct crawler_expired_data *) cm->data;
    pthread_mutex_lock(&d->lock);
    d->crawlerstats[CLEAR_LRU(slab_cls)].end_time = current_time;
    d->crawlerstats[CLEAR_LRU(slab_cls)].run_complete = true;
    pthread_mutex_unlock(&d->lock);
}

static void crawler_expired_finalize(crawler_module_t *cm) {
    struct crawler_expired_data *d = (struct crawler_expired_data *) cm->data;
    pthread_mutex_lock(&d->lock);
    d->end_time = current_time;
    d->crawl_complete = true;
    pthread_mutex_unlock(&d->lock);

    if (!d->is_external) {
        free(d);
    }
}

/* I pulled this out to make the main thread clearer, but it reaches into the
 * main thread's values too much. Should rethink again.
 */
static void crawler_expired_eval(crawler_module_t *cm, item *search, uint32_t hv, int i) {
    int slab_id = CLEAR_LRU(i);
    struct crawler_expired_data *d = (struct crawler_expired_data *) cm->data;
    pthread_mutex_lock(&d->lock);
    crawlerstats_t *s = &d->crawlerstats[slab_id];
    int is_flushed = item_is_flushed(search);
    if ((search->exptime != 0 && search->exptime < current_time)
        || is_flushed) {
        crawlers[i].reclaimed++;
        s->reclaimed++;

        if (settings.verbose > 1) {
            int ii;
            char *key = ITEM_key(search);
            fprintf(stderr, "LRU crawler found an expired item (flags: %d, slab: %d): ",
                search->it_flags, search->slabs_clsid);
            for (ii = 0; ii < search->nkey; ++ii) {
                fprintf(stderr, "%c", key[ii]);
            }
            fprintf(stderr, "\n");
        }
        if ((search->it_flags & ITEM_FETCHED) == 0 && !is_flushed) {
            crawlers[i].unfetched++;
        }
        do_item_unlink_nolock(search, hv);
        do_item_remove(search);
        assert(search->slabs_clsid == 0);
    } else {
        s->seen++;
        refcount_decr(search);
        if (search->exptime == 0) {
            s->noexp++;
        } else if (search->exptime - current_time > 3599) {
            s->ttl_hourplus++;
        } else {
            rel_time_t ttl_remain = search->exptime - current_time;
            int bucket = ttl_remain / 60;
            s->histo[bucket]++;
        }
    }
    pthread_mutex_unlock(&d->lock);
}

static void crawler_metadump_eval(crawler_module_t *cm, item *it, uint32_t hv, int i) {
    //int slab_id = CLEAR_LRU(i);
    char keybuf[KEY_MAX_LENGTH * 3 + 1];
    int is_flushed = item_is_flushed(it);
    /* Ignore expired content. */
    if ((it->exptime != 0 && it->exptime < current_time)
        || is_flushed) {
        refcount_decr(it);
        return;
    }
    // TODO: uriencode directly into the buffer.
    uriencode(ITEM_key(it), keybuf, it->nkey, KEY_MAX_LENGTH * 3 + 1);
    int total = snprintf(cm->c.cbuf, 4096,
            "key=%s exp=%ld la=%llu cas=%llu fetch=%s\n",
            keybuf,
            (it->exptime == 0) ? -1 : (long)it->exptime + process_started,
            (unsigned long long)it->time + process_started,
            (unsigned long long)ITEM_get_cas(it),
            (it->it_flags & ITEM_FETCHED) ? "yes" : "no");
    refcount_decr(it);
    // TODO: some way of tracking the errors. these are very unlikely though.
    if (total >= LRU_CRAWLER_WRITEBUF - 1 || total <= 0) {
        /* Failed to write, don't push it. */
        return;
    }
    bipbuf_push(cm->c.buf, total);
}

static int lru_crawler_poll(crawler_client_t *c) {
    unsigned char *data;
    unsigned int data_size = 0;
    struct pollfd to_poll[1];
    to_poll[0].fd = c->sfd;
    to_poll[0].events = POLLOUT;

    int ret = poll(to_poll, 1, 1000);

    if (ret < 0) {
        // fatal.
        return -1;
    }

    if (ret == 0) return 0;

    if (to_poll[0].revents & POLLIN) {
        char buf[1];
        int res = read(c->sfd, buf, 1);
        if (res == 0 || (res == -1 && (errno != EAGAIN && errno != EWOULDBLOCK))) {
            lru_crawler_close_client(c);
            return -1;
        }
    }
    if ((data = bipbuf_peek_all(c->buf, &data_size)) != NULL) {
        if (to_poll[0].revents & (POLLHUP|POLLERR)) {
            lru_crawler_close_client(c);
            return -1;
        } else if (to_poll[0].revents & POLLOUT) {
            int total = write(c->sfd, data, data_size);
            if (total == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    lru_crawler_close_client(c);
                    return -1;
                }
            } else if (total == 0) {
                lru_crawler_close_client(c);
                return -1;
            } else {
                bipbuf_poll(c->buf, total);
            }
        }
    }
    return 0;
}

/* Grab some space to work with, if none exists, run the poll() loop and wait
 * for it to clear up or close.
 * Return NULL if closed.
 */
static int lru_crawler_client_getbuf(crawler_client_t *c) {
    void *buf = NULL;
    if (c->c == NULL) return -1;
    /* not enough space. */
    while ((buf = bipbuf_request(c->buf, LRU_CRAWLER_WRITEBUF)) == NULL) {
        // TODO: max loops before closing.
        int ret = lru_crawler_poll(c);
        if (ret < 0) return ret;
    }

    c->cbuf = buf;
    return 0;
}

static void lru_crawler_class_done(int i) {
    crawlers[i].it_flags = 0;
    crawler_count--;
    do_item_unlinktail_q((item *)&crawlers[i]);
    do_item_stats_add_crawl(i, crawlers[i].reclaimed,
            crawlers[i].unfetched, crawlers[i].checked);
    pthread_mutex_unlock(&lru_locks[i]);
    if (active_crawler_mod.mod->doneclass != NULL)
        active_crawler_mod.mod->doneclass(&active_crawler_mod, i);
}

static void *item_crawler_thread(void *arg) {
    int i;
    int crawls_persleep = settings.crawls_persleep;

    pthread_mutex_lock(&lru_crawler_lock);
    pthread_cond_signal(&lru_crawler_cond);
    settings.lru_crawler = true;
    if (settings.verbose > 2)
        fprintf(stderr, "Starting LRU crawler background thread\n");
    while (do_run_lru_crawler_thread) {
    pthread_cond_wait(&lru_crawler_cond, &lru_crawler_lock);

    while (crawler_count) {
        item *search = NULL;
        void *hold_lock = NULL;

        for (i = POWER_SMALLEST; i < LARGEST_ID; i++) {
            if (crawlers[i].it_flags != 1) {
                continue;
            }

            /* Get memory from bipbuf, if client has no space, flush. */
            if (active_crawler_mod.c.c != NULL) {
                int ret = lru_crawler_client_getbuf(&active_crawler_mod.c);
                if (ret != 0) {
                    lru_crawler_class_done(i);
                    continue;
                }
            } else if (active_crawler_mod.mod->needs_client) {
                lru_crawler_class_done(i);
                continue;
            }
            pthread_mutex_lock(&lru_locks[i]);
            search = do_item_crawl_q((item *)&crawlers[i]);
            if (search == NULL ||
                (crawlers[i].remaining && --crawlers[i].remaining < 1)) {
                if (settings.verbose > 2)
                    fprintf(stderr, "Nothing left to crawl for %d\n", i);
                lru_crawler_class_done(i);
                continue;
            }
            uint32_t hv = hash(ITEM_key(search), search->nkey);
            /* Attempt to hash item lock the "search" item. If locked, no
             * other callers can incr the refcount
             */
            if ((hold_lock = item_trylock(hv)) == NULL) {
                pthread_mutex_unlock(&lru_locks[i]);
                continue;
            }
            /* Now see if the item is refcount locked */
            if (refcount_incr(search) != 2) {
                refcount_decr(search);
                if (hold_lock)
                    item_trylock_unlock(hold_lock);
                pthread_mutex_unlock(&lru_locks[i]);
                continue;
            }

            crawlers[i].checked++;
            /* Frees the item or decrements the refcount. */
            /* Interface for this could improve: do the free/decr here
             * instead? */
            if (!active_crawler_mod.mod->needs_lock) {
                pthread_mutex_unlock(&lru_locks[i]);
            }

            active_crawler_mod.mod->eval(&active_crawler_mod, search, hv, i);

            if (hold_lock)
                item_trylock_unlock(hold_lock);
            if (active_crawler_mod.mod->needs_lock) {
                pthread_mutex_unlock(&lru_locks[i]);
            }

            if (crawls_persleep-- <= 0 && settings.lru_crawler_sleep) {
                usleep(settings.lru_crawler_sleep);
                crawls_persleep = settings.crawls_persleep;
            }
        }
    }

    if (active_crawler_mod.mod != NULL) {
        if (active_crawler_mod.mod->finalize != NULL)
            active_crawler_mod.mod->finalize(&active_crawler_mod);
        while (active_crawler_mod.c.c != NULL && bipbuf_used(active_crawler_mod.c.buf)) {
            lru_crawler_poll(&active_crawler_mod.c);
        }
        // Double checking in case the client closed during the poll
        if (active_crawler_mod.c.c != NULL) {
            lru_crawler_release_client(&active_crawler_mod.c);
        }
        active_crawler_mod.mod = NULL;
    }

    if (settings.verbose > 2)
        fprintf(stderr, "LRU crawler thread sleeping\n");
    STATS_LOCK();
    stats_state.lru_crawler_running = false;
    STATS_UNLOCK();
    }
    pthread_mutex_unlock(&lru_crawler_lock);
    if (settings.verbose > 2)
        fprintf(stderr, "LRU crawler thread stopping\n");

    return NULL;
}

static pthread_t item_crawler_tid;

int stop_item_crawler_thread(void) {
    int ret;
    pthread_mutex_lock(&lru_crawler_lock);
    do_run_lru_crawler_thread = 0;
    pthread_cond_signal(&lru_crawler_cond);
    pthread_mutex_unlock(&lru_crawler_lock);
    if ((ret = pthread_join(item_crawler_tid, NULL)) != 0) {
        fprintf(stderr, "Failed to stop LRU crawler thread: %s\n", strerror(ret));
        return -1;
    }
    settings.lru_crawler = false;
    return 0;
}

/* Lock dance to "block" until thread is waiting on its condition:
 * caller locks mtx. caller spawns thread.
 * thread blocks on mutex.
 * caller waits on condition, releases lock.
 * thread gets lock, sends signal.
 * caller can't wait, as thread has lock.
 * thread waits on condition, releases lock
 * caller wakes on condition, gets lock.
 * caller immediately releases lock.
 * thread is now safely waiting on condition before the caller returns.
 */
int start_item_crawler_thread(void) {
    int ret;

    if (settings.lru_crawler)
        return -1;
    pthread_mutex_lock(&lru_crawler_lock);
    do_run_lru_crawler_thread = 1;
    if ((ret = pthread_create(&item_crawler_tid, NULL,
        item_crawler_thread, NULL)) != 0) {
        fprintf(stderr, "Can't create LRU crawler thread: %s\n",
            strerror(ret));
        pthread_mutex_unlock(&lru_crawler_lock);
        return -1;
    }
    /* Avoid returning until the crawler has actually started */
    pthread_cond_wait(&lru_crawler_cond, &lru_crawler_lock);
    pthread_mutex_unlock(&lru_crawler_lock);

    return 0;
}

/* 'remaining' is passed in so the LRU maintainer thread can scrub the whole
 * LRU every time.
 */
static int do_lru_crawler_start(uint32_t id, uint32_t remaining) {
    int i;
    uint32_t sid;
    uint32_t tocrawl[3];
    int starts = 0;
    tocrawl[0] = id | HOT_LRU;
    tocrawl[1] = id | WARM_LRU;
    tocrawl[2] = id | COLD_LRU;

    for (i = 0; i < 3; i++) {
        sid = tocrawl[i];
        pthread_mutex_lock(&lru_locks[sid]);
        // TODO: Pretty sure this is a needless optimization.
        //if (tails[sid] != NULL) {
            if (settings.verbose > 2)
                fprintf(stderr, "Kicking LRU crawler off for LRU %u\n", sid);
            crawlers[sid].nbytes = 0;
            crawlers[sid].nkey = 0;
            crawlers[sid].it_flags = 1; /* For a crawler, this means enabled. */
            crawlers[sid].next = 0;
            crawlers[sid].prev = 0;
            crawlers[sid].time = 0;
            crawlers[sid].remaining = remaining;
            crawlers[sid].slabs_clsid = sid;
            crawlers[sid].reclaimed = 0;
            crawlers[sid].unfetched = 0;
            crawlers[sid].checked = 0;
            do_item_linktail_q((item *)&crawlers[sid]);
            crawler_count++;
            starts++;
        //}
        pthread_mutex_unlock(&lru_locks[sid]);
    }
    if (starts) {
        STATS_LOCK();
        stats_state.lru_crawler_running = true;
        stats.lru_crawler_starts++;
        STATS_UNLOCK();
    }
    return starts;
}

static int lru_crawler_set_client(crawler_module_t *cm, void *c, const int sfd) {
    crawler_client_t *crawlc = &cm->c;
    if (crawlc->c != NULL) {
        return -1;
    }
    crawlc->c = c;
    crawlc->sfd = sfd;

    crawlc->buf = bipbuf_new(1024 * 128);
    if (crawlc->buf == NULL) {
        return -2;
    }
    return 0;
}

int lru_crawler_start(uint8_t *ids, uint32_t remaining,
                             const enum crawler_run_type type, void *data,
                             void *c, const int sfd) {
    int starts = 0;
    if (pthread_mutex_trylock(&lru_crawler_lock) != 0) {
        return -1;
    }

    /* Configure the module */
    assert(crawler_mod_regs[type] != NULL);
    active_crawler_mod.mod = crawler_mod_regs[type];
    if (active_crawler_mod.mod->init != NULL) {
        active_crawler_mod.mod->init(&active_crawler_mod, data);
    }
    if (active_crawler_mod.mod->needs_client) {
        if (c == NULL || sfd == 0) {
            pthread_mutex_unlock(&lru_crawler_lock);
            return -2;
        }
        if (lru_crawler_set_client(&active_crawler_mod, c, sfd) != 0) {
            pthread_mutex_unlock(&lru_crawler_lock);
            return -2;
        }
    }

    for (int sid = POWER_SMALLEST; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
        if (ids[sid]) {
            starts += do_lru_crawler_start(sid, remaining);
        }
    }
    if (starts) {
        pthread_cond_signal(&lru_crawler_cond);
    }
    pthread_mutex_unlock(&lru_crawler_lock);
    return starts;
}

/*
 * Also only clear the crawlerstats once per sid.
 */
enum crawler_result_type lru_crawler_crawl(char *slabs, const enum crawler_run_type type,
        void *c, const int sfd) {
    char *b = NULL;
    uint32_t sid = 0;
    int starts = 0;
    uint8_t tocrawl[MAX_NUMBER_OF_SLAB_CLASSES];

    /* FIXME: I added this while debugging. Don't think it's needed? */
    memset(tocrawl, 0, sizeof(uint8_t) * MAX_NUMBER_OF_SLAB_CLASSES);
    if (strcmp(slabs, "all") == 0) {
        for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
            tocrawl[sid] = 1;
        }
    } else {
        for (char *p = strtok_r(slabs, ",", &b);
             p != NULL;
             p = strtok_r(NULL, ",", &b)) {

            if (!safe_strtoul(p, &sid) || sid < POWER_SMALLEST
                    || sid >= MAX_NUMBER_OF_SLAB_CLASSES) {
                pthread_mutex_unlock(&lru_crawler_lock);
                return CRAWLER_BADCLASS;
            }
            tocrawl[sid] = 1;
        }
    }

    starts = lru_crawler_start(tocrawl, settings.lru_crawler_tocrawl,
            type, NULL, c, sfd);
    if (starts == -1) {
        return CRAWLER_RUNNING;
    } else if (starts == -2) {
        return CRAWLER_ERROR; /* FIXME: not very helpful. */
    } else if (starts) {
        return CRAWLER_OK;
    } else {
        return CRAWLER_NOTSTARTED;
    }
}

/* If we hold this lock, crawler can't wake up or move */
void lru_crawler_pause(void) {
    pthread_mutex_lock(&lru_crawler_lock);
}

void lru_crawler_resume(void) {
    pthread_mutex_unlock(&lru_crawler_lock);
}

int init_lru_crawler(void) {
    if (lru_crawler_initialized == 0) {
        if (pthread_cond_init(&lru_crawler_cond, NULL) != 0) {
            fprintf(stderr, "Can't initialize lru crawler condition\n");
            return -1;
        }
        pthread_mutex_init(&lru_crawler_lock, NULL);
        active_crawler_mod.c.c = NULL;
        active_crawler_mod.mod = NULL;
        active_crawler_mod.data = NULL;
        lru_crawler_initialized = 1;
    }
    return 0;
}
