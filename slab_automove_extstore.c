/*  Copyright 2017 Facebook.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 */

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include "slab_automove_extstore.h"
#include <stdlib.h>
#include <string.h>

#define MIN_PAGES_FOR_SOURCE 2
#define MIN_PAGES_FOR_RECLAIM 2.5
#define MIN_PAGES_FREE 1.5
#define MEMCHECK_PERIOD 60

struct window_data {
    uint64_t age;
    uint64_t dirty;
    uint64_t evicted;
    unsigned int excess_free;
    unsigned int relaxed;
};

struct window_global {
    uint32_t pool_low;
    uint32_t pool_high;
};

typedef struct {
    struct window_data *window_data;
    struct window_global *window_global;
    struct settings *settings;
    uint32_t window_size;
    uint32_t window_cur;
    uint32_t item_size;
    rel_time_t last_memcheck_run;
    double max_age_ratio;
    double free_ratio;
    bool pool_filled_once;
    unsigned int free_mem[MAX_NUMBER_OF_SLAB_CLASSES];
    item_stats_automove iam_before[MAX_NUMBER_OF_SLAB_CLASSES];
    item_stats_automove iam_after[MAX_NUMBER_OF_SLAB_CLASSES];
    slab_stats_automove sam_before[MAX_NUMBER_OF_SLAB_CLASSES];
    slab_stats_automove sam_after[MAX_NUMBER_OF_SLAB_CLASSES];
} slab_automove;

void *slab_automove_extstore_init(struct settings *settings) {
    uint32_t window_size = settings->slab_automove_window;
    double max_age_ratio = settings->slab_automove_ratio;
    slab_automove *a = calloc(1, sizeof(slab_automove));
    if (a == NULL)
        return NULL;
    a->window_data = calloc(window_size * MAX_NUMBER_OF_SLAB_CLASSES, sizeof(struct window_data));
    a->window_global = calloc(window_size, sizeof(struct window_global));
    a->window_size = window_size;
    a->max_age_ratio = max_age_ratio;
    a->free_ratio = settings->slab_automove_freeratio;
    a->item_size = settings->ext_item_size;
    a->last_memcheck_run = 0;
    a->settings = settings;
    a->pool_filled_once = false;
    if (a->window_data == NULL || a->window_global == NULL) {
        if (a->window_data)
            free(a->window_data);
        if (a->window_global)
            free(a->window_global);
        free(a);
        return NULL;
    }

    // do a dry run to fill the before structs
    fill_item_stats_automove(a->iam_before);
    fill_slab_stats_automove(a->sam_before);

    return (void *)a;
}

void slab_automove_extstore_free(void *arg) {
    slab_automove *a = (slab_automove *)arg;
    free(a->window_data);
    free(a);
}

static void window_sum(struct window_data *wd, struct window_data *w,
        uint32_t size) {
    for (int x = 0; x < size; x++) {
        struct window_data *d = &wd[x];
        w->age += d->age;
        w->dirty += d->dirty;
        w->evicted += d->evicted;
        w->excess_free += d->excess_free;
        w->relaxed += d->relaxed;
    }
}

/* This could potentially merge with above */
static void window_global_sum(struct window_global *wg,
        struct window_global *w, uint32_t size) {
    for (int x = 0; x < size; x++) {
        struct window_global *d = &wg[x];
        w->pool_high += d->pool_high;
        w->pool_low += d->pool_low;
    }
}

static void global_pool_check(slab_automove *a) {
    bool mem_limit_reached;
    uint32_t free = a->free_mem[0];
    struct window_global *wg = &a->window_global[a->window_cur % a->window_size];
    unsigned int count = global_page_pool_size(&mem_limit_reached);
    memset(wg, 0, sizeof(struct window_global));
    if (!mem_limit_reached)
        return;
    if (count < free / 2) {
        wg->pool_low = 1;
        a->pool_filled_once = true;
    } else if (count > free) {
        wg->pool_high = 1;
    } else {
        a->pool_filled_once = true;
    }
}

/* A percentage of memory is configured to be held "free" as buffers for the
 * external storage system.
 * % of global memory is desired in the global page pool
 * each slab class has a % of free chunks desired based on how much memory is
 * currently in the class. This allows time for extstore to flush data when
 * spikes or waves of set data arrive.
 * The global page pool reserve acts as a secondary buffer for any slab class,
 * which helps absorb shifts in which class is active.
 */
static void memcheck(slab_automove *a) {
    unsigned int total_pages = 0;
    if (current_time < a->last_memcheck_run + MEMCHECK_PERIOD)
        return;
    a->last_memcheck_run = current_time;
    for (int n = 1; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        slab_stats_automove *sam = &a->sam_after[n];
        total_pages += sam->total_pages;
        unsigned int hold_free = (sam->total_pages * sam->chunks_per_page)
            * a->free_ratio;
        if (sam->chunks_per_page * MIN_PAGES_FREE > hold_free)
            hold_free = sam->chunks_per_page * MIN_PAGES_FREE;
        a->free_mem[n] = hold_free;
        if (a->settings->ext_free_memchunks[n] != hold_free && a->pool_filled_once) {
            a->settings->ext_free_memchunks[n] = hold_free;
        }
    }
    // remember to add what remains in global pool.
    total_pages += a->sam_after[0].total_pages;
    a->free_mem[0] = total_pages * a->free_ratio;
}

static struct window_data *get_window_data(slab_automove *a, int class) {
    int w_offset = class * a->window_size;
    return &a->window_data[w_offset + (a->window_cur % a->window_size)];
}

void slab_automove_extstore_run(void *arg, int *src, int *dst) {
    slab_automove *a = (slab_automove *)arg;
    int n;
    struct window_data w_sum;
    int oldest = -1;
    uint64_t oldest_age = 0;
    int youngest = -1;
    uint64_t youngest_age = ~0;
    bool too_free = false;
    *src = -1;
    *dst = -1;

    global_pool_check(a);
    struct window_global wg_sum;
    memset(&wg_sum, 0, sizeof(struct window_global));
    window_global_sum(a->window_global, &wg_sum, a->window_size);
    // fill after structs
    fill_item_stats_automove(a->iam_after);
    fill_slab_stats_automove(a->sam_after);
    a->window_cur++;

    memcheck(a);

    // iterate slabs
    for (n = POWER_SMALLEST; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        bool small_slab = a->sam_before[n].chunk_size < a->item_size
            ? true : false;
        bool free_enough = false;
        struct window_data *wd = get_window_data(a, n);
        // summarize the window-up-to-now.
        memset(&w_sum, 0, sizeof(struct window_data));
        int w_offset = n * a->window_size;
        window_sum(&a->window_data[w_offset], &w_sum, a->window_size);
        memset(wd, 0, sizeof(struct window_data));

        // if page delta, oom, or evicted delta, mark window dirty
        // classes marked dirty cannot donate memory back to global pool.
        if (a->iam_after[n].evicted - a->iam_before[n].evicted > 0 ||
            a->iam_after[n].outofmemory - a->iam_before[n].outofmemory > 0) {
            wd->evicted = 1;
            wd->dirty = 1;
        }
        if (a->sam_after[n].total_pages - a->sam_before[n].total_pages > 0) {
            wd->dirty = 1;
        }
        // Mark excess free if we're over the free mem limit for too long.
        // "free_enough" means it is either wobbling, recently received a new
        // page of memory, or the crawler is freeing memory.
        if (a->sam_after[n].free_chunks > a->free_mem[n]) {
            free_enough = true;
        }
        // double the free requirements means we may have memory we can
        // reclaim to global, if it stays this way for the whole window.
        if (a->sam_after[n].free_chunks > (a->free_mem[n] * 2) && a->free_mem[n] > 0) {
            wd->excess_free = 1;
        }

        // set age into window
        wd->age = a->iam_after[n].age;

        // grab age as average of window total
        uint64_t age = w_sum.age / a->window_size;

        // if > N free chunks and not dirty, reclaim memory
        // small slab classes aren't age balanced and rely more on global
        // pool. reclaim them more aggressively.
        if (a->sam_after[n].free_chunks > a->sam_after[n].chunks_per_page * MIN_PAGES_FOR_RECLAIM
                && w_sum.dirty == 0) {
            if (small_slab) {
                *src = n;
                *dst = 0;
                too_free = true;
            } else if (!small_slab && w_sum.excess_free >= a->window_size) {
                // If large slab and free chunks haven't decreased for a full
                // window, reclaim pages.
                *src = n;
                *dst = 0;
                too_free = true;
            }
        }

        if (!small_slab) {
            // if oldest and have enough pages, is oldest
            if (age > oldest_age
                    && a->sam_after[n].total_pages > MIN_PAGES_FOR_SOURCE) {
                oldest = n;
                oldest_age = age;
            }

            // don't count as youngest if it hasn't been using new chunks.
            // (if it was relaxed recently, and is currently "free enough")
            if (age < youngest_age && a->sam_after[n].total_pages != 0
                    && w_sum.excess_free < a->window_size
                    && !(w_sum.relaxed && free_enough)) {
                youngest = n;
                youngest_age = age;
            }
        }
    }

    memcpy(a->iam_before, a->iam_after,
            sizeof(item_stats_automove) * MAX_NUMBER_OF_SLAB_CLASSES);
    memcpy(a->sam_before, a->sam_after,
            sizeof(slab_stats_automove) * MAX_NUMBER_OF_SLAB_CLASSES);
    // only make decisions if window has filled once.
    if (a->window_cur < a->window_size)
        return;

    if (wg_sum.pool_high >= a->window_size && !wg_sum.pool_low && youngest != -1) {
        if (a->sam_after[youngest].free_chunks <= a->free_mem[youngest]) {
            *src = 0;
            *dst = youngest;
        }
        struct window_data *wd = get_window_data(a, youngest);
        // "relaxing" here and below allows us to skip classes which will
        // never grow or are growing slowly, more quickly finding other
        // classes which violate the age ratio.
        wd->relaxed = 1;
    } else if (!too_free && wg_sum.pool_low && oldest != -1) {
        *src = oldest;
        *dst = 0;
    } else if (!too_free && youngest != -1 && oldest != -1 && youngest != oldest) {
        // if we have a youngest and oldest, and oldest is outside the ratio.
        if (youngest_age < ((double)oldest_age * a->max_age_ratio)) {
            struct window_data *wd = get_window_data(a, youngest);
            wd->relaxed = 1;
            // only actually assign more memory if it's absorbed what it has
            if (a->sam_after[youngest].free_chunks <= a->free_mem[youngest]) {
                *src = 0;
                *dst = youngest;

            }
        }
    }
    return;
}
