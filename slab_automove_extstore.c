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

struct window_data {
    uint64_t age;
    uint64_t dirty;
    uint64_t evicted;
    unsigned int excess_free;
    unsigned int relaxed;
};

typedef struct {
    struct window_data *window_data;
    struct settings *settings;
    uint32_t window_size;
    uint32_t window_cur;
    uint32_t item_size;
    double max_age_ratio;
    double free_ratio;
    bool pool_filled_once;
    unsigned int global_pool_watermark;
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
    a->window_size = window_size;
    a->max_age_ratio = max_age_ratio;
    a->free_ratio = settings->slab_automove_freeratio;
    a->item_size = settings->ext_item_size;
    a->settings = settings;
    a->pool_filled_once = false;
    if (a->window_data == NULL) {
        if (a->window_data)
            free(a->window_data);
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

static int global_pool_check(slab_automove *a) {
    bool mem_limit_reached;
    unsigned int free = a->global_pool_watermark;
    unsigned int count = global_page_pool_size(&mem_limit_reached);
    if (!mem_limit_reached)
        return 0;
    if (count < free) {
        a->pool_filled_once = true;
        return 1;
    } else {
        a->pool_filled_once = true;
    }
    return 0;
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

    // FIXME: is there a cached counter for total pages alloced?
    // technically we only really need to do this once as the pages are
    // prefilled and ratio isn't a runtime change.
    for (int n = 1; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        slab_stats_automove *sam = &a->sam_after[n];
        total_pages += sam->total_pages;
    }
    // always update what remains in the global page pool
    total_pages += a->sam_after[0].total_pages;
    a->global_pool_watermark = total_pages * a->free_ratio;
    if (a->global_pool_watermark < 2)
        a->global_pool_watermark = 2;
    settings.ext_global_pool_min = a->global_pool_watermark;
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
    bool too_free = false;
    *src = -1;
    *dst = -1;

    int global_low = global_pool_check(a);
    // fill after structs
    fill_item_stats_automove(a->iam_after);
    fill_slab_stats_automove(a->sam_after);
    a->window_cur++;

    memcheck(a);

    // iterate slabs
    for (n = POWER_SMALLEST; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        bool small_slab = a->sam_before[n].chunk_size < a->item_size
            ? true : false;
        struct window_data *wd = get_window_data(a, n);
        int w_offset = n * a->window_size;
        memset(wd, 0, sizeof(struct window_data));
        unsigned int free_target = a->sam_after[n].chunks_per_page * MIN_PAGES_FREE;

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
        // double the free requirements means we may have memory we can
        // reclaim to global, if it stays this way for the whole window.
        if (a->sam_after[n].free_chunks > (free_target * 2)) {
            wd->excess_free = 1;
        }

        // set age into window
        wd->age = a->iam_after[n].age;

        // summarize the window-up-to-now.
        memset(&w_sum, 0, sizeof(struct window_data));
        window_sum(&a->window_data[w_offset], &w_sum, a->window_size);

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

        }
    }

    memcpy(a->iam_before, a->iam_after,
            sizeof(item_stats_automove) * MAX_NUMBER_OF_SLAB_CLASSES);
    memcpy(a->sam_before, a->sam_after,
            sizeof(slab_stats_automove) * MAX_NUMBER_OF_SLAB_CLASSES);
    // only make decisions if window has filled once.
    if (a->window_cur < a->window_size)
        return;

    if (!too_free && global_low && oldest != -1) {
        *src = oldest;
        *dst = 0;
    }
    return;
}
