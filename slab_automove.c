/*  Copyright 2017 Facebook.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 */

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include "slab_automove.h"
#include <stdlib.h>
#include <string.h>

#define MIN_PAGES_FOR_SOURCE 2
#define MIN_PAGES_FOR_RECLAIM 2.5

struct window_data {
    uint64_t age;
    uint64_t dirty;
    float evicted_ratio;
    uint64_t evicted_seen; // if evictions were seen at all this window
};

typedef struct {
    struct window_data *window_data;
    uint32_t window_size;
    uint32_t window_cur;
    double max_age_ratio;
    item_stats_automove iam_before[MAX_NUMBER_OF_SLAB_CLASSES];
    item_stats_automove iam_after[MAX_NUMBER_OF_SLAB_CLASSES];
    slab_stats_automove sam_before[MAX_NUMBER_OF_SLAB_CLASSES];
    slab_stats_automove sam_after[MAX_NUMBER_OF_SLAB_CLASSES];
} slab_automove;

void *slab_automove_init(struct settings *settings) {
    uint32_t window_size = settings->slab_automove_window;
    double max_age_ratio = settings->slab_automove_ratio;
    slab_automove *a = calloc(1, sizeof(slab_automove));
    if (a == NULL)
        return NULL;
    a->window_data = calloc(window_size * MAX_NUMBER_OF_SLAB_CLASSES, sizeof(struct window_data));
    a->window_size = window_size;
    a->max_age_ratio = max_age_ratio;
    if (a->window_data == NULL) {
        free(a);
        return NULL;
    }

    // do a dry run to fill the before structs
    fill_item_stats_automove(a->iam_before);
    fill_slab_stats_automove(a->sam_before);

    return (void *)a;
}

void slab_automove_free(void *arg) {
    slab_automove *a = (slab_automove *)arg;
    free(a->window_data);
    free(a);
}

static void window_sum(struct window_data *wd, struct window_data *w, uint32_t size) {
    int x;
    for (x = 0; x < size; x++) {
        struct window_data *d = &wd[x];
        w->age += d->age;
        w->dirty += d->dirty;
        w->evicted_ratio += d->evicted_ratio;
        w->evicted_seen += d->evicted_seen;
    }
}

// TODO: if oldest is dirty, find next oldest.
// still need to base ratio off of absolute age
void slab_automove_run(void *arg, int *src, int *dst) {
    slab_automove *a = (slab_automove *)arg;
    int n;
    struct window_data w_sum;
    int oldest = -1;
    uint64_t oldest_age = 0;
    int youngest = -1;
    uint64_t youngest_age = ~0;
    bool youngest_evicting = false;
    *src = -1;
    *dst = -1;

    // fill after structs
    fill_item_stats_automove(a->iam_after);
    fill_slab_stats_automove(a->sam_after);
    // Loop once to get total_evicted for this window.
    uint64_t evicted_total = 0;
    for (n = POWER_SMALLEST; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        evicted_total += a->iam_after[n].evicted - a->iam_before[n].evicted;
    }
    a->window_cur++;

    // iterate slabs
    for (n = POWER_SMALLEST; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        int w_offset = n * a->window_size;
        struct window_data *wd = &a->window_data[w_offset + (a->window_cur % a->window_size)];
        memset(wd, 0, sizeof(struct window_data));

        // if page delta, or evicted delta, mark window dirty
        // (or outofmemory)
        uint64_t evicted_delta = a->iam_after[n].evicted - a->iam_before[n].evicted;
        if (evicted_delta > 0) {
            // FIXME: the python script is using floats. we have ints.
            wd->evicted_ratio = (float) evicted_delta / evicted_total;
            wd->evicted_seen = 1;
            wd->dirty = 1;
        }

        if (a->iam_after[n].outofmemory - a->iam_before[n].outofmemory > 0) {
            wd->dirty = 1;
        }
        if (a->sam_after[n].total_pages - a->sam_before[n].total_pages > 0) {
            wd->dirty = 1;
        }

        // set age into window
        wd->age = a->iam_after[n].age;

        // summarize the window-up-to-now.
        memset(&w_sum, 0, sizeof(struct window_data));
        window_sum(&a->window_data[w_offset], &w_sum, a->window_size);

        // grab age as average of window total
        uint64_t age = w_sum.age / a->window_size;

        // if > N free chunks and not dirty, make decision.
        if (a->sam_after[n].free_chunks > a->sam_after[n].chunks_per_page * MIN_PAGES_FOR_RECLAIM) {
            if (w_sum.dirty == 0) {
                *src = n;
                *dst = 0;
                youngest = oldest = -1;
                break;
            }
        }

        // if oldest and have enough pages, is oldest
        if (age > oldest_age && a->sam_after[n].total_pages > MIN_PAGES_FOR_SOURCE) {
            oldest = n;
            oldest_age = age;
        }

        // grab evicted count from window
        // if > half the window and youngest, mark as youngest
        // or, if more than 25% of total evictions in the window.
        if (age < youngest_age && (w_sum.evicted_seen > a->window_size / 2
                    || w_sum.evicted_ratio / a->window_size > 0.25)) {
            youngest = n;
            youngest_age = age;
            youngest_evicting = wd->evicted_seen ? true : false;
        }
    }

    memcpy(a->iam_before, a->iam_after,
            sizeof(item_stats_automove) * MAX_NUMBER_OF_SLAB_CLASSES);
    memcpy(a->sam_before, a->sam_after,
            sizeof(slab_stats_automove) * MAX_NUMBER_OF_SLAB_CLASSES);
    // if we have a youngest and oldest, and oldest is outside the ratio,
    // also, only make decisions if window has filled once.
    if (youngest != -1 && oldest != -1 && a->window_cur > a->window_size) {
        if (youngest_age < ((double)oldest_age * a->max_age_ratio) && youngest_evicting) {
            *src = oldest;
            *dst = youngest;
        }
    }
    return;
}
