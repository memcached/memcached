#include "memcached.h"

/*
 * This file contains global variables shared across the rest of the
 * memcached codebase.  These were originally in memcached.c but had
 * to be removed to make the rest of the object files linkable into
 * the test infrastructure.
 *
 */

/*
 * We keep the current time of day in a global variable that's updated by a
 * timer event. This saves us a bunch of time() system calls (we really only
 * need to get the time once a second, whereas there can be tens of thousands
 * of requests a second) and allows us to use server-start-relative timestamps
 * rather than absolute UNIX timestamps, a space savings on systems where
 * sizeof(time_t) > sizeof(unsigned int).
 */
volatile rel_time_t current_time;

/** exported globals **/
struct stats stats;
struct settings settings;
struct slab_rebalance slab_rebal;
volatile int slab_rebalance_signal;
