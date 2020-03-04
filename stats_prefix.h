#ifndef STATS_PREFIX_H
#define STATS_PREFIX_H

/* The stats prefix subsystem stores detailed statistics for each key prefix.
 * Simple statistics like total number of GETS are stored by the Stats
 * subsystem defined elsewhere.
 *
 * Suppose the prefix delimiter is ":", then "user:123" and "user:456" both
 * have the same prefix "user".
 */


/* Initialize the stats prefix subsystem. Should be called once before other
 * functions are called. The global hash initialization should be done before
 * using this subsystem.
 */
void stats_prefix_init(char prefix_delimiter);

/* Clear previously collected stats. Requires you to have the acquired
 * the STATS_LOCK() first.
 */
void stats_prefix_clear(void);

/* Record a GET for a key */
void stats_prefix_record_get(const char *key, const size_t nkey, const bool is_hit);

/* Record a DELETE for a key */
void stats_prefix_record_delete(const char *key, const size_t nkey);

/* Record a SET for a key */
void stats_prefix_record_set(const char *key, const size_t nkey);

/* Return the collected stats in a textual for suitable for writing to a client.
 * The size of the output text is stored in the length parameter.
 * Returns NULL on error
 */
char *stats_prefix_dump(int *length);

/* Visible for testing */
#define PREFIX_HASH_SIZE 256
typedef struct _prefix_stats PREFIX_STATS;
struct _prefix_stats {
    char *prefix;
    size_t prefix_len;
    uint64_t num_gets;
    uint64_t num_sets;
    uint64_t num_deletes;
    uint64_t num_hits;
    PREFIX_STATS *next;
};

/* Return the PREFIX_STATS structure for the specified key, creating it if
 * it does not already exist. Returns NULL if the key does not contain
 * prefix delimiter, or if there was an error. Requires you to have acquired
 * STATS_LOCK() first.
 */
PREFIX_STATS *stats_prefix_find(const char *key, const size_t nkey);

#endif
