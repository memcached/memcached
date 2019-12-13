#ifndef STATS_H
#define STATS_H

/* stats */
void stats_prefix_init(char prefix_delimiter);
void stats_prefix_clear(void);
void stats_prefix_record_get(const char *key, const size_t nkey, const bool is_hit);
void stats_prefix_record_delete(const char *key, const size_t nkey);
void stats_prefix_record_set(const char *key, const size_t nkey);
/*@null@*/
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
PREFIX_STATS *stats_prefix_find(const char *key, const size_t nkey);

#endif
