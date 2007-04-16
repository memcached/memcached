/* stats */
void stats_prefix_init(void);
void stats_prefix_clear(void);
void stats_prefix_record_get(const char *key, const bool is_hit);
void stats_prefix_record_delete(const char *key);
void stats_prefix_record_set(const char *key);
/*@null@*/
char *stats_prefix_dump(int *length);
