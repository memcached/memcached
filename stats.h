/* stats */
void stats_prefix_init(void);
void stats_prefix_clear(void);
void stats_prefix_record_get(char *key, int is_hit);
void stats_prefix_record_delete(char *key);
void stats_prefix_record_set(char *key);
char *stats_prefix_dump(int *length);
