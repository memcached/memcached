/* See items.c */
void item_init(void);
/*@null@*/
item *item_alloc(char *key, const size_t nkey, const int flags, const rel_time_t exptime, const int nbytes);
void item_free(item *it);
bool item_size_ok(char *key, const size_t nkey, const int flags, const int nbytes);

int item_link(item *it);    /* may fail if transgresses limits */
void item_unlink(item *it);
void item_remove(item *it);
void item_update(item *it);   /* update LRU time to current and reposition */
int item_replace(item *it, item *new_it);

/*@null@*/
char *item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes);
void item_stats(char *buffer, const int buflen);

/*@null@*/
char *item_stats_sizes(int *bytes);
void item_flush_expired(void);
