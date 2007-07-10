/* See items.c */
void item_init(void);
/*@null@*/
item *do_item_alloc(char *key, const size_t nkey, const int flags, const rel_time_t exptime, const int nbytes);
void item_free(item *it);
bool item_size_ok(const size_t nkey, const int flags, const int nbytes);

int  do_item_link(item *it);     /** may fail if transgresses limits */
void do_item_unlink(item *it);
void do_item_remove(item *it);
void do_item_update(item *it);   /** update LRU time to current and reposition */
int  do_item_replace(item *it, item *new_it);

/*@null@*/
char *do_item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes);
char *do_item_stats(int *bytes);

/*@null@*/
char *do_item_stats_sizes(int *bytes);
void do_item_flush_expired(void);
item *item_get(const char *key, const size_t nkey);

item *do_item_get_notedeleted(const char *key, const size_t nkey, bool *delete_locked);
item *do_item_get_nocheck(const char *key, const size_t nkey);
