#define HOT_LRU 0
#define WARM_LRU 64
#define COLD_LRU 128
#define TEMP_LRU 192

#define CLEAR_LRU(id) (id & ~(3<<6))
#define GET_LRU(id) (id & (3<<6))

/* See items.c */
uint64_t get_cas_id(void);
void set_cas_id(uint64_t new_cas);

/*@null@*/
item *do_item_alloc(char *key, const size_t nkey, const unsigned int flags, const rel_time_t exptime, const int nbytes);
item_chunk *do_item_alloc_chunk(item_chunk *ch, const size_t bytes_remain);
item *do_item_alloc_pull(const size_t ntotal, const unsigned int id);
void item_free(item *it);
bool item_size_ok(const size_t nkey, const int flags, const int nbytes);

int  do_item_link(item *it, const uint32_t hv);     /** may fail if transgresses limits */
void do_item_unlink(item *it, const uint32_t hv);
void do_item_unlink_nolock(item *it, const uint32_t hv);
void do_item_remove(item *it);
void do_item_update(item *it);   /** update LRU time to current and reposition */
void do_item_update_nolock(item *it);
int  do_item_replace(item *it, item *new_it, const uint32_t hv);
void do_item_link_fixup(item *it);

int item_is_flushed(item *it);
unsigned int do_get_lru_size(uint32_t id);

void do_item_linktail_q(item *it);
void do_item_unlinktail_q(item *it);
item *do_item_crawl_q(item *it);

void *item_lru_bump_buf_create(void);

#define LRU_PULL_EVICT 1
#define LRU_PULL_CRAWL_BLOCKS 2
#define LRU_PULL_RETURN_ITEM 4 /* fill info struct if available */

struct lru_pull_tail_return {
    item *it;
    uint32_t hv;
};

int lru_pull_tail(const int orig_id, const int cur_lru,
        const uint64_t total_bytes, const uint8_t flags, const rel_time_t max_age,
        struct lru_pull_tail_return *ret_it);

/*@null@*/
char *item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes);
void item_stats(ADD_STAT add_stats, void *c);
void do_item_stats_add_crawl(const int i, const uint64_t reclaimed,
        const uint64_t unfetched, const uint64_t checked);
void item_stats_totals(ADD_STAT add_stats, void *c);
/*@null@*/
void item_stats_sizes(ADD_STAT add_stats, void *c);
void item_stats_sizes_init(void);
void item_stats_sizes_enable(ADD_STAT add_stats, void *c);
void item_stats_sizes_disable(ADD_STAT add_stats, void *c);
void item_stats_sizes_add(item *it);
void item_stats_sizes_remove(item *it);
bool item_stats_sizes_status(void);

/* stats getter for slab automover */
typedef struct {
    int64_t evicted;
    int64_t outofmemory;
    uint32_t age;
} item_stats_automove;
void fill_item_stats_automove(item_stats_automove *am);

item *do_item_get(const char *key, const size_t nkey, const uint32_t hv, conn *c, const bool do_update);
item *do_item_touch(const char *key, const size_t nkey, uint32_t exptime, const uint32_t hv, conn *c);
void do_item_bump(conn *c, item *it, const uint32_t hv);
void item_stats_reset(void);
extern pthread_mutex_t lru_locks[POWER_LARGEST];

int start_lru_maintainer_thread(void *arg);
int stop_lru_maintainer_thread(void);
int init_lru_maintainer(void);
void lru_maintainer_pause(void);
void lru_maintainer_resume(void);

void *lru_bump_buf_create(void);
