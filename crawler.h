#ifndef CRAWLER_H
#define CRAWLER_H

#define LRU_CRAWLER_CAP_REMAINING -1

typedef struct {
    uint64_t histo[61];
    uint64_t ttl_hourplus;
    uint64_t noexp;
    uint64_t reclaimed;
    uint64_t seen;
    rel_time_t start_time;
    rel_time_t end_time;
    bool run_complete;
} crawlerstats_t;

struct crawler_expired_data {
    pthread_mutex_t lock;
    crawlerstats_t crawlerstats[POWER_LARGEST];
    /* redundant with crawlerstats_t so we can get overall start/stop/done */
    rel_time_t start_time;
    rel_time_t end_time;
    bool crawl_complete;
    bool is_external; /* whether this was an alloc local or remote to the module. */
};

enum crawler_result_type {
    CRAWLER_OK=0, CRAWLER_RUNNING, CRAWLER_BADCLASS, CRAWLER_NOTSTARTED, CRAWLER_ERROR
};
int start_item_crawler_thread(void);
int stop_item_crawler_thread(void);
int init_lru_crawler(void *arg);
enum crawler_result_type lru_crawler_crawl(char *slabs, enum crawler_run_type,
        void *c, const int sfd, unsigned int remaining);
int lru_crawler_start(uint8_t *ids, uint32_t remaining,
                             const enum crawler_run_type type, void *data,
                             void *c, const int sfd);
void lru_crawler_pause(void);
void lru_crawler_resume(void);

#endif
