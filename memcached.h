#define DATA_BUFFER_SIZE 2048

struct stats {
    unsigned int  curr_items;
    unsigned int  total_items;
    unsigned long long  curr_bytes;
    unsigned int  curr_conns;
    unsigned int  total_conns;
    unsigned int  conn_structs;
    unsigned int  get_cmds;
    unsigned int  set_cmds;
    unsigned int  get_hits;
    unsigned int  get_misses;
    unsigned long long bytes_read;
    unsigned long long bytes_written;
};

struct settings {
    unsigned long long maxbytes;
    int maxitems;
    int maxconns;
    int port;
    struct in_addr interface;
    int verbose;
};

extern struct stats stats;
extern struct settings settings;

#define ITEM_LINKED 1
#define ITEM_DELETED 2

typedef struct _stritem {
    struct _stritem *next;
    struct _stritem *prev;
    int    refcount; 
    int    it_flags;
    char   *key;
    void   *data;
    unsigned int slabs_clsid;
    int    nbytes;  /* size of data */
    int    ntotal;  /* size of this struct + key + data */
    int    flags;
    time_t time;    /* least recent access */
    time_t exptime; /* expire time */
    void * end[0];
} item;

enum conn_states {
    conn_listening,  /* the socket which listens for connections */
    conn_read,       /* reading in a command line */
    conn_write,      /* writing out a simple response */
    conn_nread,      /* reading in a fixed number of bytes */
    conn_swallow,    /* swallowing unnecessary bytes w/o storing */
    conn_closing,    /* closing this connection */
    conn_mwrite      /* writing out many items sequentially */
};

#define NREAD_ADD 1
#define NREAD_SET 2
#define NREAD_REPLACE 3

typedef struct {
    int    sfd;
    int    state;
    struct event event;
    short  ev_flags;
    short  which;  /* which events were just triggered */

    char   *rbuf;  
    int    rsize;  
    int    rbytes;

    char   *wbuf;
    char   *wcurr;
    int    wsize;
    int    wbytes; 
    int    write_and_go; /* which state to go into after finishing current write */
    void   *write_and_free; /* free this memory after finishing writing */

    char   *rcurr;
    int    rlbytes;
    
    /* data for the nread state */

    /* 
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual 
     * data. The data is read into item->data to avoid extra copying.
     */

    void   *item;     /* for commands set/add/replace  */
    int    item_comm; /* which one is it: set/add/replace */

    /* data for the swallow state */
    int    sbytes;    /* how many bytes to swallow */

    /* data for the mwrite state */
    item   **ilist;   /* list of items to write out */
    int    isize;
    item   **icurr;
    int    ileft;
    int    ipart;     /* 1 if we're writing a VALUE line, 2 if we're writing data */
    char   ibuf[256]; /* for VALUE lines */
    char   *iptr;
    int    ibytes;
                         
} conn;


/*
 * Functions
 */

/* slabs memory allocation */

/* Init the subsystem. The argument is the limit on no. of bytes to allocate, 0 if no limit */
void slabs_init(unsigned int limit);

/* Given object size, return id to use when allocating/freeing memory for object */
/* 0 means error: can't store such a large object */
unsigned int slabs_clsid(unsigned int size);

/* Allocate object of given size class identified by id. 0 on error */
void *slabs_alloc(unsigned int id);

/* Free previously allocated object */
void slabs_free(void *ptr, unsigned int id);
    
/* Fill buffer with stats */
void slabs_stats(char *buffer, int buflen);
        
    
/* event handling, network IO */
void event_handler(int fd, short which, void *arg);
conn *conn_new(int sfd, int init_state, int event_flags);
void conn_close(conn *c);
void conn_init(void);
void drive_machine(conn *c);
int new_socket(void);
int server_socket(int port);
int update_event(conn *c, int new_flags);
int try_read_command(conn *c);
int try_read_network(conn *c);
void complete_nread(conn *c);
void process_command(conn *c, char *command);

/* stats */
void stats_reset(void);
void stats_init(void);

/* defaults */
void settings_init(void);

/* associative array */
void assoc_init(void);
void *assoc_find(char *key);
int assoc_insert(char *key, void *value);
void assoc_delete(char *key);


void item_init(void);
item *item_alloc(char *key, int flags, time_t exptime, int nbytes);
void item_free(item *it);

int item_link(item *it);    /* may fail if transgresses limits */
void item_unlink(item *it);
void item_remove(item *it);

void item_update(item *it);   /* update LRU time to current and reposition */
int item_replace(item *it, item *new_it);
char *item_cachedump(unsigned int slabs_clsid, unsigned int limit, unsigned int *bytes);
void item_stats(char *buffer, int buflen);
