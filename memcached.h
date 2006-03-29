/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* $Id$ */

#define DATA_BUFFER_SIZE 2048

#if defined(TCP_CORK) && !defined(TCP_NOPUSH)
#define TCP_NOPUSH TCP_CORK
#endif

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
    time_t        started;          /* when the process was started */
    unsigned long long bytes_read;
    unsigned long long bytes_written;
};

struct settings {
    unsigned int maxbytes;
    int maxconns;
    int port;
    struct in_addr interface;
    int verbose;
    int managed;          /* if 1, a tracker manages virtual buckets */
    time_t oldest_live;   /* ignore existing items older than this */
    int evict_to_free;
};

extern struct stats stats;
extern struct settings settings;

#define ITEM_LINKED 1
#define ITEM_DELETED 2

/* temp */
#define ITEM_SLABBED 4

typedef struct _stritem {
    struct _stritem *next;
    struct _stritem *prev;
    struct _stritem *h_next;  /* hash chain next */
    unsigned short  refcount; 
    unsigned short  flags;
    int    nbytes;  /* size of data */
    time_t time;    /* least recent access */
    time_t exptime; /* expire time */
    unsigned char it_flags;     /* ITEM_* above */
    unsigned char slabs_clsid;
    unsigned char nkey;         /* key length, with terminating null and padding */
    unsigned char dummy1;
    void * end[0];
} item;

#define ITEM_key(item) ((char*)&((item)->end[0]))

/* warning: don't use these macros with a function, as it evals its arg twice */
#define ITEM_data(item) ((char*) &((item)->end[0]) + (item)->nkey)
#define ITEM_ntotal(item) (sizeof(struct _stritem) + (item)->nkey + (item)->nbytes)

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
    short  which;   /* which events were just triggered */

    char   *rbuf;   /* buffer to read commands into */
    char   *rcurr;  /* but if we parsed some already, this is where we stopped */
    int    rsize;   /* total allocated size of rbuf */
    int    rbytes;  /* how much data, starting from rcur, do we have unparsed */

    char   *wbuf;
    char   *wcurr;
    int    wsize;
    int    wbytes; 
    int    write_and_go; /* which state to go into after finishing current write */
    void   *write_and_free; /* free this memory after finishing writing */
    char    is_corked;         /* boolean, connection is corked */

    char   *ritem;  /* when we read in an item's value, it goes here */
    int    rlbytes;
    
    /* data for the nread state */

    /* 
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual 
     * data. The data is read into ITEM_data(item) to avoid extra copying.
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
    char   ibuf[300]; /* for VALUE lines */
    char   *iptr;
    int    ibytes;
    int    binary;    /* are we in binary mode */
    int    bucket;    /* bucket number for the next command, if running as
                         a managed instance. -1 (_not_ 0) means invalid. */
    int    gen;       /* generation requested for the bucket */
                         
} conn;

/* number of virtual buckets for a managed instance */
#define MAX_BUCKETS 32768

/* listening socket */
extern int l_socket;

/* temporary hack */
/* #define assert(x) if(!(x)) { printf("assert failure: %s\n", #x); pre_gdb(); }
   void pre_gdb (); */

/*
 * Functions
 */

/* 
 * given time value that's either unix time or delta from current unix time, return
 * unix time. Use the fact that delta can't exceed one month (and real time value can't 
 * be that low).
 */

time_t realtime(time_t exptime);

/* slabs memory allocation */

/* Init the subsystem. The argument is the limit on no. of bytes to allocate, 0 if no limit */
void slabs_init(unsigned int limit);

/* Preallocate as many slab pages as possible (called from slabs_init)
   on start-up, so users don't get confused out-of-memory errors when
   they do have free (in-slab) space, but no space to make new slabs.
   if maxslabs is 18 (POWER_LARGEST - POWER_SMALLEST + 1), then all
   slab types can be made.  if max memory is less than 18 MB, only the
   smaller ones will be made.  */
void slabs_preallocate (unsigned int maxslabs);

/* Given object size, return id to use when allocating/freeing memory for object */
/* 0 means error: can't store such a large object */
unsigned int slabs_clsid(unsigned int size);

/* Allocate object of given length. 0 on error */
void *slabs_alloc(unsigned int size);

/* Free previously allocated object */
void slabs_free(void *ptr, unsigned int size);
    
/* Fill buffer with stats */
char* slabs_stats(int *buflen);

/* Request some slab be moved between classes
  1 = success
   0 = fail
   -1 = tried. busy. send again shortly. */
int slabs_reassign(unsigned char srcid, unsigned char dstid);
    
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
item *assoc_find(char *key);
int assoc_insert(char *key, item *item);
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
char *item_stats_sizes(int *bytes);
void item_stats(char *buffer, int buflen);
