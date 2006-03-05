/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *  memcached - memory caching daemon
 *
 *       http://www.danga.com/memcached/
 *
 *  Copyright 2003 Danga Interactive, Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Anatoly Vorobey <mellon@pobox.com>
 *      Brad Fitzpatrick <brad@danga.com>
 *
 *  $Id$
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
/* some POSIX systems need the following definition
 * to get mlockall flags out of sys/mman.h.  */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif
#include <pwd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <event.h>
#include <assert.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#include "memcached.h"

struct stats stats;
struct settings settings;

static item **todelete = 0;
static int delcurr;
static int deltotal;

int *buckets = 0; /* bucket->generation array for a managed instance */

time_t realtime(time_t exptime) {
    time_t now;

    /* no. of seconds in 30 days - largest possible delta exptime */
    #define REALTIME_MAXDELTA 60*60*24*30

    if (exptime == 0) return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA)
        return exptime;
    else {
        now = time(0);
        return exptime + now;
    }
}

void stats_init(void) {
    stats.curr_items = stats.total_items = stats.curr_conns = stats.total_conns = stats.conn_structs = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = 0;
    stats.curr_bytes = stats.bytes_read = stats.bytes_written = 0;
    stats.started = time(0);
}

void stats_reset(void) {
    stats.total_items = stats.total_conns = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = 0;
    stats.bytes_read = stats.bytes_written = 0;
}

void settings_init(void) {
    settings.port = 11211;
    settings.interface.s_addr = htonl(INADDR_ANY);
    settings.maxbytes = 64*1024*1024; /* default is 64MB */
    settings.maxconns = 1024;         /* to limit connections-related memory to about 5MB */
    settings.verbose = 0;
    settings.oldest_live = 0;
    settings.evict_to_free = 1;       /* push old items out of cache when memory runs out */
    settings.managed = 0;
}

conn **freeconns;
int freetotal;
int freecurr;

void set_cork (conn *c, int val) {
    if (c->is_corked == val) return;
    c->is_corked = val;
#ifdef TCP_NOPUSH
    setsockopt(c->sfd, IPPROTO_TCP, TCP_NOPUSH, &val, sizeof(val));
#endif
}

void conn_init(void) {
    freetotal = 200;
    freecurr = 0;
    freeconns = (conn **)malloc(sizeof (conn *)*freetotal);
    return;
}

conn *conn_new(int sfd, int init_state, int event_flags) {
    conn *c;

    /* do we have a free conn structure from a previous close? */
    if (freecurr > 0) {
        c = freeconns[--freecurr];
    } else { /* allocate a new one */
        if (!(c = (conn *)malloc(sizeof(conn)))) {
            perror("malloc()");
            return 0;
        }
        c->rbuf = c->wbuf = 0;
        c->ilist = 0;

        c->rbuf = (char *) malloc(DATA_BUFFER_SIZE);
        c->wbuf = (char *) malloc(DATA_BUFFER_SIZE);
        c->ilist = (item **) malloc(sizeof(item *)*200);

        if (c->rbuf == 0 || c->wbuf == 0 || c->ilist == 0) {
            if (c->rbuf != 0) free(c->rbuf);
            if (c->wbuf != 0) free(c->wbuf);
            if (c->ilist !=0) free(c->ilist);
            free(c);
            perror("malloc()");
            return 0;
        }
        c->rsize = c->wsize = DATA_BUFFER_SIZE;
        c->rcurr = c->rbuf;
        c->isize = 200;
        stats.conn_structs++;
    }

    if (settings.verbose > 1) {
        if (init_state == conn_listening)
            fprintf(stderr, "<%d server listening\n", sfd);
        else
            fprintf(stderr, "<%d new client connection\n", sfd);
    }

    c->sfd = sfd;
    c->state = init_state;
    c->rlbytes = 0;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->ritem = 0;
    c->icurr = c->ilist; 
    c->ileft = 0;
    c->iptr = c->ibuf;
    c->ibytes = 0;

    c->write_and_go = conn_read;
    c->write_and_free = 0;
    c->item = 0;
    c->bucket = -1;
    c->gen = 0;

    c->is_corked = 0;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1) {
        if (freecurr < freetotal) {
            freeconns[freecurr++] = c;
        } else {
            free (c->rbuf);
            free (c->wbuf);
            free (c->ilist);
            free (c);
        }
        return 0;
    }

    stats.curr_conns++;
    stats.total_conns++;

    return c;
}

void conn_close(conn *c) {
    /* delete the event, the socket and the conn */
    event_del(&c->event);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    close(c->sfd);

    if (c->item) {
        item_free(c->item);
    }

    if (c->ileft) {
        for (; c->ileft > 0; c->ileft--,c->icurr++) {
            item_remove(*(c->icurr));
        }
    }

    if (c->write_and_free) {
        free(c->write_and_free);
    }

    /* if we have enough space in the free connections array, put the structure there */
    if (freecurr < freetotal) {
        freeconns[freecurr++] = c;
    } else {
        /* try to enlarge free connections array */
        conn **new_freeconns = realloc(freeconns, sizeof(conn *)*freetotal*2);
        if (new_freeconns) {
            freetotal *= 2;
            freeconns = new_freeconns;
            freeconns[freecurr++] = c;
        } else {
            free(c->rbuf);
            free(c->wbuf);
            free(c->ilist);
            free(c);
        }
    }

    stats.curr_conns--;

    return;
}

void out_string(conn *c, char *str) {
    int len;

    if (settings.verbose > 1)
        fprintf(stderr, ">%d %s\n", c->sfd, str);

    len = strlen(str);
    if (len + 2 > c->wsize) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    strcpy(c->wbuf, str);
    strcat(c->wbuf, "\r\n");
    c->wbytes = len + 2;
    c->wcurr = c->wbuf;

    c->state = conn_write;
    c->write_and_go = conn_read;
    return;
}

/* 
 * we get here after reading the value in set/add/replace commands. The command
 * has been stored in c->item_comm, and the item is ready in c->item.
 */

void complete_nread(conn *c) {
    item *it = c->item;
    int comm = c->item_comm;
    item *old_it;
    time_t now = time(0);

    stats.set_cmds++;

    while(1) {
        if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2) != 0) {
            out_string(c, "CLIENT_ERROR bad data chunk");
            break;
        }

        old_it = assoc_find(ITEM_key(it));

        if (old_it && settings.oldest_live &&
            old_it->time <= settings.oldest_live) {
            item_unlink(old_it);
            old_it = 0;
        }

        if (old_it && old_it->exptime && old_it->exptime < now) {
            item_unlink(old_it);
            old_it = 0;
        }

        if (old_it && comm==NREAD_ADD) {
            item_update(old_it);
            out_string(c, "NOT_STORED");
            break;
        }
        
        if (!old_it && comm == NREAD_REPLACE) {
            out_string(c, "NOT_STORED");
            break;
        }

        if (old_it && (old_it->it_flags & ITEM_DELETED) && (comm == NREAD_REPLACE || comm == NREAD_ADD)) {
            out_string(c, "NOT_STORED");
            break;
        }
        
        if (old_it) {
            item_replace(old_it, it);
        } else item_link(it);
        
        c->item = 0;
        out_string(c, "STORED");
        return;
    }
            
    item_free(it); 
    c->item = 0; 
    return;
}

void process_stat(conn *c, char *command) {
    time_t now = time(0);

    if (strcmp(command, "stats") == 0) {
        char temp[1024];
        pid_t pid = getpid();
        char *pos = temp;
        struct rusage usage;
        
        getrusage(RUSAGE_SELF, &usage);

        pos += sprintf(pos, "STAT pid %u\r\n", pid);
        pos += sprintf(pos, "STAT uptime %lu\r\n", now - stats.started);
        pos += sprintf(pos, "STAT time %ld\r\n", now);
        pos += sprintf(pos, "STAT version " VERSION "\r\n");
        pos += sprintf(pos, "STAT rusage_user %ld.%06ld\r\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        pos += sprintf(pos, "STAT rusage_system %ld.%06ld\r\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
        pos += sprintf(pos, "STAT curr_items %u\r\n", stats.curr_items);
        pos += sprintf(pos, "STAT total_items %u\r\n", stats.total_items);
        pos += sprintf(pos, "STAT bytes %llu\r\n", stats.curr_bytes);
        pos += sprintf(pos, "STAT curr_connections %u\r\n", stats.curr_conns - 1); /* ignore listening conn */
        pos += sprintf(pos, "STAT total_connections %u\r\n", stats.total_conns);
        pos += sprintf(pos, "STAT connection_structures %u\r\n", stats.conn_structs);
        pos += sprintf(pos, "STAT cmd_get %u\r\n", stats.get_cmds);
        pos += sprintf(pos, "STAT cmd_set %u\r\n", stats.set_cmds);
        pos += sprintf(pos, "STAT get_hits %u\r\n", stats.get_hits);
        pos += sprintf(pos, "STAT get_misses %u\r\n", stats.get_misses);
        pos += sprintf(pos, "STAT bytes_read %llu\r\n", stats.bytes_read);
        pos += sprintf(pos, "STAT bytes_written %llu\r\n", stats.bytes_written);
        pos += sprintf(pos, "STAT limit_maxbytes %u\r\n", settings.maxbytes);
        pos += sprintf(pos, "END");
        out_string(c, temp);
        return;
    }

    if (strcmp(command, "stats reset") == 0) {
        stats_reset();
        out_string(c, "RESET");
        return;
    }

#ifdef HAVE_MALLOC_H
#ifdef HAVE_STRUCT_MALLINFO
    if (strcmp(command, "stats malloc") == 0) {
        char temp[512];
        struct mallinfo info;
        char *pos = temp;

        info = mallinfo();
        pos += sprintf(pos, "STAT arena_size %d\r\n", info.arena);
        pos += sprintf(pos, "STAT free_chunks %d\r\n", info.ordblks);
        pos += sprintf(pos, "STAT fastbin_blocks %d\r\n", info.smblks);
        pos += sprintf(pos, "STAT mmapped_regions %d\r\n", info.hblks);
        pos += sprintf(pos, "STAT mmapped_space %d\r\n", info.hblkhd);
        pos += sprintf(pos, "STAT max_total_alloc %d\r\n", info.usmblks);
        pos += sprintf(pos, "STAT fastbin_space %d\r\n", info.fsmblks);
        pos += sprintf(pos, "STAT total_alloc %d\r\n", info.uordblks);
        pos += sprintf(pos, "STAT total_free %d\r\n", info.fordblks);
        pos += sprintf(pos, "STAT releasable_space %d\r\nEND", info.keepcost);
        out_string(c, temp);
        return;
    }
#endif /* HAVE_STRUCT_MALLINFO */
#endif /* HAVE_MALLOC_H */

    if (strcmp(command, "stats maps") == 0) {
        char *wbuf;
        int wsize = 8192; /* should be enough */
        int fd;
        int res;

        wbuf = (char *)malloc(wsize);
        if (wbuf == 0) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }
            
        fd = open("/proc/self/maps", O_RDONLY);
        if (fd == -1) {
            out_string(c, "SERVER_ERROR cannot open the maps file");
            free(wbuf);
            return;
        }

        res = read(fd, wbuf, wsize - 6);  /* 6 = END\r\n\0 */
        if (res == wsize - 6) {
            out_string(c, "SERVER_ERROR buffer overflow");
            free(wbuf); close(fd);
            return;
        }
        if (res == 0 || res == -1) {
            out_string(c, "SERVER_ERROR can't read the maps file");
            free(wbuf); close(fd);
            return;
        }
        strcpy(wbuf + res, "END\r\n");
        c->write_and_free=wbuf;
        c->wcurr=wbuf;
        c->wbytes = res + 6;
        c->state = conn_write;
        c->write_and_go = conn_read;
        close(fd);
        return;
    }

    if (strncmp(command, "stats cachedump", 15) == 0) {
        char *buf;
        unsigned int bytes, id, limit = 0;
        char *start = command + 15;
        if (sscanf(start, "%u %u\r\n", &id, &limit) < 1) {
            out_string(c, "CLIENT_ERROR bad command line");
            return;
        }

        buf = item_cachedump(id, limit, &bytes);
        if (buf == 0) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }

        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        c->state = conn_write;
        c->write_and_go = conn_read;
        return;
    }

    if (strcmp(command, "stats slabs")==0) {
        int bytes = 0;
        char *buf = slabs_stats(&bytes);
        if (!buf) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }
        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        c->state = conn_write;
        c->write_and_go = conn_read;
        return;
    }

    if (strcmp(command, "stats items")==0) {
        char buffer[4096];
        item_stats(buffer, 4096);
        out_string(c, buffer);
        return;
    }

    if (strcmp(command, "stats sizes")==0) {
        int bytes = 0;
        char *buf = item_stats_sizes(&bytes);
        if (! buf) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }

        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        c->state = conn_write;
        c->write_and_go = conn_read;
        return;
    }

    out_string(c, "ERROR");
}

void process_command(conn *c, char *command) {
    
    int comm = 0;
    int incr = 0;

    /* 
     * for commands set/add/replace, we build an item and read the data
     * directly into it, then continue in nread_complete().
     */ 

    if (settings.verbose > 1)
        fprintf(stderr, "<%d %s\n", c->sfd, command);

    /* All incoming commands will require a response, so we cork at the beginning,
       and uncork at the very end (usually by means of out_string)  */
    set_cork(c, 1);

    if ((strncmp(command, "add ", 4) == 0 && (comm = NREAD_ADD)) || 
        (strncmp(command, "set ", 4) == 0 && (comm = NREAD_SET)) ||
        (strncmp(command, "replace ", 8) == 0 && (comm = NREAD_REPLACE))) {

        char key[251];
        int flags;
        time_t expire;
        int len, res;
        item *it;

        res = sscanf(command, "%*s %250s %u %ld %d\n", key, &flags, &expire, &len);
        if (res!=4 || strlen(key)==0 ) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        if (settings.managed) {
            int bucket = c->bucket;
            if (bucket == -1) {
                out_string(c, "CLIENT_ERROR no BG data in managed mode");
                return;
            }
            c->bucket = -1;
            if (buckets[bucket] != c->gen) {
                out_string(c, "ERROR_NOT_OWNER");
                return;
            }
        }

        expire = realtime(expire);
        it = item_alloc(key, flags, expire, len+2);
        if (it == 0) {
            out_string(c, "SERVER_ERROR out of memory");
            /* swallow the data line */
            c->write_and_go = conn_swallow;
            c->sbytes = len+2;
            return;
        }

        c->item_comm = comm;
        c->item = it;
        c->ritem = ITEM_data(it);
        c->rlbytes = it->nbytes;
        c->state = conn_nread;
        return;
    }

    if ((strncmp(command, "incr ", 5) == 0 && (incr = 1)) ||
        (strncmp(command, "decr ", 5) == 0)) {
        char temp[32];
        unsigned int value;
        item *it;
        unsigned int delta;
        char key[251];
        int res;
        char *ptr;
        time_t now = time(0);

        res = sscanf(command, "%*s %250s %u\n", key, &delta);
        if (res!=2 || strlen(key)==0 ) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        if (settings.managed) {
            int bucket = c->bucket;
            if (bucket == -1) {
                out_string(c, "CLIENT_ERROR no BG data in managed mode");
                return;
            }
            c->bucket = -1;
            if (buckets[bucket] != c->gen) {
                out_string(c, "ERROR_NOT_OWNER");
                return;
            }
        }

        it = assoc_find(key);
        if (it && (it->it_flags & ITEM_DELETED)) {
            it = 0;
        }
        if (it && it->exptime && it->exptime < now) {
            item_unlink(it);
            it = 0;
        }

        if (!it) {
            out_string(c, "NOT_FOUND");
            return;
        }

        ptr = ITEM_data(it);
        while (*ptr && (*ptr<'0' && *ptr>'9')) ptr++;
        
        value = atoi(ptr);

        if (incr)
            value+=delta;
        else {
            if (delta >= value) value = 0;
            else value-=delta;
        }

        sprintf(temp, "%u", value);
        res = strlen(temp);
        if (res + 2 > it->nbytes) { /* need to realloc */
            item *new_it;
            new_it = item_alloc(ITEM_key(it), it->flags, it->exptime, res + 2 );
            if (new_it == 0) {
                out_string(c, "SERVER_ERROR out of memory");
                return;
            }
            memcpy(ITEM_data(new_it), temp, res);
            memcpy(ITEM_data(new_it) + res, "\r\n", 2);
            item_replace(it, new_it);
        } else { /* replace in-place */
            memcpy(ITEM_data(it), temp, res);
            memset(ITEM_data(it) + res, ' ', it->nbytes-res-2);
        }
        out_string(c, temp);
        return;
    }
        
    if (strncmp(command, "get ", 4) == 0) {

        char *start = command + 4;
        char key[251];
        int next;
        int i = 0;
        item *it;
        time_t now = time(0);

        if (settings.managed) {
            int bucket = c->bucket;
            if (bucket == -1) {
                out_string(c, "CLIENT_ERROR no BG data in managed mode");
                return;
            }
            c->bucket = -1;
            if (buckets[bucket] != c->gen) {
                out_string(c, "ERROR_NOT_OWNER");
                return;
            }
        }

        while(sscanf(start, " %250s%n", key, &next) >= 1) {
            start+=next;
            stats.get_cmds++;
            it = assoc_find(key);
            if (it && (it->it_flags & ITEM_DELETED)) {
                it = 0;
            }
            if (settings.oldest_live && settings.oldest_live <= now &&
                it && it->time <= settings.oldest_live) {
                item_unlink(it);
                it = 0;
            }
            if (it && it->exptime && it->exptime < now) {
                item_unlink(it);
                it = 0;
            }

            if (it) {
                if (i >= c->isize) {
                    item **new_list = realloc(c->ilist, sizeof(item *)*c->isize*2);
                    if (new_list) {
                        c->isize *= 2;
                        c->ilist = new_list;
                    } else break;
                }
                stats.get_hits++;
                it->refcount++;
                item_update(it);
                *(c->ilist + i) = it;
                i++;
            } else stats.get_misses++;
        }
        c->icurr = c->ilist;
        c->ileft = i;
        if (c->ileft) {
            c->ipart = 0;
            c->state = conn_mwrite;
            c->ibytes = 0;
            return;
        } else {
            out_string(c, "END");
            return;
        }
    }

    if (strncmp(command, "delete ", 7) == 0) {
        char key[251];
        item *it;
        int res;
        time_t exptime = 0;

        if (settings.managed) {
            int bucket = c->bucket;
            if (bucket == -1) {
                out_string(c, "CLIENT_ERROR no BG data in managed mode");
                return;
            }
            c->bucket = -1;
            if (buckets[bucket] != c->gen) {
                out_string(c, "ERROR_NOT_OWNER");
                return;
            }
        }

        res = sscanf(command, "%*s %250s %ld", key, &exptime);
        it = assoc_find(key);
        if (!it) {
            out_string(c, "NOT_FOUND");
            return;
        }

        if (exptime == 0) {
            item_unlink(it);
            out_string(c, "DELETED");
            return;
        }

        if (delcurr >= deltotal) {
            item **new_delete = realloc(todelete, sizeof(item *) * deltotal * 2);
            if (new_delete) {
                todelete = new_delete;
                deltotal *= 2;
            } else { 
                /* 
                 * can't delete it immediately, user wants a delay,
                 * but we ran out of memory for the delete queue
                 */
                out_string(c, "SERVER_ERROR out of memory");
                return;
            }
        }
            
        exptime = realtime(exptime);

        it->refcount++;
        /* use its expiration time as its deletion time now */
        it->exptime = exptime;
        it->it_flags |= ITEM_DELETED;
        todelete[delcurr++] = it;
        out_string(c, "DELETED");
        return;
    }

    if (strncmp(command, "own ", 4) == 0) {
        int bucket, gen;
        char *start = command+4;
        if (!settings.managed) {
            out_string(c, "CLIENT_ERROR not a managed instance");
            return;
        }
        if (sscanf(start, "%u:%u\r\n", &bucket,&gen) == 2) {
            if ((bucket < 0) || (bucket >= MAX_BUCKETS)) {
                out_string(c, "CLIENT_ERROR bucket number out of range");
                return;
            }
            buckets[bucket] = gen;
            out_string(c, "OWNED");
            return;
        } else {
            out_string(c, "CLIENT_ERROR bad format");
            return;
        }
    }

    if (strncmp(command, "disown ", 7) == 0) {
        int bucket;
        char *start = command+7;
        if (!settings.managed) {
            out_string(c, "CLIENT_ERROR not a managed instance");
            return;
        }
        if (sscanf(start, "%u\r\n", &bucket) == 1) {
            if ((bucket < 0) || (bucket >= MAX_BUCKETS)) {
                out_string(c, "CLIENT_ERROR bucket number out of range");
                return;
            }
            buckets[bucket] = 0;
            out_string(c, "DISOWNED");
            return;
        } else {
            out_string(c, "CLIENT_ERROR bad format");
            return;
        }
    }

    if (strncmp(command, "bg ", 3) == 0) {
        int bucket, gen;
        char *start = command+3;
        if (!settings.managed) {
            out_string(c, "CLIENT_ERROR not a managed instance");
            return;
        }
        if (sscanf(start, "%u:%u\r\n", &bucket,&gen) == 2) {
            /* we never write anything back, even if input's wrong */
            if ((bucket < 0) || (bucket >= MAX_BUCKETS) || (gen<=0)) {
                /* do nothing, bad input */
            } else {
                c->bucket = bucket;
                c->gen = gen;
            }
            c->state = conn_read;
            /* normally conn_write uncorks the connection, but this
               is the only time we accept a command w/o writing anything */
            set_cork(c,0); 
            return;
        } else {
            out_string(c, "CLIENT_ERROR bad format");
            return;
        }
    }

    if (strncmp(command, "stats", 5) == 0) {
        process_stat(c, command);
        return;
    }

    if (strncmp(command, "flush_all", 9) == 0) {
        time_t exptime = 0;
        int res;

        if (strcmp(command, "flush_all") == 0) {
            settings.oldest_live = time(0);
            out_string(c, "OK");
            return;
        }

        res = sscanf(command, "%*s %ld", &exptime); 
        if (res != 1) {
            out_string(c, "ERROR");
            return;
        }

        settings.oldest_live = realtime(exptime);
        out_string(c, "OK");
        return;
    }

    if (strcmp(command, "version") == 0) {
        out_string(c, "VERSION " VERSION);
        return;
    }

    if (strcmp(command, "quit") == 0) {
        c->state = conn_closing;
        return;
    }

    if (strncmp(command, "slabs reassign ", 15) == 0) {
        int src, dst;
        char *start = command+15;
        if (sscanf(start, "%u %u\r\n", &src, &dst) == 2) {
            int rv = slabs_reassign(src, dst);
            if (rv == 1) {
                out_string(c, "DONE");
                return;
            }
            if (rv == 0) {
                out_string(c, "CANT");
                return;
            }
            if (rv == -1) {
                out_string(c, "BUSY");
                return;
            }
        }
        out_string(c, "CLIENT_ERROR bogus command");
        return;
    }
    
    out_string(c, "ERROR");
    return;
}

/* 
 * if we have a complete line in the buffer, process it.
 */
int try_read_command(conn *c) {
    char *el, *cont;

    if (!c->rbytes)
        return 0;
    el = memchr(c->rcurr, '\n', c->rbytes);
    if (!el)
        return 0;
    cont = el + 1;
    if (el - c->rcurr > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    process_command(c, c->rcurr);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    return 1;
}

/*
 * read from network as much as we can, handle buffer overflow and connection
 * close. 
 * before reading, move the remaining incomplete fragment of a command
 * (if any) to the beginning of the buffer.
 * return 0 if there's nothing to read on the first read.
 */
int try_read_network(conn *c) {
    int gotdata = 0;
    int res;

    if (c->rcurr != c->rbuf) {
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) {
        if (c->rbytes >= c->rsize) {
            char *new_rbuf = realloc(c->rbuf, c->rsize*2);
            if (!new_rbuf) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't realloc input buffer\n");
                c->rbytes = 0; /* ignore what we read */
                out_string(c, "SERVER_ERROR out of memory");
                c->write_and_go = conn_closing;
                return 1;
            }
            c->rbuf = new_rbuf; c->rsize *= 2;
        }
        res = read(c->sfd, c->rbuf + c->rbytes, c->rsize - c->rbytes);
        if (res > 0) {
            stats.bytes_read += res;
            gotdata = 1;
            c->rbytes += res;
            continue;
        }
        if (res == 0) {
            /* connection closed */
            c->state = conn_closing;
            return 1;
        }
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            else return 0;
        }
    }
    return gotdata;
}

int update_event(conn *c, int new_flags) {
    if (c->ev_flags == new_flags)
        return 1;
    if (event_del(&c->event) == -1) return 0;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return 0;
    return 1;
}
    
void drive_machine(conn *c) {

    int exit = 0;
    int sfd, flags = 1;
    socklen_t addrlen;
    struct sockaddr addr;
    conn *newc;
    int res;

    while (!exit) {
        /* printf("state %d\n", c->state);*/
        switch(c->state) {
        case conn_listening:
            addrlen = sizeof(addr);
            if ((sfd = accept(c->sfd, &addr, &addrlen)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    exit = 1;
                    break;
                } else {
                    perror("accept()");
                }
                break;
            }
            if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
                fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                perror("setting O_NONBLOCK");
                close(sfd);
                break;
            }            
            newc = conn_new(sfd, conn_read, EV_READ | EV_PERSIST);
            if (!newc) {
                if (settings.verbose > 0)
                    fprintf(stderr, "couldn't create new connection\n");
                close(sfd);
                break;
            }

            break;

        case conn_read:
            if (try_read_command(c)) {
                continue;
            }
            if (try_read_network(c)) {
                continue;
            }
            /* we have no command line and no data to read from network */
            if (!update_event(c, EV_READ | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                c->state = conn_closing;
                break;
            }
            exit = 1;
            break;

        case conn_nread:
            /* we are reading rlbytes into ritem; */
            if (c->rlbytes == 0) {
                complete_nread(c);
                break;
            }
            /* first check if we have leftovers in the conn_read buffer */
            if (c->rbytes > 0) {
                int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
                memcpy(c->ritem, c->rcurr, tocopy);
                c->ritem += tocopy;
                c->rlbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                break;
            }

            /*  now try reading from the socket */
            res = read(c->sfd, c->ritem, c->rlbytes);
            if (res > 0) {
                stats.bytes_read += res;
                c->ritem += res;
                c->rlbytes -= res;
                break;
            }
            if (res == 0) { /* end of stream */
                c->state = conn_closing;
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!update_event(c, EV_READ | EV_PERSIST)) {
                    if (settings.verbose > 0) 
                        fprintf(stderr, "Couldn't update event\n");
                    c->state = conn_closing;
                    break;
                }
                exit = 1;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to read, and not due to blocking\n");
            c->state = conn_closing;
            break;

        case conn_swallow:
            /* we are reading sbytes and throwing them away */
            if (c->sbytes == 0) {
                c->state = conn_read;
                break;
            }

            /* first check if we have leftovers in the conn_read buffer */
            if (c->rbytes > 0) {
                int tocopy = c->rbytes > c->sbytes ? c->sbytes : c->rbytes;
                c->sbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                break;
            }

            /*  now try reading from the socket */
            res = read(c->sfd, c->rbuf, c->rsize > c->sbytes ? c->sbytes : c->rsize);
            if (res > 0) {
                stats.bytes_read += res;
                c->sbytes -= res;
                break;
            }
            if (res == 0) { /* end of stream */
                c->state = conn_closing;
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!update_event(c, EV_READ | EV_PERSIST)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    c->state = conn_closing;
                    break;
                }
                exit = 1;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to read, and not due to blocking\n");
            c->state = conn_closing;
            break;

        case conn_write:
            /* we are writing wbytes bytes starting from wcurr */
            if (c->wbytes == 0) {
                if (c->write_and_free) {
                    free(c->write_and_free);
                    c->write_and_free = 0;
                }
                c->state = c->write_and_go;
                if (c->state == conn_read)
                    set_cork(c, 0);
                break;
            }
            res = write(c->sfd, c->wcurr, c->wbytes);
            if (res > 0) {
                stats.bytes_written += res;
                c->wcurr  += res;
                c->wbytes -= res;
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    c->state = conn_closing;
                    break;
                }                
                exit = 1;
                break;
            }
            /* if res==0 or res==-1 and error is not EAGAIN or EWOULDBLOCK,
               we have a real error, on which we close the connection */
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to write, and not due to blocking\n");
            c->state = conn_closing;
            break;
        case conn_mwrite:
            /* 
             * we're writing ibytes bytes from iptr. iptr alternates between
             * ibuf, where we build a string "VALUE...", and ITEM_data(it) for the 
             * current item. When we finish a chunk, we choose the next one using 
             * ipart, which has the following semantics: 0 - start the loop, 1 - 
             * we finished ibuf, go to current ITEM_data(it); 2 - we finished ITEM_data(it),
             * move to the next item and build its ibuf; 3 - we finished all items, 
             * write "END".
             */
            if (c->ibytes > 0) {
                res = write(c->sfd, c->iptr, c->ibytes);
                if (res > 0) {
                    stats.bytes_written += res;
                    c->iptr += res;
                    c->ibytes -= res;
                    break;
                }
                if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                        if (settings.verbose > 0)
                            fprintf(stderr, "Couldn't update event\n");
                        c->state = conn_closing;
                        break;
                    }
                    exit = 1;
                    break;
                }
                /* if res==0 or res==-1 and error is not EAGAIN or EWOULDBLOCK,
                   we have a real error, on which we close the connection */
                if (settings.verbose > 0)
                    fprintf(stderr, "Failed to write, and not due to blocking\n");
                c->state = conn_closing;
                break;
            } else {
                item *it;
                /* we finished a chunk, decide what to do next */
                switch (c->ipart) {
                case 1:
                    it = *(c->icurr);
                    assert((it->it_flags & ITEM_SLABBED) == 0);
                    c->iptr = ITEM_data(it);
                    c->ibytes = it->nbytes;
                    c->ipart = 2;
                    break;
                case 2:
                    it = *(c->icurr);
                    item_remove(it);
                    c->ileft--;
                    if (c->ileft <= 0) {
                        c->ipart = 3;
                        break;
                    } else {
                        c->icurr++;
                    }
                    /* FALL THROUGH */
                case 0:
                    it = *(c->icurr);
                    assert((it->it_flags & ITEM_SLABBED) == 0);
                    c->ibytes = sprintf(c->ibuf, "VALUE %s %u %u\r\n", ITEM_key(it), it->flags, it->nbytes - 2);
                    if (settings.verbose > 1)
                        fprintf(stderr, ">%d sending key %s\n", c->sfd, ITEM_key(it));
                    c->iptr = c->ibuf;
                    c->ipart = 1;
                    break;
                case 3:
                    out_string(c, "END");
                    break;
                }
            }
            break;

        case conn_closing:
            conn_close(c);
            exit = 1;
            break;
        }

    }

    return;
}


void event_handler(int fd, short which, void *arg) {
    conn *c;
    
    c = (conn *)arg;
    c->which = which;

    /* sanity */
    if (fd != c->sfd) {
        if (settings.verbose > 0)
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
        conn_close(c);
        return;
    }

    /* do as much I/O as possible until we block */
    drive_machine(c);

    /* wait for next event */
    return;
}

int new_socket(void) {
    int sfd;
    int flags;

    if ((sfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        close(sfd);
        return -1;
    }
    return sfd;
}

int server_socket(int port) {
    int sfd;
    struct linger ling = {0, 0};
    struct sockaddr_in addr;
    int flags =1;

    if ((sfd = new_socket()) == -1) {
        return -1;
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
#if !defined(TCP_NOPUSH)
    setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
#endif

    /* 
     * the memset call clears nonstandard fields in some impementations
     * that otherwise mess things up.
     */
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = settings.interface;
    if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind()");
        close(sfd);
        return -1;
    }
    if (listen(sfd, 1024) == -1) {
        perror("listen()");
        close(sfd);
        return -1;
    }
    return sfd;
}

/* invoke right before gdb is called, on assert */
void pre_gdb () {
    int i = 0;
    if(l_socket) close(l_socket);
    for (i=3; i<=500; i++) close(i); /* so lame */
    kill(getpid(), SIGABRT);
}

struct event deleteevent;

void delete_handler(int fd, short which, void *arg) {
    struct timeval t;
    static int initialized = 0;

    if (initialized) {
        /* some versions of libevent don't like deleting events that don't exist,
           so only delete once we know this event has been added. */
        evtimer_del(&deleteevent);
    } else {
        initialized = 1;
    }

    evtimer_set(&deleteevent, delete_handler, 0);
    t.tv_sec = 5; t.tv_usec=0;
    evtimer_add(&deleteevent, &t);

    {
        int i, j=0;
        time_t now = time(0);
        for (i=0; i<delcurr; i++) {
            item *it = todelete[i];
            if (it->exptime < now) {
                assert(it->refcount > 0);
                it->it_flags &= ~ITEM_DELETED;
                item_unlink(it);
                item_remove(it);
            } else {
                todelete[j++] = it;
            }
        }
        delcurr = j;
    }
                
    return;
}
        
void usage(void) {
    printf(PACKAGE " " VERSION "\n");
    printf("-p <num>      port number to listen on\n");
    printf("-l <ip_addr>  interface to listen on, default is INDRR_ANY\n");
    printf("-d            run as a daemon\n");
    printf("-r            maximize core file limit\n");
    printf("-u <username> assume identity of <username> (only when run as root)\n");
    printf("-m <num>      max memory to use for items in megabytes, default is 64 MB\n");
    printf("-M            return error on memory exhausted (rather than removing items)\n");
    printf("-c <num>      max simultaneous connections, default is 1024\n");
    printf("-k            lock down all paged memory\n");
    printf("-v            verbose (print errors/warnings while in event loop)\n");
    printf("-vv           very verbose (also print client commands/reponses)\n");
    printf("-h            print this help and exit\n");
    printf("-i            print memcached and libevent license\n");
    printf("-b            run a managed instanced (mnemonic: buckets)\n");
    printf("-P <file>     save PID in <file>, only used with -d option\n");
    return;
}

void usage_license(void) {
    printf(PACKAGE " " VERSION "\n\n");
    printf(
	"Copyright (c) 2003, Danga Interactive, Inc. <http://www.danga.com/>\n"
	"All rights reserved.\n"
	"\n"
	"Redistribution and use in source and binary forms, with or without\n"
	"modification, are permitted provided that the following conditions are\n"
	"met:\n"
	"\n"
	"    * Redistributions of source code must retain the above copyright\n"
	"notice, this list of conditions and the following disclaimer.\n"
	"\n"
	"    * Redistributions in binary form must reproduce the above\n"
	"copyright notice, this list of conditions and the following disclaimer\n"
	"in the documentation and/or other materials provided with the\n"
	"distribution.\n"
	"\n"
	"    * Neither the name of the Danga Interactive nor the names of its\n"
	"contributors may be used to endorse or promote products derived from\n"
	"this software without specific prior written permission.\n"
	"\n"
	"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
	"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
	"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
	"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
	"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
	"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
	"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
	"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
	"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
	"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
	"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
	"\n"
	"\n"
	"This product includes software developed by Niels Provos.\n"
	"\n"
	"[ libevent ]\n"
	"\n"
	"Copyright 2000-2003 Niels Provos <provos@citi.umich.edu>\n"
	"All rights reserved.\n"
	"\n"
	"Redistribution and use in source and binary forms, with or without\n"
	"modification, are permitted provided that the following conditions\n"
	"are met:\n"
	"1. Redistributions of source code must retain the above copyright\n"
	"   notice, this list of conditions and the following disclaimer.\n"
	"2. Redistributions in binary form must reproduce the above copyright\n"
	"   notice, this list of conditions and the following disclaimer in the\n"
	"   documentation and/or other materials provided with the distribution.\n"
	"3. All advertising materials mentioning features or use of this software\n"
	"   must display the following acknowledgement:\n"
	"      This product includes software developed by Niels Provos.\n"
	"4. The name of the author may not be used to endorse or promote products\n"
	"   derived from this software without specific prior written permission.\n"
	"\n"
	"THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n"
	"IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n"
	"OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n"
	"IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n"
	"INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n"
	"NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
	"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
	"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
	"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n"
	"THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    );

    return;
}

void save_pid(pid_t pid,char *pid_file) {
    FILE *fp;
    if (!pid_file)
        return;

    if (!(fp = fopen(pid_file,"w"))) {
        fprintf(stderr,"Could not open the pid file %s for writing\n",pid_file);
        return;
    }

    fprintf(fp,"%ld\n",(long) pid);
    if (fclose(fp) == -1) {
        fprintf(stderr,"Could not close the pid file %s.\n",pid_file);
        return;
    }
}

void remove_pidfile(char *pid_file) {
  if (!pid_file)
      return;

  if (unlink(pid_file)) {
      fprintf(stderr,"Could not remove the pid file %s.\n",pid_file);
  }

}

int l_socket=0;

int main (int argc, char **argv) {
    int c;
    conn *l_conn;
    struct in_addr addr;
    int lock_memory = 0;
    int daemonize = 0;
    int maxcore = 0;
    char *username = 0;
    struct passwd *pw;
    struct sigaction sa;
    struct rlimit rlim;
    char *pid_file = NULL;

    /* init settings */
    settings_init();

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    /* process arguments */
    while ((c = getopt(argc, argv, "bp:m:Mc:khirvdl:u:P:")) != -1) {
        switch (c) {
        case 'b':
            settings.managed = 1;
            break;
        case 'p':
            settings.port = atoi(optarg);
            break;
        case 'm':
            settings.maxbytes = atoi(optarg)*1024*1024;
            break;
        case 'M':
            settings.evict_to_free = 0;
            break;
        case 'c':
            settings.maxconns = atoi(optarg);
            break;
        case 'h':
            usage();
            exit(0);
        case 'i':
            usage_license();
            exit(0);
        case 'k':
            lock_memory = 1;
            break;
        case 'v':
            settings.verbose++;
            break;
        case 'l':
            if (!inet_aton(optarg, &addr)) {
                fprintf(stderr, "Illegal address: %s\n", optarg);
                return 1;
            } else {
                settings.interface = addr;
            }
            break;
        case 'd':
            daemonize = 1;
            break;
        case 'r':
            maxcore = 1;
            break;
        case 'u':
            username = optarg;
            break;
        case 'P':
            pid_file = optarg;
            break;
        default:
            fprintf(stderr, "Illegal argument \"%c\"\n", c);
            return 1;
        }
    }

    if (maxcore) {
        struct rlimit rlim_new;
        /* 
         * First try raising to infinity; if that fails, try bringing
         * the soft limit to the hard. 
         */
        if (getrlimit(RLIMIT_CORE, &rlim)==0) {
            rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
            if (setrlimit(RLIMIT_CORE, &rlim_new)!=0) {
                /* failed. try raising just to the old max */
                rlim_new.rlim_cur = rlim_new.rlim_max = 
                    rlim.rlim_max;
                (void) setrlimit(RLIMIT_CORE, &rlim_new);
            }
        }
        /* 
         * getrlimit again to see what we ended up with. Only fail if 
         * the soft limit ends up 0, because then no core files will be 
         * created at all.
         */
           
        if ((getrlimit(RLIMIT_CORE, &rlim)!=0) || rlim.rlim_cur==0) {
            fprintf(stderr, "failed to ensure corefile creation\n");
            exit(1);
        }
    }
                        
    /* 
     * If needed, increase rlimits to allow as many connections
     * as needed.
     */
    
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        fprintf(stderr, "failed to getrlimit number of files\n");
        exit(1);
    } else {
        int maxfiles = settings.maxconns;
        if (rlim.rlim_cur < maxfiles) 
            rlim.rlim_cur = maxfiles + 3;
        if (rlim.rlim_max < rlim.rlim_cur)
            rlim.rlim_max = rlim.rlim_cur;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            fprintf(stderr, "failed to set rlimit for open files. Try running as root or requesting smaller maxconns value.\n");
            exit(1);
        }
    }

    /* 
     * initialization order: first create the listening socket
     * (may need root on low ports), then drop root if needed,
     * then daemonise if needed, then init libevent (in some cases
     * descriptors created by libevent wouldn't survive forking).
     */

    /* create the listening socket and bind it */
    l_socket = server_socket(settings.port);
    if (l_socket == -1) {
        fprintf(stderr, "failed to listen\n");
        exit(1);
    }

    /* lose root privileges if we have them */
    if (getuid()== 0 || geteuid()==0) {
        if (username==0 || *username=='\0') {
            fprintf(stderr, "can't run as root without the -u switch\n");
            return 1;
        }
        if ((pw = getpwnam(username)) == 0) {
            fprintf(stderr, "can't find the user %s to switch to\n", username);
            return 1;
        }
        if (setgid(pw->pw_gid)<0 || setuid(pw->pw_uid)<0) {
            fprintf(stderr, "failed to assume identity of user %s\n", username);
            return 1;
        }
    }

    /* daemonize if requested */
    /* if we want to ensure our ability to dump core, don't chdir to / */
    if (daemonize) {
        int res;
        res = daemon(maxcore, settings.verbose);
        if (res == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            return 1;
        }
    }


    /* initialize other stuff */
    item_init();
    event_init();
    stats_init();
    assoc_init();
    conn_init();
    slabs_init(settings.maxbytes);

    /* managed instance? alloc and zero a bucket array */
    if (settings.managed) {
        buckets = malloc(sizeof(int)*MAX_BUCKETS);
        if (buckets == 0) {
            fprintf(stderr, "failed to allocate the bucket array");
            exit(1);
        }
        memset(buckets, 0, sizeof(int)*MAX_BUCKETS);
    }

    /* lock paged memory if needed */
    if (lock_memory) {
#ifdef HAVE_MLOCKALL
        mlockall(MCL_CURRENT | MCL_FUTURE);
#else
        fprintf(stderr, "warning: mlockall() not supported on this platform.  proceeding without.\n");
#endif
    }

    /*
     * ignore SIGPIPE signals; we can use errno==EPIPE if we
     * need that information
     */
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigemptyset(&sa.sa_mask) == -1 ||
        sigaction(SIGPIPE, &sa, 0) == -1) {
        perror("failed to ignore SIGPIPE; sigaction");
        exit(1); 
    }

    /* create the initial listening connection */
    if (!(l_conn = conn_new(l_socket, conn_listening, EV_READ | EV_PERSIST))) {
        fprintf(stderr, "failed to create listening connection");
        exit(1);
    }

    /* initialise deletion array and timer event */
    deltotal = 200; delcurr = 0;
    todelete = malloc(sizeof(item *)*deltotal);
    delete_handler(0,0,0); /* sets up the event */

    /* save the PID in if we're a daemon */
    if (daemonize)
        save_pid(getpid(),pid_file);

    /* enter the loop */
    event_loop(0);

    /* remove the PID file if we're a daemon */
    if (daemonize)
        remove_pidfile(pid_file);

    return 0;
}

