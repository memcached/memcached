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
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <event.h>
#include <malloc.h>

#include "memcached.h"

struct stats stats;
struct settings settings;

static item **todelete = 0;
static int delcurr;
static int deltotal;

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
}

conn **freeconns;
int freetotal;
int freecurr;

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
        c->isize = 200;
        stats.conn_structs++;
    }

    c->sfd = sfd;
    c->state = init_state;
    c->rlbytes = 0;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->rcurr = c->rbuf;
    c->icurr = c->ilist; 
    c->ileft = 0;
    c->iptr = c->ibuf;
    c->ibytes = 0;

    c->write_and_go = conn_read;
    c->write_and_free = 0;
    c->item = 0;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1) {
        free(c);
        return 0;
    }

    stats.curr_conns++;
    stats.total_conns++;

    return c;
}

void conn_close(conn *c) {
    /* delete the event, the socket and the conn */
    event_del(&c->event);

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
        char temp[768];
        pid_t pid = getpid();
        char *pos = temp;

        pos += sprintf(pos, "STAT pid %u\r\n", pid);
        pos += sprintf(pos, "STAT uptime %lu\r\n", now - stats.started);
        pos += sprintf(pos, "STAT version " VERSION "\r\n");
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

    if ((strncmp(command, "add ", 4) == 0 && (comm = NREAD_ADD)) || 
        (strncmp(command, "set ", 4) == 0 && (comm = NREAD_SET)) ||
        (strncmp(command, "replace ", 8) == 0 && (comm = NREAD_REPLACE))) {

        char key[251];
        int flags;
        time_t expire;
        int len, res;
        item *it;

        res = sscanf(command, "%*s %250s %u %lu %d\n", key, &flags, &expire, &len);
        if (res!=4 || strlen(key)==0 ) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
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
        c->rcurr = ITEM_data(it);
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

        while(sscanf(start, " %250s%n", key, &next) >= 1) {
            start+=next;
            stats.get_cmds++;
            it = assoc_find(key);
            if (it && (it->it_flags & ITEM_DELETED)) {
                it = 0;
            }
            if (it && it->exptime && it->exptime < now) {
                item_unlink(it);
                it = 0;
            }

            if (it) {
                stats.get_hits++;
                it->refcount++;
                item_update(it);
                *(c->ilist + i) = it;
                i++;
                if (i > c->isize) {
                    c->isize *= 2;
                    c->ilist = realloc(c->ilist, sizeof(item *)*c->isize);
                }
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
        char *start = command+7;
        item *it;

        sscanf(start, " %250s", key);
        it = assoc_find(key);
        if (!it) {
            out_string(c, "NOT_FOUND");
            return;
        }

        it->refcount++;
        /* use its expiration time as its deletion time now */
        it->exptime = time(0) + 4;
        it->it_flags |= ITEM_DELETED;
        todelete[delcurr++] = it;
        if (delcurr >= deltotal) {
            deltotal *= 2;
            todelete = realloc(todelete, sizeof(item *)*deltotal);
        }
        out_string(c, "DELETED");
        return;
    }
        
    if (strncmp(command, "stats", 5) == 0) {
        process_stat(c, command);
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
 * if we have a complete line in the buffer, process it and move whatever
 * remains in the buffer to its beginning.
 */
int try_read_command(conn *c) {
    char *el, *cont;

    if (!c->rbytes)
        return 0;
    el = memchr(c->rbuf, '\n', c->rbytes);
    if (!el)
        return 0;
    cont = el + 1;
    if (el - c->rbuf > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    process_command(c, c->rbuf);

    if (cont - c->rbuf < c->rbytes) { /* more stuff in the buffer */
        memmove(c->rbuf, cont, c->rbytes - (cont - c->rbuf));
    }
    c->rbytes -= (cont - c->rbuf);
    return 1;
}

/*
 * read from network as much as we can, handle buffer overflow and connection
 * close. 
 * return 0 if there's nothing to read on the first read.
 */
int try_read_network(conn *c) {
    int gotdata = 0;
    int res;
    while (1) {
        if (c->rbytes >= c->rsize) {
            char *new_rbuf = realloc(c->rbuf, c->rsize*2);
            if (!new_rbuf) {
                if(settings.verbose)
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
      /*printf("state %d\n", c->state); */
        switch(c->state) {
        case conn_listening:
            addrlen = sizeof(addr);
            if ((sfd = accept(c->sfd, &addr, &addrlen)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    perror("accept() shouldn't block");
                } else {
                    perror("accept()");
                }
                return;
            }
            if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
                fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                perror("setting O_NONBLOCK");
                close(sfd);
                return;
            }            
            newc = conn_new(sfd, conn_read, EV_READ | EV_PERSIST);
            if (!newc) {
                if(settings.verbose)
                    fprintf(stderr, "couldn't create new connection\n");
                close(sfd);
                return;
            }
            exit = 1;
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
                if(settings.verbose)
                    fprintf(stderr, "Couldn't update event\n");
                c->state = conn_closing;
                break;
            }
            exit = 1;
            break;

        case conn_nread:
            /* we are reading rlbytes into rcurr; */
            if (c->rlbytes == 0) {
                complete_nread(c);
                break;
            }
            /* first check if we have leftovers in the conn_read buffer */
            if (c->rbytes > 0) {
                int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
                memcpy(c->rcurr, c->rbuf, tocopy);
                c->rcurr += tocopy;
                c->rlbytes -= tocopy;
                if (c->rbytes > tocopy) {
                    memmove(c->rbuf, c->rbuf+tocopy, c->rbytes - tocopy);
                }
                c->rbytes -= tocopy;
                break;
            }

            /*  now try reading from the socket */
            res = read(c->sfd, c->rcurr, c->rlbytes);
            if (res > 0) {
                stats.bytes_read += res;
                c->rcurr += res;
                c->rlbytes -= res;
                break;
            }
            if (res == 0) { /* end of stream */
                c->state = conn_closing;
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!update_event(c, EV_READ | EV_PERSIST)) {
                    if(settings.verbose) 
                        fprintf(stderr, "Couldn't update event\n");
                    c->state = conn_closing;
                    break;
                }
                exit = 1;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if(settings.verbose)
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
                if (c->rbytes > tocopy) {
                    memmove(c->rbuf, c->rbuf+tocopy, c->rbytes - tocopy);
                }
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
                    if(settings.verbose)
                        fprintf(stderr, "Couldn't update event\n");
                    c->state = conn_closing;
                    break;
                }
                exit = 1;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if(settings.verbose)
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
                    if(settings.verbose)
                        fprintf(stderr, "Couldn't update event\n");
                    c->state = conn_closing;
                    break;
                }                
                exit = 1;
                break;
            }
            /* if res==0 or res==-1 and error is not EAGAIN or EWOULDBLOCK,
               we have a real error, on which we close the connection */
            if(settings.verbose)
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
                        if(settings.verbose)
                            fprintf(stderr, "Couldn't update event\n");
                        c->state = conn_closing;
                        break;
                    }
                    exit = 1;
                    break;
                }
                /* if res==0 or res==-1 and error is not EAGAIN or EWOULDBLOCK,
                   we have a real error, on which we close the connection */
                if(settings.verbose)
                    fprintf(stderr, "Failed to write, and not due to blocking\n");
                c->state = conn_closing;
                break;
            } else {
                item *it;
                /* we finished a chunk, decide what to do next */
                switch (c->ipart) {
                case 1:
                    it = *(c->icurr);
                    c->iptr = ITEM_data(it);
                    c->ibytes = it->nbytes;
                    c->ipart = 2;
                    break;
                case 2:
                    it = *(c->icurr);
                    item_remove(it);
                    if (c->ileft <= 1) {
                        c->ipart = 3;
                        break;
                    } else {
                        c->ileft--;
                        c->icurr++;
                    }
                    /* FALL THROUGH */
                case 0:
                    it = *(c->icurr);
                    sprintf(c->ibuf, "VALUE %s %u %u\r\n", ITEM_key(it), it->flags, it->nbytes - 2);
                    c->iptr = c->ibuf;
                    c->ibytes = strlen(c->iptr);
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
        if(settings.verbose)
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


struct event deleteevent;

void delete_handler(int fd, short which, void *arg) {
    struct timeval t;

    evtimer_del(&deleteevent);
    evtimer_set(&deleteevent, delete_handler, 0);
    t.tv_sec = 5; t.tv_usec=0;
    evtimer_add(&deleteevent, &t);

    {
        int i, j=0;
        time_t now = time(0);
        for (i=0; i<delcurr; i++) {
            if (todelete[i]->exptime < now) {
                /* no longer mark it deleted. it's now expired, same as dead */
                todelete[i]->it_flags &= ~ITEM_DELETED;
                todelete[i]->refcount--;
            } else {
                todelete[j++] = todelete[i];
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
    printf("-m <num>      max memory to use for items in megabytes, default is 64 MB\n");
    printf("-c <num>      max simultaneous connections, default is 1024\n");
    printf("-k            lock down all paged memory\n");
    printf("-v            verbose (print errors/warnings while in event loop)\n");
    printf("-h            print this help and exit\n");
    printf("-i            print memcached and libevent license\n");
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


int main (int argc, char **argv) {
    int c;
    int l_socket;
    conn *l_conn;
    struct in_addr addr;
    int lock_memory = 0;
    int daemonize = 0;

    /* init settings */
    settings_init();

    /* process arguments */
    while ((c = getopt(argc, argv, "p:m:c:khivdl:")) != -1) {
        switch (c) {
        case 'p':
            settings.port = atoi(optarg);
            break;
        case 'm':
            settings.maxbytes = atoi(optarg)*1024*1024;
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
            settings.verbose = 1;
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
        default:
            fprintf(stderr, "Illegal argument \"%c\"\n", c);
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


    if (daemonize) {
        int res;
        res = daemon(0, 0);
        if (res == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            return 1;
        }
    }

    /* lock paged memory if needed */
    if (lock_memory) {
        mlockall(MCL_CURRENT | MCL_FUTURE);
    }

    /* create the listening socket and bind it */
    l_socket = server_socket(settings.port);
    if (l_socket == -1) {
        fprintf(stderr, "failed to listen\n");
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

    /* enter the loop */
    event_loop(0);

    return 0;
}

