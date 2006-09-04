/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Hash table
 *
 * The hash function used here is by Bob Jenkins, 1996:
 *    <http://burtleburtle.net/bob/hash/doobs.html>
 *       "By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.
 *       You may use this code any way you wish, private, educational,
 *       or commercial.  It's free."
 *
 * The rest of the file is licensed under the BSD license.  See LICENSE.
 *
 * $Id$
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <event.h>
#include <assert.h>

#include "memcached.h"

typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

/* hard-code one million buckets, for now (2**20 == 4MB hash) */
#define HASHPOWER  20

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define mix(a,b,c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 32-bit value
  k       : the key (the unaligned variable-length array of bytes)
  len     : the length of the key, counting by bytes
  initval : can be any 4-byte value
Returns a 32-bit value.  Every bit of the key affects every bit of
the return value.  Every 1-bit and 2-bit delta achieves avalanche.
About 6*len+35 instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 32 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (ub1 **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.  You may use this
code any way you wish, private, educational, or commercial.  It's free.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^32 is
acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

ub4 hash( k, length, initval)
     register ub1 *k;        /* the key */
     register ub4  length;   /* the length of the key */
     register ub4  initval;  /* the previous hash, or an arbitrary value */
{
    register ub4 a,b,c,len;

    /* Set up the internal state */
    len = length;
    a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
    c = initval;         /* the previous hash value */

    /*---------------------------------------- handle most of the key */
    while (len >= 12)
        {
            a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
            b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
            c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
            mix(a,b,c);
            k += 12; len -= 12;
        }

    /*------------------------------------- handle the last 11 bytes */
    c += length;
    switch(len)              /* all the case statements fall through */
        {
        case 11: c+=((ub4)k[10]<<24);
        case 10: c+=((ub4)k[9]<<16);
        case 9 : c+=((ub4)k[8]<<8);
            /* the first byte of c is reserved for the length */
        case 8 : b+=((ub4)k[7]<<24);
        case 7 : b+=((ub4)k[6]<<16);
        case 6 : b+=((ub4)k[5]<<8);
        case 5 : b+=k[4];
        case 4 : a+=((ub4)k[3]<<24);
        case 3 : a+=((ub4)k[2]<<16);
        case 2 : a+=((ub4)k[1]<<8);
        case 1 : a+=k[0];
            /* case 0: nothing left to add */
        }
    mix(a,b,c);
    /*-------------------------------------------- report the result */
    return c;
}

static item** hashtable = 0;

void assoc_init(void) {
    unsigned int hash_size = hashsize(HASHPOWER) * sizeof(void*);
    hashtable = malloc(hash_size);
    if (! hashtable) {
        fprintf(stderr, "Failed to init hashtable.\n");
        exit(1);
    }
    memset(hashtable, 0, hash_size);
}

item *assoc_find(char *key) {
    ub4 hv = hash(key, strlen(key), 0) & hashmask(HASHPOWER);
    item *it = hashtable[hv];

    while (it) {
        if (strcmp(key, ITEM_key(it)) == 0)
            return it;
        it = it->h_next;
    }
    return 0;
}

/* returns the address of the item pointer before the key.  if *item == 0,
   the item wasn't found */

static item** _hashitem_before (char *key) {
    ub4 hv = hash(key, strlen(key), 0) & hashmask(HASHPOWER);
    item **pos = &hashtable[hv];

    while (*pos && strcmp(key, ITEM_key(*pos))) {
        pos = &(*pos)->h_next;
    }
    return pos;
}

/* Note: this isn't an assoc_update.  The key must not already exist to call this */
int assoc_insert(char *key, item *it) {
    ub4 hv;
    assert(assoc_find(key) == 0);  /* shouldn't have duplicately named things defined */
    hv = hash(key, strlen(key), 0) & hashmask(HASHPOWER);
    it->h_next = hashtable[hv];
    hashtable[hv] = it;
    return 1;
}

void assoc_delete(char *key) {
    item **before = _hashitem_before(key);
    if (*before) {
        item *nxt = (*before)->h_next;
        (*before)->h_next = 0;   /* probably pointless, but whatever. */
        *before = nxt;
        return;
    }
    /* Note:  we never actually get here.  the callers don't delete things
       they can't find. */
    assert(*before != 0);
}
