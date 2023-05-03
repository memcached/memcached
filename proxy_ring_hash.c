/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
* Copyright (c) 2022, Cache Forge LLC, All rights reserved.
* Alan Kasindorf <alan@cacheforge.com>
* Copyright (c) 2007, Last.fm, All rights reserved.
* Richard Jones <rj@last.fm>
* Christian Muehlhaeuser <muesli@gmail.com>
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the Last.fm Limited nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY Last.fm ``AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Last.fm BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "proxy.h"
#include "md5.h"

#define DEFAULT_BUCKET_SIZE 160

typedef struct {
    unsigned int point; // continuum point.
    unsigned int id; // server id.
} cpoint;

typedef struct {
    struct proxy_hash_caller phc; // passed back to the proxy API.
    unsigned int total_buckets;
    cpoint continuum[]; // points to server ids.
} ketama_t;

static uint64_t ketama_key_hasher(const void *key, size_t len, uint64_t seed);
static struct proxy_hash_func ketama_key_hash = {
    ketama_key_hasher,
};

/* FROM ketama.c */
static void ketama_md5_digest( char* inString, unsigned char md5pword[16] )
{
    md5_state_t md5state;

    md5_init( &md5state );
    md5_append( &md5state, (unsigned char *)inString, strlen( inString ) );
    md5_finish( &md5state, md5pword );
}

static int ketama_compare(const void *p1, const void *p2) {
    const cpoint *a = p1;
    const cpoint *b = p2;

    return (a->point < b->point) ? -1 : ((a->point > b->point) ? 1 : 0);
}

static uint64_t ketama_key_hasher(const void *key, size_t len, uint64_t seed) {
    // NOTE: seed is ignored!
    // embedding the md5 bits since key is specified with a length here.
    md5_state_t md5state;
    unsigned char digest[16];

    md5_init(&md5state);
    md5_append(&md5state, (unsigned char *)key, len);
    md5_finish(&md5state, digest);

    // mix the hash down (from ketama_hashi)
    unsigned int h = (unsigned int)(( digest[3] << 24 )
                        | ( digest[2] << 16 )
                        | ( digest[1] <<  8 )
                        |   digest[0] );
    return h;
}

// Note: must return lookupas as zero-indexed.
static uint32_t ketama_get_server(uint64_t hash, void *ctx) {
    ketama_t *kt = (ketama_t *)ctx;
    unsigned int h = hash;
    int highp = kt->total_buckets;
    int lowp = 0, midp;
    unsigned int midval, midval1;

    // divide and conquer array search to find server with next biggest
    // point after what this key hashes to
    while ( 1 )
    {
        midp = (int)( ( lowp+highp ) / 2 );

        if ( midp == kt->total_buckets )
            return kt->continuum[0].id-1; // if at the end, roll back to zeroth

        midval = kt->continuum[midp].point;
        midval1 = midp == 0 ? 0 : kt->continuum[midp-1].point;

        if ( h <= midval && h > midval1 )
            return kt->continuum[midp].id-1;

        if ( midval < h )
            lowp = midp + 1;
        else
            highp = midp - 1;

        if ( lowp > highp )
            return kt->continuum[0].id-1;
    }
}
/* END FROM ketama.c */

// not much to be done about this without making the interface unusable.
#define MODE_DEFAULT 0 // uses xxhash
#define MODE_KETAMA 1 // uses md5
#define MODE_TWEMPROXY 2 // technically "libmemcached" ?
#define MODE_EVCACHE 3 // not sure why this has a funny string init.

// Not sure the hash algo used here matters all that much given the low number
// of points... but it might be better to let it be overrideable.
static void _add_server_default(ketama_t *kt, size_t hashstring_size, const char **parts,
        lua_Integer bucket_size, lua_Integer id, unsigned int *cont) {
    char *hashstring = malloc(hashstring_size);

    for (int k = 0; k < bucket_size; k++) {
        size_t len = snprintf(hashstring, hashstring_size, "%s:%s-%d", parts[0], parts[1], k);
        kt->continuum[*cont].point = (unsigned int) XXH3_64bits(hashstring, len);
        kt->continuum[*cont].id = id;
    }

    free(hashstring);
}

static void _add_server_ketama(ketama_t *kt, size_t hashstring_size, const char **parts,
        lua_Integer bucket_size, lua_Integer id, unsigned int *cont) {
    char *hashstring = malloc(hashstring_size);

    for (int k = 0; k < bucket_size / 4; k++) {
        unsigned char digest[16];

        // - create hashing string for ketama
        snprintf(hashstring, hashstring_size, "%s:%s-%d", parts[0], parts[1], k);

        // - md5() hash it
        // mostly from ketama.c
        ketama_md5_digest(hashstring, digest);

        /* Use successive 4-bytes from hash as numbers
         * for the points on the circle: */
        for(int h = 0; h < 4; h++ )
        {
            kt->continuum[*cont].point = ( digest[3+h*4] << 24 )
                                  | ( digest[2+h*4] << 16 )
                                  | ( digest[1+h*4] <<  8 )
                                  |   digest[h*4];
            kt->continuum[*cont].id = id;
            (*cont)++;
        }

    }

    free(hashstring);
}

static void _add_server_twemproxy(ketama_t *kt, size_t hashstring_size, const char **parts,
        lua_Integer bucket_size, lua_Integer id, unsigned int *cont) {
    char *hashstring = malloc(hashstring_size);

    for (int k = 0; k < bucket_size / 4; k++) {
        unsigned char digest[16];

        // - create hashing string for ketama
        if (strcmp(parts[1], "11211") == 0) {
            // twemproxy sources libmemcached as removing the default port
            // from the string if found.
            snprintf(hashstring, hashstring_size, "%s-%d", parts[0], k);
        } else {
            snprintf(hashstring, hashstring_size, "%s:%s-%d", parts[0], parts[1], k);
        }

        // - md5() hash it
        // mostly from ketama.c
        ketama_md5_digest(hashstring, digest);

        /* Use successive 4-bytes from hash as numbers
         * for the points on the circle: */
        for(int h = 0; h < 4; h++ )
        {
            kt->continuum[*cont].point = ( digest[3+h*4] << 24 )
                                  | ( digest[2+h*4] << 16 )
                                  | ( digest[1+h*4] <<  8 )
                                  |   digest[h*4];
            kt->continuum[*cont].id = id;
            (*cont)++;
        }

    }

    free(hashstring);
}

static void _add_server_evcache(ketama_t *kt, size_t hashstring_size, const char **parts,
        lua_Integer bucket_size, lua_Integer id, unsigned int *cont) {
    char *hashstring = malloc(hashstring_size);

    for (int k = 0; k < bucket_size / 4; k++) {
        unsigned char digest[16];

        // - create hashing string for ketama
        snprintf(hashstring, hashstring_size, "%s/%s:%s-%d", parts[0], parts[0], parts[1], k);
        // - md5() hash it
        // mostly from ketama.c
        ketama_md5_digest(hashstring, digest);

        /* Use successive 4-bytes from hash as numbers
         * for the points on the circle: */
        for(int h = 0; h < 4; h++ )
        {
            kt->continuum[*cont].point = ( digest[3+h*4] << 24 )
                                  | ( digest[2+h*4] << 16 )
                                  | ( digest[1+h*4] <<  8 )
                                  |   digest[h*4];
            kt->continuum[*cont].id = id;
            (*cont)++;
        }

    }

    free(hashstring);
}

#define PARTS 2
// stack = [pool, option]
static int ketama_new(lua_State *L) {
    lua_Integer bucket_size = DEFAULT_BUCKET_SIZE;
    const char *parts[PARTS];
    size_t partlens[PARTS];
    int makemode = 0;

    // check for UA_TTABLE at 1
    luaL_checktype(L, 1, LUA_TTABLE);
    // get number of servers in pool.
    // NOTE: rawlen skips metatable redirection. if we care; lua_len instead.
    lua_Unsigned total = lua_rawlen(L, 1);

    // check for optional input
    int argc = lua_gettop(L);
    if (argc > 1) {
        luaL_checktype(L, 2, LUA_TTABLE);
        if (lua_getfield(L, 2, "omode") != LUA_TNIL) {
            luaL_checktype(L, -1, LUA_TSTRING);
            const char *mode = lua_tostring(L, -1);
            if (strcmp(mode, "default") == 0) {
                makemode = MODE_DEFAULT;
            } else if (strcmp(mode, "ketama") == 0) {
                makemode = MODE_KETAMA;
            } else if (strcmp(mode, "twemproxy") == 0) {
                makemode = MODE_TWEMPROXY;
            } else if (strcmp(mode, "evcache") == 0) {
                makemode = MODE_EVCACHE;
            } else {
                lua_pushstring(L, "ring_hash: bad omode argument");
                lua_error(L);
            }
        }
        lua_pop(L, 1); // pops the nil or mode

        if (lua_getfield(L, 2, "obuckets") != LUA_TNIL) {
          int success = 0;
          bucket_size = lua_tointegerx(L, -1, &success);
          if (!success || bucket_size < 1) {
              lua_pushstring(L, "ring_hash: option argument must be a positive integer");
              lua_error(L);
          }
        }
        lua_pop(L, 1);
    }

    // newuserdatauv() sized for pool*
    size_t size = sizeof(ketama_t) + sizeof(cpoint) * (total * bucket_size);
    ketama_t *kt = lua_newuserdatauv(L, size, 0);
    // TODO: check *kt.
    kt->total_buckets = bucket_size * total;

    // loop over pool
    unsigned int cont = 0;
    lua_pushnil(L); // start the pool iterator
    while (lua_next(L, 1) != 0) {
        // key is -2, value is -1.
        // value is another table. need to query it to get what we need for
        // the hash.
        // hash string is: hostname/ipaddr:port-repitition
        // TODO: bother doing error checking?
        lua_getfield(L, -1, "id");
        lua_Integer id = lua_tointeger(L, -1);
        lua_pop(L, 1);

        // FIXME: we need to do the lua_pop after string assembly to be safe.
        lua_getfield(L, -1, "addr");
        parts[0] = lua_tolstring(L, -1, &partlens[0]);
        lua_pop(L, 1);
        lua_getfield(L, -1, "port");
        parts[1] = lua_tolstring(L, -1, &partlens[1]);
        lua_pop(L, 1);

        size_t hashstring_size = 0;
        for (int x = 0; x < PARTS; x++) {
            hashstring_size += partlens[x];
        }

        // We have up to 3 delimiters in the final hashstring and an index
        // 16 bytes is plenty to accomodate this requirement.
        hashstring_size += 16;

        switch (makemode) {
            case MODE_DEFAULT:
                _add_server_default(kt, hashstring_size, parts, bucket_size, id, &cont);
                break;
            case MODE_KETAMA:
                _add_server_ketama(kt, hashstring_size, parts, bucket_size, id, &cont);
                break;
            case MODE_TWEMPROXY:
                _add_server_twemproxy(kt, hashstring_size, parts, bucket_size, id, &cont);
                break;
            case MODE_EVCACHE:
                // EVCache uses the ipaddress couple of times, we need to factor that in
                // when calculating the hashstring_size
                hashstring_size += partlens[0];
                _add_server_evcache(kt, hashstring_size, parts, bucket_size, id, &cont);
                break;
        }

        lua_pop(L, 1); // remove value, leave key for next iteration.
    }

    // - qsort the points
    qsort( &kt->continuum, cont, sizeof(cpoint), ketama_compare);

    // set the hash/fetch function and the context ptr.
    kt->phc.ctx = kt;
    kt->phc.selector_func = ketama_get_server;

    // - add a pushlightuserdata for the sub-struct with func/ctx.
    lua_pushlightuserdata(L, &kt->phc);
    // - return [UD, lightuserdata]
    return 2;
}

int mcplib_open_dist_ring_hash(lua_State *L) {
    const struct luaL_Reg ketama_f[] = {
        {"new", ketama_new},
        {NULL, NULL},
    };

    luaL_newlib(L, ketama_f);
    lua_pushlightuserdata(L, &ketama_key_hash);
    lua_setfield(L, -2, "hash");

    return 1;
}
