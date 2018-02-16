/*
 * Copyright (c) <2008>, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the  nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY SUN MICROSYSTEMS, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL SUN MICROSYSTEMS, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
provider memcached {
   /**
    * Fired when a connection object is allocated from the connection pool.
    * @param connid the connection id
    */
   probe conn__allocate(int connid);

   /**
    * Fired when a connection object is released back to the connection pool.
    * @param connid the connection id
    */
   probe conn__release(int connid);

   /**
    * Fired when a new connection object is created (there are no more
    * connection objects in the connection pool).
    * @param ptr pointer to the connection object
    */
   probe conn__create(void *ptr);

   /**
    * Fired when a connection object is destroyed ("released back to
    * the memory subsystem").
    * @param ptr pointer to the connection object
    */
   probe conn__destroy(void *ptr);

   /**
    * Fired when a connection is dispatched from the "main thread" to a
    * worker thread.
    * @param connid the connection id
    * @param threadid the thread id
    */
   probe conn__dispatch(int connid, int threadid);

   /**
    * Allocate memory from the slab allocator.
    * @param size the requested size
    * @param slabclass the allocation will be fulfilled in this class
    * @param slabsize the size of each item in this class
    * @param ptr pointer to allocated memory
    */
   probe slabs__allocate(int size, int slabclass, int slabsize, void* ptr);

   /**
    * Failed to allocate memory (out of memory).
    * @param size the requested size
    * @param slabclass the class that failed to fulfill the request
    */
   probe slabs__allocate__failed(int size, int slabclass);

   /**
    * Fired when a slab class attempts to allocate more space.
    * @param slabclass class that needs more memory
    */
   probe slabs__slabclass__allocate(int slabclass);

   /**
    * Failed to allocate memory (out of memory).
    * @param slabclass the class that failed grab more memory
    */
   probe slabs__slabclass__allocate__failed(int slabclass);

   /**
    * Release memory.
    * @param size the size of the memory
    * @param slabclass the class the memory belongs to
    * @param ptr pointer to the memory to release
    */
   probe slabs__free(int size, int slabclass, void* ptr);

   /**
    * Fired when the when we have searched the hash table for a named key.
    * These two elements provide an insight in how well the hash function
    * functions. Long traversals are a sign of a less optimal function,
    * wasting cpu capacity.
    *
    * @param key the key searched for
    * @param keylen length of the key
    * @param depth the depth in the list of hash table
    */
   probe assoc__find(const char *key, int keylen, int depth);

   /**
    * Fired when a new item has been inserted.
    * @param key the key just inserted
    * @param keylen length of the key
    */
   probe assoc__insert(const char *key, int keylen);

   /**
    * Fired when a new item has been removed.
    * @param key the key just deleted
    * @param keylen length of the key
    */
   probe assoc__delete(const char *key, int keylen);

   /**
    * Fired when an item is linked into the cache.
    * @param key the items key
    * @param keylen length of the key
    * @param size the size of the data
    */
   probe item__link(const char *key, int keylen, int size);

   /**
    * Fired when an item is deleted.
    * @param key the items key
    * @param keylen length of the key
    * @param size the size of the data
    */
   probe item__unlink(const char *key, int keylen, int size);

   /**
    * Fired when the refcount for an item is reduced.
    * @param key the items key
    * @param keylen length of the key
    * @param size the size of the data
    */
   probe item__remove(const char *key, int keylen, int size);

   /**
    * Fired when the "last refenced" time is updated.
    * @param key the items key
    * @param keylen length of the key
    * @param size the size of the data
    */
   probe item__update(const char *key, int keylen, int size);

   /**
    * Fired when an item is replaced with another item.
    * @param oldkey the key of the item to replace
    * @param oldkeylen the length of the old key
    * @param oldsize the size of the old item
    * @param newkey the key of the new item
    * @param newkeylen the length of the new key
    * @param newsize the size of the new item
    */
   probe item__replace(const char *oldkey, int oldkeylen, int oldsize,
                       const char *newkey, int newkeylen, int newsize);

   /**
    * Fired when the processing of a command starts.
    * @param connid the connection id
    * @param request the incoming request
    * @param size the size of the request
    */
   probe process__command__start(int connid, const void *request, int size);

   /**
    * Fired when the processing of a command is done.
    * @param connid the connection id
    * @param response the response to send back to the client
    * @param size the size of the response
    */
   probe process__command__end(int connid, const void *response, int size);

   /**
    * Fired for a get-command
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size size of the key's data (or signed int -1 if not found)
    * @param casid the casid for the item
    */
   probe command__get(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for an add-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size the new size of the key's data (or signed int -1 if
    *             not found)
    * @param casid the casid for the item
    */
   probe command__add(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for a set-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size the new size of the key's data (or signed int -1 if
    *             not found)
    * @param casid the casid for the item
    */
   probe command__set(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for a replace-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size the new size of the key's data (or signed int -1 if
    *             not found)
    * @param casid the casid for the item
    */
   probe command__replace(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for a prepend-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size the new size of the key's data (or signed int -1 if
    *             not found)
    * @param casid the casid for the item
    */
   probe command__prepend(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for an append-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size the new size of the key's data (or signed int -1 if
    *             not found)
    * @param casid the casid for the item
    */
   probe command__append(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for an touch-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size the new size of the key's data (or signed int -1 if
    *             not found)
    * @param casid the casid for the item
    */
   probe command__touch(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for a cas-command.
    * @param connid connection id
    * @param key requested key
    * @param keylen length of the key
    * @param size size of the key's data (or signed int -1 if not found)
    * @param casid the cas id requested
    */
   probe command__cas(int connid, const char *key, int keylen, int size, int64_t casid);

   /**
    * Fired for an incr command.
    * @param connid connection id
    * @param key the requested key
    * @param keylen length of the key
    * @param val the new value
    */
   probe command__incr(int connid, const char *key, int keylen, int64_t val);

   /**
    * Fired for a decr command.
    * @param connid connection id
    * @param key the requested key
    * @param keylen length of the key
    * @param val the new value
    */
   probe command__decr(int connid, const char *key, int keylen, int64_t val);

   /**
    * Fired for a delete command.
    * @param connid connection id
    * @param key the requested key
    * @param keylen length of the key
    */
   probe command__delete(int connid, const char *key, int keylen);

};

#pragma D attributes Unstable/Unstable/Common provider memcached provider
#pragma D attributes Private/Private/Common provider memcached module
#pragma D attributes Private/Private/Common provider memcached function
#pragma D attributes Unstable/Unstable/Common provider memcached name
#pragma D attributes Unstable/Unstable/Common provider memcached args
