#ifndef ASSOC_H
#define ASSOC_H

struct assoc {
   /* how many powers of 2's worth of buckets we use */
   unsigned int hashpower;


   /* Main hash table. This is where we look except during expansion. */
   hash_item** primary_hashtable;

   /*
    * Previous hash table. During expansion, we look here for keys that haven't
    * been moved over to the primary yet.
    */
   hash_item** old_hashtable;

   /* Number of items in the hash table. */
   unsigned int hash_items;

   /* Flag: Are we in the middle of expanding now? */
   bool expanding;

   /*
    * During expansion we migrate values with bucket granularity; this is how
    * far we've gotten so far. Ranges from 0 .. hashsize(hashpower - 1) - 1.
    */
   unsigned int expand_bucket;
};

/* associative array */
ENGINE_ERROR_CODE assoc_init(struct default_engine *engine);
hash_item *assoc_find(struct default_engine *engine, uint32_t hash,
                      const char *key, const size_t nkey);
int assoc_insert(struct default_engine *engine, uint32_t hash,
                 hash_item *item);
void assoc_delete(struct default_engine *engine, uint32_t hash,
                  const char *key, const size_t nkey);
int start_assoc_maintenance_thread(struct default_engine *engine);
void stop_assoc_maintenance_thread(struct default_engine *engine);

#endif
