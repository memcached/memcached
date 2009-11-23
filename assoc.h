#ifndef ASSOC_H
#define ASSOC_H

/* associative array */
ENGINE_ERROR_CODE assoc_init(void);
hash_item *assoc_find(uint32_t hash, const char *key, const size_t nkey);
int assoc_insert(uint32_t hash, hash_item *item);
void assoc_delete(uint32_t hash, const char *key, const size_t nkey);
int start_assoc_maintenance_thread(struct default_engine *engine);
void stop_assoc_maintenance_thread(struct default_engine *engine);

#endif
