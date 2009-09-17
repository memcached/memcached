#ifndef ASSOC_H
#define ASSOC_H

/* associative array */
ENGINE_ERROR_CODE assoc_init(void);
hash_item *assoc_find(const char *key, const size_t nkey);
int assoc_insert(hash_item *item);
void assoc_delete(const char *key, const size_t nkey);
void do_assoc_move_next_bucket(void);
int start_assoc_maintenance_thread(void);
void stop_assoc_maintenance_thread(void);

#endif
