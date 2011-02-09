/**
 * \private
 */
struct genhash_entry_t {
    /** The key for this entry */
    void *key;
    /** Size of the key */
    size_t nkey;
    /** The value for this entry */
    void *value;
    /** Size of the value */
    size_t nvalue;
    /** Pointer to the next entry */
    struct genhash_entry_t *next;
};

struct _genhash {
    size_t size;
    struct hash_ops ops;
    struct genhash_entry_t *buckets[];
};
