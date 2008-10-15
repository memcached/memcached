/*
 * str   a NULL-terminated base decimal 10 unsigned integer
 * out   out parameter, if conversion succeeded
 *
 * returns true if conversion succeeded.
 */
bool safe_strtoull(const char *str, unsigned long long *out);

