#include "config.h"

/* fast-enough functions for uriencoding strings. */
void uriencode_init(void);
bool uriencode(const char *src, char *dst, const size_t srclen, const size_t dstlen);
char *uriencode_p(const char *src, char *dst, const size_t srclen);

/*
 * Wrappers around strtoull/strtoll that are safer and easier to
 * use.  For tests and assumptions, see internal_tests.c.
 *
 * str   a NULL-terminated base decimal 10 unsigned integer
 * out   out parameter, if conversion succeeded
 *
 * returns true if conversion succeeded.
 */
bool safe_strtoull(const char *str, uint64_t *out);
bool safe_strtoull_hex(const char *str, uint64_t *out);
bool safe_strtoll(const char *str, int64_t *out);
bool safe_strtoul(const char *str, uint32_t *out);
bool safe_strtol(const char *str, int32_t *out);
bool safe_strtod(const char *str, double *out);
bool safe_strcpy(char *dst, const char *src, const size_t dstmax);
bool safe_memcmp(const void *a, const void *b, size_t len);

#ifndef HAVE_HTONLL
extern uint64_t htonll(uint64_t);
extern uint64_t ntohll(uint64_t);
#endif

#ifdef __GCC
# define __gcc_attribute__ __attribute__
#else
# define __gcc_attribute__(x)
#endif

/**
 * Vararg variant of perror that makes for more useful error messages
 * when reporting with parameters.
 *
 * @param fmt a printf format
 */
void vperror(const char *fmt, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

/* Some common timepsec functions.
 */

void mc_timespec_add(struct timespec *ts1, struct timespec *ts2);

#define safe_free(p) if (p) { free(p); p = NULL; }

/* name list functionality */
typedef struct list_str {
    char *str;
    struct list_str *next;
} LIST_STR;

void name_list_append(LIST_STR **ptr, char *str);
void name_list_dup(LIST_STR **dst, LIST_STR *src);
void *name_list_free(LIST_STR *ptr);
void name_list_append_option(LIST_STR **ptr, char *str);
char *name_list_to_string(LIST_STR *ptr, char *separator);
