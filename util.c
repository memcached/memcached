#include <stdlib.h>
#include <assert.h>

#include "memcached.h"

bool safe_strtoull(const char *str, unsigned long long *out) {
  assert(out != NULL);
  *out = 0;
  char *endptr;
  unsigned long long ull = strtoull(str, &endptr, 10);
  if (*endptr == '\0' && endptr != str) {
    *out = ull;
    return true;
  }
  return false;
}
