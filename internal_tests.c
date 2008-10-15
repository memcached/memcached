/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "memcached.h"

int main(int argc, char **argv) {
  unsigned long long ull;
  assert(safe_strtoull("123", &ull));
  assert(ull == 123);

  // Empty:
  assert(!safe_strtoull("", &ull));

  // Bogus:
  assert(!safe_strtoull("123BOGUS", &ull));

  printf("OK.\n");
  return 0;
}
