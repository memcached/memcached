/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "memcached.h"

static void test_safe_strtoull(void);
static void test_safe_strtoll(void);

static void test_safe_strtoull() {
  uint64_t val;
  assert(safe_strtoull("123", &val));
  assert(val == 123);
  assert(safe_strtoull("+123", &val));
  assert(val == 123);
  assert(!safe_strtoull("", &val));  // empty
  assert(!safe_strtoull("123BOGUS", &val));  // non-numeric
  assert(!safe_strtoull("92837498237498237498029383", &val)); // out of range

  // extremes:
  assert(safe_strtoull("18446744073709551615", &val)); // 2**64 - 1
  assert(val == 18446744073709551615ULL);
  assert(!safe_strtoull("18446744073709551616", &val)); // 2**64
  assert(!safe_strtoull("-1", &val));  // negative
}

static void test_safe_strtoll() {
  int64_t val;
  assert(safe_strtoll("123", &val));
  assert(val == 123);
  assert(safe_strtoll("+123", &val));
  assert(val == 123);
  assert(safe_strtoll("-123", &val));
  assert(val == -123);
  assert(!safe_strtoll("", &val));  // empty
  assert(!safe_strtoll("123BOGUS", &val));  // non-numeric
  assert(!safe_strtoll("92837498237498237498029383", &val)); // out of range

  // extremes:
  assert(!safe_strtoll("18446744073709551615", &val)); // 2**64 - 1
  assert(safe_strtoll("9223372036854775807", &val)); // 2**63 - 1
  assert(val == 9223372036854775807LL);
  /*
  assert(safe_strtoll("-9223372036854775808", &val)); // -2**63
  assert(val == -9223372036854775808LL);
  */
  assert(!safe_strtoll("-9223372036854775809", &val)); // -2**63 - 1

  // We'll allow space to terminate the string.  And leading space.
  assert(safe_strtoll(" 123 foo", &val));
  assert(val == 123);

}

int main(int argc, char **argv) {
  test_safe_strtoull();
  test_safe_strtoll();
  printf("OK.\n");
  return 0;
}
