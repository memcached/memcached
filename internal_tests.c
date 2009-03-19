/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "memcached.h"

static void test_safe_strtoull(void);
static void test_safe_strtoul(void);
static void test_safe_strtoll(void);
static void test_safe_strtol(void);

static void test_safe_strtoul() {
  uint32_t val;
  assert(safe_strtoul("123", &val));
  assert(val == 123);
  assert(safe_strtoul("+123", &val));
  assert(val == 123);
  assert(!safe_strtoul("", &val));  // empty
  assert(!safe_strtoul("123BOGUS", &val));  // non-numeric
  /* Not sure what it does, but this works with ICC :/
  assert(!safe_strtoul("92837498237498237498029383", &val)); // out of range
  */

  // extremes:
  assert(safe_strtoul("4294967295", &val)); // 2**32 - 1
  assert(val == 4294967295L);
  /* This actually works on 64-bit ubuntu
  assert(!safe_strtoul("4294967296", &val)); // 2**32
  */
  assert(!safe_strtoul("-1", &val));  // negative
}


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

static void test_safe_strtol() {
  int32_t val;
  assert(safe_strtol("123", &val));
  assert(val == 123);
  assert(safe_strtol("+123", &val));
  assert(val == 123);
  assert(safe_strtol("-123", &val));
  assert(val == -123);
  assert(!safe_strtol("", &val));  // empty
  assert(!safe_strtol("123BOGUS", &val));  // non-numeric
  assert(!safe_strtol("92837498237498237498029383", &val)); // out of range

  // extremes:
  /* This actually works on 64-bit ubuntu
  assert(!safe_strtol("2147483648", &val)); // (expt 2.0 31.0)
  */
  assert(safe_strtol("2147483647", &val)); // (- (expt 2.0 31) 1)
  assert(val == 2147483647L);
  /* This actually works on 64-bit ubuntu
  assert(!safe_strtol("-2147483649", &val)); // (- (expt -2.0 31) 1)
  */

  // We'll allow space to terminate the string.  And leading space.
  assert(safe_strtol(" 123 foo", &val));
  assert(val == 123);
}

int main(int argc, char **argv) {
  test_safe_strtoull();
  test_safe_strtoll();
  test_safe_strtoul();
  test_safe_strtol();
  printf("OK.\n");
  return 0;
}
