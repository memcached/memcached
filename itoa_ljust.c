//=== itoa_ljust.cpp - Fast integer to ascii conversion           --*- C++ -*-//
//
// Substantially simplified (and slightly faster) version
// based on the following functions in Google's protocol buffers:
//
//    FastInt32ToBufferLeft()
//    FastUInt32ToBufferLeft()
//    FastInt64ToBufferLeft()
//    FastUInt64ToBufferLeft()
//
// Differences:
//    1) Greatly simplified
//    2) Avoids GOTO statements - uses "switch" instead and relies on
//       compiler constant folding and propagation for high performance
//    3) Avoids unary minus of signed types - undefined behavior if value
//       is INT_MIN in platforms using two's complement representation
//    4) Uses memcpy to store 2 digits at a time - lets the compiler
//       generate a 2-byte load/store in platforms that support
//       unaligned access, this is faster (and less code) than explicitly
//       loading and storing each byte
//
// Copyright (c) 2016 Arturo Martin-de-Nicolas
// arturomdn@gmail.com
// https://github.com/amdn/itoa_ljust/
//
// Released under the BSD 3-Clause License, see Google's original copyright
// and license below.
//===----------------------------------------------------------------------===//

// Protocol Buffers - Google's data interchange format
// Copyright 2008 Google Inc.  All rights reserved.
// https://developers.google.com/protocol-buffers/
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//===----------------------------------------------------------------------===//

#include "itoa_ljust.h"
#include <string.h>

static const char lut[201] =
    "0001020304050607080910111213141516171819"
    "2021222324252627282930313233343536373839"
    "4041424344454647484950515253545556575859"
    "6061626364656667686970717273747576777879"
    "8081828384858687888990919293949596979899";

#define dd(u) ((const uint16_t)(lut[u]))

static inline char* out2(const int d, char* p) {
    memcpy(p, &((uint16_t *)lut)[d], 2);
    return p + 2;
}

static inline char* out1(const char in, char* p) {
    memcpy(p, &in, 1);
    return p + 1;
}

static inline int digits( uint32_t u, unsigned k, int* d, char** p, int n ) {
    if (u < k*10) {
        *d = u / k;
        *p = out1('0'+*d, *p);
        --n;
    }
    return n;
}

static inline char* itoa(uint32_t u, char* p, int d, int n) {
    switch(n) {
    case 10: d  = u / 100000000; p = out2( d, p );
    case  9: u -= d * 100000000;
    case  8: d  = u /   1000000; p = out2( d, p );
    case  7: u -= d *   1000000;
    case  6: d  = u /     10000; p = out2( d, p );
    case  5: u -= d *     10000;
    case  4: d  = u /       100; p = out2( d, p );
    case  3: u -= d *       100;
    case  2: d  = u /         1; p = out2( d, p );
    case  1: ;
    }
    *p = '\0';
    return p;
}

char* itoa_u32(uint32_t u, char* p) {
    int d = 0,n;
         if (u >=100000000) n = digits(u, 100000000, &d, &p, 10);
    else if (u <       100) n = digits(u,         1, &d, &p,  2);
    else if (u <     10000) n = digits(u,       100, &d, &p,  4);
    else if (u <   1000000) n = digits(u,     10000, &d, &p,  6);
    else                    n = digits(u,   1000000, &d, &p,  8);
    return itoa( u, p, d, n );
}

char* itoa_32(int32_t i, char* p) {
    uint32_t u = i;
    if (i < 0) {
        *p++ = '-';
        u = -u;
    }
    return itoa_u32(u, p);
}

char* itoa_u64(uint64_t u, char* p) {
    int d;

    uint32_t lower = (uint32_t)u;
    if (lower == u) return itoa_u32(lower, p);

    uint64_t upper = u / 1000000000;
    p = itoa_u64(upper, p);
    lower = u - (upper * 1000000000);
    d = lower / 100000000;
    p = out1('0'+d,p);
    return itoa( lower, p, d, 9 );
}

char* itoa_64(int64_t i, char* p) {
    uint64_t u = i;
    if (i < 0) {
        *p++ = '-';
        u = -u;
    }
    return itoa_u64(u, p);
}
