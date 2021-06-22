/* crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013, 2015 Mark Adler
 * Version 1.3  31 Dec 2015  Mark Adler
 */

/*
  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the author be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Mark Adler
  madler@alumni.caltech.edu
 */

/* Use hardware CRC instruction on Intel SSE 4.2 processors.  This computes a
   CRC-32C, *not* the CRC-32 used by Ethernet and zip, gzip, etc.  A software
   version is provided as a fall-back, as well as for speed comparisons. */

/* Version history:
   1.0  10 Feb 2013  First version
   1.1   1 Aug 2013  Correct comments on why three crc instructions in parallel
   1.2   1 Nov 2015  Add const qualifier to avoid compiler warning
                     Load entire input into memory (test code)
                     Argument gives number of times to repeat (test code)
                     Argument < 0 forces software implementation (test code)
   1.3  31 Dec 2015  Check for Intel architecture using compiler macro
                     Support big-endian processors in software calculation
                     Add header for external use
 */

#include <pthread.h>
#include "crc32c.h"

crc_func crc32c;

/* CRC-32C (iSCSI) polynomial in reversed bit order. */
#define POLY 0x82f63b78

uint32_t crc32c_sw_little(uint32_t crc, void const *buf, size_t len);
uint32_t crc32c_sw_big(uint32_t crc, void const *buf, size_t len);
#ifdef __x86_64__

/* Hardware CRC-32C for Intel and compatible processors. */

/* Multiply a matrix times a vector over the Galois field of two elements,
   GF(2).  Each element is a bit in an unsigned integer.  mat must have at
   least as many entries as the power of two for most significant one bit in
   vec. */
static inline uint32_t gf2_matrix_times(uint32_t *mat, uint32_t vec) {
    uint32_t sum = 0;
    while (vec) {
        if (vec & 1)
            sum ^= *mat;
        vec >>= 1;
        mat++;
    }
    return sum;
}

/* Multiply a matrix by itself over GF(2).  Both mat and square must have 32
   rows. */
static inline void gf2_matrix_square(uint32_t *square, uint32_t *mat) {
    for (unsigned n = 0; n < 32; n++)
        square[n] = gf2_matrix_times(mat, mat[n]);
}

/* Construct an operator to apply len zeros to a crc.  len must be a power of
   two.  If len is not a power of two, then the result is the same as for the
   largest power of two less than len.  The result for len == 0 is the same as
   for len == 1.  A version of this routine could be easily written for any
   len, but that is not needed for this application. */
static void crc32c_zeros_op(uint32_t *even, size_t len) {
    uint32_t odd[32];       /* odd-power-of-two zeros operator */

    /* put operator for one zero bit in odd */
    odd[0] = POLY;              /* CRC-32C polynomial */
    uint32_t row = 1;
    for (unsigned n = 1; n < 32; n++) {
        odd[n] = row;
        row <<= 1;
    }

    /* put operator for two zero bits in even */
    gf2_matrix_square(even, odd);

    /* put operator for four zero bits in odd */
    gf2_matrix_square(odd, even);

    /* first square will put the operator for one zero byte (eight zero bits),
       in even -- next square puts operator for two zero bytes in odd, and so
       on, until len has been rotated down to zero */
    do {
        gf2_matrix_square(even, odd);
        len >>= 1;
        if (len == 0)
            return;
        gf2_matrix_square(odd, even);
        len >>= 1;
    } while (len);

    /* answer ended up in odd -- copy to even */
    for (unsigned n = 0; n < 32; n++)
        even[n] = odd[n];
}

/* Take a length and build four lookup tables for applying the zeros operator
   for that length, byte-by-byte on the operand. */
static void crc32c_zeros(uint32_t zeros[][256], size_t len) {
    uint32_t op[32];

    crc32c_zeros_op(op, len);
    for (unsigned n = 0; n < 256; n++) {
        zeros[0][n] = gf2_matrix_times(op, n);
        zeros[1][n] = gf2_matrix_times(op, n << 8);
        zeros[2][n] = gf2_matrix_times(op, n << 16);
        zeros[3][n] = gf2_matrix_times(op, n << 24);
    }
}

/* Apply the zeros operator table to crc. */
static inline uint32_t crc32c_shift(uint32_t zeros[][256], uint32_t crc) {
    return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
           zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/* Block sizes for three-way parallel crc computation.  LONG and SHORT must
   both be powers of two.  The associated string constants must be set
   accordingly, for use in constructing the assembler instructions. */
#define LONG 8192
#define LONGx1 "8192"
#define LONGx2 "16384"
#define SHORT 256
#define SHORTx1 "256"
#define SHORTx2 "512"

/* Tables for hardware crc that shift a crc by LONG and SHORT zeros. */
static pthread_once_t crc32c_once_hw = PTHREAD_ONCE_INIT;
static uint32_t crc32c_long[4][256];
static uint32_t crc32c_short[4][256];

/* Initialize tables for shifting crcs. */
static void crc32c_init_hw(void) {
    crc32c_zeros(crc32c_long, LONG);
    crc32c_zeros(crc32c_short, SHORT);
}

/* Compute CRC-32C using the Intel hardware instruction. */
static uint32_t crc32c_hw(uint32_t crc, void const *buf, size_t len) {
    /* populate shift tables the first time through */
    pthread_once(&crc32c_once_hw, crc32c_init_hw);

    /* pre-process the crc */
    crc = ~crc;
    uint64_t crc0 = crc;            /* 64-bits for crc32q instruction */

    /* compute the crc for up to seven leading bytes to bring the data pointer
       to an eight-byte boundary */
    unsigned char const *next = buf;
    while (len && ((uintptr_t)next & 7) != 0) {
        __asm__("crc32b\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next++;
        len--;
    }

    /* compute the crc on sets of LONG*3 bytes, executing three independent crc
       instructions, each on LONG bytes -- this is optimized for the Nehalem,
       Westmere, Sandy Bridge, and Ivy Bridge architectures, which have a
       throughput of one crc per cycle, but a latency of three cycles */
    while (len >= LONG*3) {
        uint64_t crc1 = 0;
        uint64_t crc2 = 0;
        unsigned char const * const end = next + LONG;
        do {
            __asm__("crc32q\t" "(%3), %0\n\t"
                    "crc32q\t" LONGx1 "(%3), %1\n\t"
                    "crc32q\t" LONGx2 "(%3), %2"
                    : "=r"(crc0), "=r"(crc1), "=r"(crc2)
                    : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
            next += 8;
        } while (next < end);
        crc0 = crc32c_shift(crc32c_long, crc0) ^ crc1;
        crc0 = crc32c_shift(crc32c_long, crc0) ^ crc2;
        next += LONG*2;
        len -= LONG*3;
    }

    /* do the same thing, but now on SHORT*3 blocks for the remaining data less
       than a LONG*3 block */
    while (len >= SHORT*3) {
        uint64_t crc1 = 0;
        uint64_t crc2 = 0;
        unsigned char const * const end = next + SHORT;
        do {
            __asm__("crc32q\t" "(%3), %0\n\t"
                    "crc32q\t" SHORTx1 "(%3), %1\n\t"
                    "crc32q\t" SHORTx2 "(%3), %2"
                    : "=r"(crc0), "=r"(crc1), "=r"(crc2)
                    : "r"(next), "0"(crc0), "1"(crc1), "2"(crc2));
            next += 8;
        } while (next < end);
        crc0 = crc32c_shift(crc32c_short, crc0) ^ crc1;
        crc0 = crc32c_shift(crc32c_short, crc0) ^ crc2;
        next += SHORT*2;
        len -= SHORT*3;
    }

    /* compute the crc on the remaining eight-byte units less than a SHORT*3
       block */
    {
        unsigned char const * const end = next + (len - (len & 7));
        while (next < end) {
            __asm__("crc32q\t" "(%1), %0"
                    : "=r"(crc0)
                    : "r"(next), "0"(crc0));
            next += 8;
        }
        len &= 7;
    }

    /* compute the crc for up to seven trailing bytes */
    while (len) {
        __asm__("crc32b\t" "(%1), %0"
                : "=r"(crc0)
                : "r"(next), "0"(crc0));
        next++;
        len--;
    }

    /* return a post-processed crc */
    return ~crc0;
}

/* Check for SSE 4.2.  SSE 4.2 was first supported in Nehalem processors
   introduced in November, 2008.  This does not check for the existence of the
   cpuid instruction itself, which was introduced on the 486SL in 1992, so this
   will fail on earlier x86 processors.  cpuid works on all Pentium and later
   processors. */
#define SSE42(have) \
    do { \
        uint32_t eax, ecx; \
        eax = 1; \
        __asm__("cpuid" \
                : "=c"(ecx) \
                : "a"(eax) \
                : "%ebx", "%edx"); \
        (have) = (ecx >> 20) & 1; \
    } while (0)

/* Compute a CRC-32C.  If the crc32 instruction is available, use the hardware
   version.  Otherwise, use the software version. */
void crc32c_init(void) {
    int sse42;

    SSE42(sse42);
    if (sse42) {
        crc32c = crc32c_hw;
    } else {
        crc32c = crc32c_sw;
    }
}

#elif defined(__aarch64__) && (defined(__linux__) || defined(__APPLE__))
#if defined(__linux__)
#include <sys/auxv.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#endif

#if defined(HWCAP_CRC32)
static inline uint32_t crc32cx(uint32_t crc, const uint64_t data)
{
        asm(".arch_extension crc\n"
        "crc32cx %w0, %w0, %x1" : "+r" (crc) : "r" (data));
        return crc;
}

static inline uint32_t crc32cb(uint32_t crc, const uint8_t data)
{
        asm(".arch_extension crc\n"
            "crc32cb %w0, %w0, %w1" : "+r" (crc) : "r" (data));
        return crc;
}

static uint32_t crc32c_hw(uint32_t crc, void const *buf, size_t len) {
    crc = ~crc;
    unsigned char const *next = buf;

    while (((uintptr_t)next & 7) && len > 0) {
        crc = crc32cb(crc, *(uint8_t *)next);
        next++;
        len--;
    }

    while (len >= 64) {
        uint64_t *next8 = (uint64_t *)next;
        crc = crc32cx(crc, next8[0]);
        crc = crc32cx(crc, next8[1]);
        crc = crc32cx(crc, next8[2]);
        crc = crc32cx(crc, next8[3]);
        crc = crc32cx(crc, next8[4]);
        crc = crc32cx(crc, next8[5]);
        crc = crc32cx(crc, next8[6]);
        crc = crc32cx(crc, next8[7]);
        next += 64;
        len -= 64;
    }

    while (len >= 8) {
        crc = crc32cx(crc, *(uint64_t *)next);
        next += 8;
        len -= 8;
    }

    while (len > 0) {
        crc = crc32cb(crc, *(uint8_t *)next);
        next++;
        len--;
    }

    return ~crc;
}

void crc32c_init(void) {
#if defined(__linux__)
    uint64_t auxv = getauxval(AT_HWCAP);

    crc32c = crc32c_sw;
    if (auxv & HWCAP_CRC32)
        crc32c = crc32c_hw;
#elif defined(__APPLE__)
    int armv8_crc32;
    size_t size = sizeof(armv8_crc32);

    if (sysctlbyname("hw.optional.armv8_crc32", &armv8_crc32, &size, NULL, 0) == 0 &&
       armv8_crc32 == 1)
        crc32c = crc32c_hw;
#endif
}
#else /* no hw crc32 on arm64 system supported? old compiler/libc/kernel? */
void crc32c_init(void) {
    crc32c = crc32c_sw;
}
#endif
#else /* !__x86_64__i && !__aarch64__ */
void crc32c_init(void) {
    crc32c = crc32c_sw;
}

#endif

/* Construct table for software CRC-32C little-endian calculation. */
static pthread_once_t crc32c_once_little = PTHREAD_ONCE_INIT;
static uint32_t crc32c_table_little[8][256];
static void crc32c_init_sw_little(void) {
    for (unsigned n = 0; n < 256; n++) {
        uint32_t crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32c_table_little[0][n] = crc;
    }
    for (unsigned n = 0; n < 256; n++) {
        uint32_t crc = crc32c_table_little[0][n];
        for (unsigned k = 1; k < 8; k++) {
            crc = crc32c_table_little[0][crc & 0xff] ^ (crc >> 8);
            crc32c_table_little[k][n] = crc;
        }
    }
}

/* Compute a CRC-32C in software assuming a little-endian architecture,
   constructing the required table if that hasn't already been done. */
uint32_t crc32c_sw_little(uint32_t crc, void const *buf, size_t len) {
    unsigned char const *next = buf;

    pthread_once(&crc32c_once_little, crc32c_init_sw_little);
    crc = ~crc;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32c_table_little[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    if (len >= 8) {
        uint64_t crcw = crc;
        do {
            crcw ^= *(uint64_t const *)next;
            crcw = crc32c_table_little[7][crcw & 0xff] ^
                   crc32c_table_little[6][(crcw >> 8) & 0xff] ^
                   crc32c_table_little[5][(crcw >> 16) & 0xff] ^
                   crc32c_table_little[4][(crcw >> 24) & 0xff] ^
                   crc32c_table_little[3][(crcw >> 32) & 0xff] ^
                   crc32c_table_little[2][(crcw >> 40) & 0xff] ^
                   crc32c_table_little[1][(crcw >> 48) & 0xff] ^
                   crc32c_table_little[0][crcw >> 56];
            next += 8;
            len -= 8;
        } while (len >= 8);
        crc = crcw;
    }
    while (len) {
        crc = crc32c_table_little[0][(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return ~crc;
}

/* Swap the bytes in a uint64_t.  (Only for big-endian.) */
#if defined(__has_builtin) || (defined(__GNUC__) && \
    (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)))
#  define swap __builtin_bswap64
#else
static inline uint64_t swap(uint64_t x) {
    x = ((x << 8) & 0xff00ff00ff00ff00) | ((x >> 8) & 0xff00ff00ff00ff);
    x = ((x << 16) & 0xffff0000ffff0000) | ((x >> 16) & 0xffff0000ffff);
    return (x << 32) | (x >> 32);
}
#endif

/* Construct tables for software CRC-32C big-endian calculation. */
static pthread_once_t crc32c_once_big = PTHREAD_ONCE_INIT;
static uint32_t crc32c_table_big_byte[256];
static uint64_t crc32c_table_big[8][256];
static void crc32c_init_sw_big(void) {
    for (unsigned n = 0; n < 256; n++) {
        uint32_t crc = n;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
        crc32c_table_big_byte[n] = crc;
    }
    for (unsigned n = 0; n < 256; n++) {
        uint32_t crc = crc32c_table_big_byte[n];
        crc32c_table_big[0][n] = swap(crc);
        for (unsigned k = 1; k < 8; k++) {
            crc = crc32c_table_big_byte[crc & 0xff] ^ (crc >> 8);
            crc32c_table_big[k][n] = swap(crc);
        }
    }
}

/* Compute a CRC-32C in software assuming a big-endian architecture,
   constructing the required tables if that hasn't already been done. */
uint32_t crc32c_sw_big(uint32_t crc, void const *buf, size_t len) {
    unsigned char const *next = buf;

    pthread_once(&crc32c_once_big, crc32c_init_sw_big);
    crc = ~crc;
    while (len && ((uintptr_t)next & 7) != 0) {
        crc = crc32c_table_big_byte[(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    if (len >= 8) {
        uint64_t crcw = swap(crc);
        do {
            crcw ^= *(uint64_t const *)next;
            crcw = crc32c_table_big[0][crcw & 0xff] ^
                   crc32c_table_big[1][(crcw >> 8) & 0xff] ^
                   crc32c_table_big[2][(crcw >> 16) & 0xff] ^
                   crc32c_table_big[3][(crcw >> 24) & 0xff] ^
                   crc32c_table_big[4][(crcw >> 32) & 0xff] ^
                   crc32c_table_big[5][(crcw >> 40) & 0xff] ^
                   crc32c_table_big[6][(crcw >> 48) & 0xff] ^
                   crc32c_table_big[7][(crcw >> 56)];
            next += 8;
            len -= 8;
        } while (len >= 8);
        crc = swap(crcw);
    }
    while (len) {
        crc = crc32c_table_big_byte[(crc ^ *next++) & 0xff] ^ (crc >> 8);
        len--;
    }
    return ~crc;
}

/* Table-driven software CRC-32C.  This is about 15 times slower than using the
   hardware instructions.  Determine the endianess of the processor and proceed
   accordingly.  Ideally the endianess will be determined at compile time, in
   which case the unused functions and tables for the other endianess will be
   removed by the optimizer.  If not, then the proper routines and tables will
   be used, even if the endianess is changed mid-stream.  (Yes, there are
   processors that permit that -- go figure.) */
uint32_t crc32c_sw(uint32_t crc, void const *buf, size_t len) {
    static int const little = 1;
    if (*(char const *)&little)
        return crc32c_sw_little(crc, buf, len);
    else
        return crc32c_sw_big(crc, buf, len);
}
