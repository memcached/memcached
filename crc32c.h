#ifndef CRC32C_H
#define    CRC32C_H


// crc32c.h -- header for crc32c.c
// Copyright (C) 2015 Mark Adler
// See crc32c.c for the license.

#include <stdint.h>

// Return the CRC-32C of buf[0..len-1] given the starting CRC crc.  This can be
// used to calculate the CRC of a sequence of bytes a chunk at a time, using
// the previously returned crc in the next call.  The first call must be with
// crc == 0.  crc32c() uses the Intel crc32 hardware instruction if available.
typedef uint32_t (*crc_func)(uint32_t crc, const void *buf, size_t len);
extern crc_func crc32c;

void crc32c_init(void);

// Expose a prototype for the crc32c software variant simply for testing purposes
uint32_t crc32c_sw(uint32_t crc, void const *buf, size_t len);

#endif    /* CRC32C_H */
