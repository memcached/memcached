#ifndef CRC32C_H
#define    CRC32C_H

typedef uint32_t (*crc_func)(uint32_t crc, const void *buf, size_t len);
crc_func crc32c;

void crc32c_init(void);

#endif    /* CRC32C_H */
