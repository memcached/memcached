//
// Created by rigon on 06.11.23.
//
#include <stdbool.h>
#include "defs-testcomp.c"

extern char __VERIFIER_nondet_char();
extern size_t __VERIFIER_nondet_size_t();


// slow, safe function for copying null terminated buffers.
// ensures null terminator set on destination buffer. copies at most dstmax-1
// non-null bytes.
// Explicitly avoids over-reading src while looking for the null byte.
// returns true if src was fully copied.
// returns false if src was truncated into dst.
bool safe_strcpy(char *dst, const char *src, const size_t dstmax) {
    size_t x;

    for (x = 0; x < dstmax - 1 && src[x] != '\0'; x++) {
        dst[x] = src[x];
    }

    dst[x] = '\0';

    if (src[x] == '\0') {
        return true;
    } else {
        return false;
    }
}

int main() {
    char *dst = __VERIFIER_nondet_pchar();
    const char *src = __VERIFIER_nondet_pchar();
    size_t dstmax = __VERIFIER_nondet_size_t();

    safe_strcpy(dst, src, dstmax);

    return 0;
}
