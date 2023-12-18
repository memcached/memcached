//
// Created by rigon on 06.11.23.
//

//#include "memcached.h"
//#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>


extern int __VERIFIER_nondet_int();


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
        assert(dst[x] != src[x]);
        return false;
    }
}

//Thomas example for first tests:
//test 1: Does the verifier work on this?
int main() {
    FILE *file = fopen("/home/rigon/Desktop/memcached_github_repo/memcached_bachelor_thesis/input_pjh/inputUtilHarness.txt", "r");

    if (file == NULL) {
        perror("Fehler beim Öffnen der Datei");
        return 0;
    }

    char dst[256]; const char src[256]; size_t dstmax[256];

    fscanf(file, "%s %s %li", dst, src, dstmax);
    fclose(file);

    safe_strcpy(dst, src, dstmax);

    return 0;
}
//test 2: use nondeterministic values for analysis
//extern unsigned int __VERIFIER_nondet_uint();
//extern unsigned char __VERIFIER_nondet_char();
//int main() {
//    unsigned int sizedst = __VERIFIER_nondet_uint();
//    char dst[sizedst];
//    unsigned int sizesrc = __VERIFIER_nondet_uint();
//    char src[sizesrc];
//
//    for(int i = 0; i < sizedst-1; i++) {
//        src[i] = __VERIFIER_nondet_char();
//    }
//    src[sizedst-1] = '\0';
//
//    safe_strcpy(dst, src, sizedst);
//}

//bool safe_strcpy_Marek_Bsp(char *dst, const char *src, const size_t dstmax) {
//    size_t x;
//
//    for (x = 0; x < dstmax - 1 && src[x] != '\0'; x++) {
//        dst[x] = src[x];
//    }
//
//    dst[x] = '\0';
//
//    if (src[x] == '\0') {
//        return true;
//    } else {
//        assert(dst[x] != src[x]);
//        return false;
//    }
//}

