/* Copyright (c) 1983, 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *     This product includes software developed by the University of
 *     California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

#include "win32.h"
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>

/*
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
int inet_aton(register const char *cp, struct in_addr *addr)
{
    register uint32_t val;
    register int base, n;
    register char c;
    u_int parts[4];
    register u_int *pp = parts;

    c = *cp;
    for (;;) {
        /*
         * Collect number up to ``.''.
         * Values are specified as for C:
         * 0x=hex, 0=octal, isdigit=decimal.
         */
        if (!isdigit(c))
            return (0);
        val = 0; base = 10;
        if (c == '0') {
            c = *++cp;
            if (c == 'x' || c == 'X')
                base = 16, c = *++cp;
            else
                base = 8;
        }
        for (;;) {
            if (isascii(c) && isdigit(c)) {
                val = (val * base) + (c - '0');
                c = *++cp;
            } else if (base == 16 && isascii(c) && isxdigit(c)) {
                val = (val << 4) |
                    (c + 10 - (islower(c) ? 'a' : 'A'));
                c = *++cp;
            } else
                break;
        }
        if (c == '.') {
            /*
             * Internet format:
             *    a.b.c.d
             *    a.b.c    (with c treated as 16 bits)
             *    a.b    (with b treated as 24 bits)
             */
            if (pp >= parts + 3)
                return (0);
            *pp++ = val;
            c = *++cp;
        } else
            break;
    }
    /*
     * Check for trailing characters.
     */
    if (c != '\0' && (!isascii(c) || !isspace(c)))
        return (0);
    /*
     * Concoct the address according to
     * the number of parts specified.
     */
    n = pp - parts + 1;
    switch (n) {

    case 0:
        return (0);        /* initial nondigit */

    case 1:                /* a -- 32 bits */
        break;

    case 2:                /* a.b -- 8.24 bits */
        if (val > 0xffffff)
            return (0);
        val |= parts[0] << 24;
        break;

    case 3:                /* a.b.c -- 8.8.16 bits */
        if (val > 0xffff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16);
        break;

    case 4:                /* a.b.c.d -- 8.8.8.8 bits */
        if (val > 0xff)
            return (0);
        val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        break;
    }
    if (addr)
        addr->s_addr = htonl(val);
    return (1);
}

unsigned __int64 strtoull(const char *p,char **pend,int base) {
    unsigned __int64 number = 0;
    int c;
    int error;

    while (('\b' == *p) || ('\t' == *p)) // skip leading white space
        p++;
    if (*p == '+')
        p++;
    switch (base) {
        case 0:
            base = 10; // assume decimal base
            if (*p == '0') {
                base = 8; // could be octal
                p++;
                switch (*p) {
                    case 'x':
                    case 'X':
                        base = 16; // hex
                        p++;
                        break;
#if BINARY
                    case 'b':
                    case 'B':
                        base = 2; // binary
                        p++;
                        break;
#endif
                }
            }
            break;
        case 16: // skip over '0x' and '0X'
            if (*p == '0' && (p[1] == 'x' || p[1] == 'X'))
                p += 2;
            break;
#if BINARY
        case 2: // skip over '0b' and '0B'
            if (*p == '0' && (p[1] == 'b' || p[1] == 'B'))
                p += 2;
            break;
#endif
    }
    error = 0;
    while (1) {
        c = *p;
        if ('0' <= c && c <= '9')
            c -= '0';
        else if ('a' <= c && c <= 'z')
            c -= 'a' - 10;
        else if ('A' <= c && c <= 'Z')
            c -= 'A' - 10;
        else // unrecognized character
            break;
        if (c >= base) // not in number base
            break;
        if ((ULLONG_MAX - c) / base < number)
            error = 1;
        number = number * base + c;
        p++;
    }
    if (pend)
        *pend = (char *)p;
    if (error) {
        number = ULLONG_MAX;
        errno = ERANGE;
    }
    return number;
}

int getrusage(int who, struct rusage * rusage) {
    FILETIME starttime;
    FILETIME exittime;
    FILETIME kerneltime;
    FILETIME usertime;
    ULARGE_INTEGER li;

    if (rusage == (struct rusage *)NULL) {
        errno = EFAULT;
        return -1;
    }
    memset(rusage, 0, sizeof(struct rusage));
    if (GetProcessTimes(GetCurrentProcess(),
                        &starttime, &exittime, &kerneltime,
                        &usertime) == 0) {
        /* Where is dosmaperr declared. Will address later. */
        /* _dosmaperr(GetLastError()); */
        return -1;
    }
    /* Convert FILETIMEs (0.1 us) to struct timeval */
    memcpy(&li, &kerneltime, sizeof(FILETIME));
    li.QuadPart /= 10L; /* Convert to microseconds */
    rusage->ru_stime.tv_sec  = (long)(li.QuadPart / 1000000L);
    rusage->ru_stime.tv_usec = li.QuadPart % 1000000L;
    memcpy(&li, &usertime, sizeof(FILETIME));
    li.QuadPart /= 10L; /* Convert to microseconds */
    rusage->ru_utime.tv_sec  = (long)(li.QuadPart / 1000000L);
    rusage->ru_utime.tv_usec = li.QuadPart % 1000000L;
    return(0);
}

int sleep(int seconds) {
    Sleep(seconds*1000);
    return 0;
}

int kill(int pid, int sig) {
    if (TerminateProcess((HANDLE)pid, 0))
        return 0;
    return -1;
}

int spawn_memcached(int argc, char **argv) {
    char buffer[4096];
    int offset=0;

    for (int ii = 0; ii < argc; ++ii) {
        if (strcmp("-d", argv[ii]) != 0) {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "%s ", argv[ii]);
        }
    }

    STARTUPINFO sinfo = { .cb = sizeof(sinfo) };
    PROCESS_INFORMATION pinfo;

    if (CreateProcess(argv[0], buffer, NULL, NULL, FALSE,
                      CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW,
                      NULL, NULL, &sinfo, &pinfo)) {
        exit(0);
    }

    return -1;
}

extern int sigaction(int sig, struct sigaction *act, struct sigaction *oact)
{
    if (sig == SIGHUP) {
        return 0;
    }

    void (*ret)(int) = signal(sig, act->sa_handler);
    if (oact != NULL) {
        oact->sa_handler = ret;
    }
    if (ret == SIG_ERR) {
        return -1;
    }

    return 0;
}

void initialize_sockets(void)
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0) {
       fprintf(stderr, "Socket Initialization Error. Program aborted\n");
       exit(EXIT_FAILURE);
    }
}
