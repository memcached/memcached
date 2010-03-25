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

int fcntl(SOCKET s, int cmd, int val)
{
    u_long imode = 1;
    switch(cmd) {
        case F_SETFL:
            switch(val) {
                case O_NONBLOCK:
                    imode = 1;
                    if(ioctlsocket(s, FIONBIO, &imode) == SOCKET_ERROR)
                        return -1;
                    break;
                case O_BLOCK:
                    imode = 0;
                    if(ioctlsocket(s, FIONBIO, &imode) == SOCKET_ERROR)
                        return -1;
                    break;
                default:
                    return -1;
            }
        case F_GETFL:
            return 0;
        default:
            return -1;
    }
}

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

int createLocalListSock(struct sockaddr_in *serv_addr) {
    SOCKET sockfd;
    int slen;

    if ((sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == INVALID_SOCKET) {
        fprintf(stderr,"socket call for local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr->sin_port = htons(0);
    if (bind(sockfd,(struct sockaddr *)serv_addr,sizeof(*serv_addr)) != 0) {
        fprintf(stderr,"bind of local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    slen = sizeof(*serv_addr);
    if (getsockname(sockfd,(struct sockaddr *)serv_addr,&slen) != 0) {
        fprintf(stderr,"getsockname on local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    if (listen(sockfd,5) == SOCKET_ERROR) {
        fprintf(stderr,"listen on local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    return((int)sockfd);
}

int createLocalSocketPair(int listSock, int *fds, struct sockaddr_in *serv_addr) {
    struct sockaddr_in cli_addr;
    fd_set myset;
    struct timeval tv;
    socklen_t lon;
    int valopt, tmpVal;

    if ((fds[0] = (int)socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == INVALID_SOCKET) {
        fprintf(stderr,"socket call for local client socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    if (fcntl(fds[0],F_SETFL,O_NONBLOCK) < 0) {
        fprintf(stderr,"fcntl call for local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    if (connect(fds[0],(struct sockaddr *)serv_addr,sizeof(*serv_addr)) == SOCKET_ERROR) {
        tmpVal = WSAGetLastError();
        if (tmpVal != WSAEWOULDBLOCK) {
            fprintf(stderr,"connect call for local server socket failed. Error Number %d.\n",tmpVal);
            fflush(stderr);
            return(-1);
        }
    }
    else {
        fprintf(stderr,"connect call for non-blocking local client socket unexpectedly succeeds.\n");
        fflush(stderr);
        return(-1);
    }
    Sleep(10);
    tmpVal = sizeof(cli_addr);
    if ((fds[1] = (int)accept(listSock, (struct sockaddr *)&cli_addr, &tmpVal))== INVALID_SOCKET) {
        fprintf(stderr,"accept call for local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    if (fcntl(fds[1],F_SETFL,O_NONBLOCK) < 0) {
        fprintf(stderr,"fcntl call for local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    FD_ZERO(&myset);
    FD_SET(fds[0], &myset);
    tmpVal = select(fds[0] + 1, NULL, &myset, NULL, &tv);
    if (tmpVal == SOCKET_ERROR) {
        fprintf(stderr,"socket call for local server socket failed. Error Number %d.\n",WSAGetLastError());
        fflush(stderr);
        return(-1);
    }
    else if (tmpVal > 0) {
        lon = sizeof(int);
        if (!getsockopt(fds[0], SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon)) {
            if (valopt) {
                fprintf(stderr,"getsockopt indicates error on connect completion.\n");
                return(-1);
            }
        }
        else {
            fprintf(stderr,"getsockopt call for local client socket failed. Error Number %d.\n",WSAGetLastError());
            fflush(stderr);
            return(-1);
        }
    }
    else if (!tmpVal) {
        fprintf(stderr,"select on connect complete timed out.\n");
        fflush(stderr);
        return(-1);
    }
    return(0);
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
