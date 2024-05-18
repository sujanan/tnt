#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/select.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include "util.h"

typedef int32_t i32;
typedef uint32_t u32;
#define ROTL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/*
 * Implementation of SHA1 algorithm.
 * Mostly copied from https://github.com/CTrabant/teeny-sha1
 */
void sha1(unsigned char *data, size_t len, unsigned char digest[20]) {
    u32 w[80];
    u32 h[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    u32 a, b, c, d, e, f = 0, k = 0;
    i32 wcount;
    u32 idx, lidx, widx, didx = 0, tmp;
    u32 loopcount = (len + 8) / 64 + 1;
    u32 tailbytes = 64 * loopcount - len;
    unsigned char datatail[128] = {0};
    datatail[0] = 0x80;
    datatail[tailbytes-8] = len*8 >> 56 & 0xFF;
    datatail[tailbytes-7] = len*8 >> 48 & 0xFF;
    datatail[tailbytes-6] = len*8 >> 40 & 0xFF;
    datatail[tailbytes-5] = len*8 >> 32 & 0xFF;
    datatail[tailbytes-4] = len*8 >> 24 & 0xFF;
    datatail[tailbytes-3] = len*8 >> 16 & 0xFF;
    datatail[tailbytes-2] = len*8 >> 8  & 0xFF;
    datatail[tailbytes-1] = len*8 >> 0  & 0xFF;
    for (lidx = 0; lidx < loopcount; lidx++) {
        memset (w, 0, 80*sizeof(u32));
        for (widx = 0; widx <= 15; widx++) {
            wcount = 24;
            while (didx < len && wcount >= 0) {
                w[widx] += (((u32)data[didx]) << wcount);
                didx++;
                wcount -= 8;
            }
            while (wcount >= 0) {
                w[widx] += (((u32)datatail[didx - len]) << wcount);
                didx++;
                wcount -= 8;
            }
        }
        for (widx = 16; widx <= 31; widx++)
            w[widx] = ROTL((w[widx-3] ^ w[widx-8] ^ w[widx-14] ^ w[widx-16]), 1);
        for (widx = 32; widx <= 79; widx++)
            w[widx] = ROTL((w[widx-6] ^ w[widx-16] ^ w[widx-28] ^ w[widx-32]), 2);
        a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
        for (idx = 0; idx <= 79; idx++) {
            if (idx <= 19) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (idx >= 20 && idx <= 39) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (idx >= 40 && idx <= 59) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else if (idx >= 60 && idx <= 79) {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            tmp = ROTL(a, 5) + f + e + k + w[idx];
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    for (idx = 0; idx < 5; idx++) {
        digest[idx*4+0] = h[idx] >> 24;
        digest[idx*4+1] = h[idx] >> 16;
        digest[idx*4+2] = h[idx] >> 8;
        digest[idx*4+3] = h[idx];
    }
}

/**
 * Implementation of URL encoding.
 * Make sure dest is at least 3 times larger than src.
 */
void urlencode(char *dest, char *src, int len) {
    char *hex = "0123456789ABCDEF";
    int i = 0, j = 0;

    while (i < len) {
        unsigned char c = src[i++];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            dest[j++] = c;
        } else if (c == ' ') {
            dest[j++] = '+';
        } else {
            /* In this case a single byte in src takes 
             * three bytes from the dest. This is why
             * dest should be at least 3 times larger 
             * than src. */ 
            dest[j++] = '%';
            dest[j++] = hex[c >> 4];
            dest[j++] = hex[c & 0xF];
        }
    }
    dest[j] = 0; /* null-terminated */
}

/**
 * Add an event to the event loop.
 */
int eloopAdd(struct eloop *eloop, int fd, int mask, onevent *onevent, void *data) {
    struct event *e = malloc(sizeof(struct event));
    if (!e) return ERR_SYS;

    e->fd = fd;
    e->mask = mask;
    e->onevent = onevent;
    e->data = data;
    e->next = NULL;
    e->prev = NULL;

    if (eloop->head == NULL && eloop->tail == NULL) {
        eloop->head = e;
        eloop->tail = e;
    } else {
        eloop->tail->next = e;
        e->prev = eloop->tail;
        eloop->tail = e;
    }

    return OK;
}

/**
 * Remove an event from the event loop.
 */
void eloopRemove(struct eloop *eloop, struct event *e) {
    if (e->prev) {
        if (e == eloop->tail)
            eloop->tail = e->prev;
        e->prev->next = e->next;
    }
    if (e->next) {
        if (e == eloop->head)
            eloop->head = e->next;
        e->next->prev = e->prev;
    }
    if (e->prev == NULL && e->next == NULL) {
        eloop->head = NULL;
        eloop->tail = NULL;
    }

    free(e);
}

/**
 * Process events in event loop.
 */
int eloopProcess(struct eloop *eloop) {
    int r;
    /* file descriptor sets to fill with select call */
    fd_set rfds, wfds, efds;

    /* initialize sets */
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    struct event *e = eloop->head;
    int maxfd = 0;
    /* add fd to sets based on the mask */
    while (e) {
        if (e->fd & ELOOP_R) FD_SET(e->fd, &rfds);
        if (e->fd & ELOOP_W) FD_SET(e->fd, &wfds);
        if (e->fd & ELOOP_E) FD_SET(e->fd, &efds);
        /* keep track of maxfd */
        if (e->fd > maxfd) maxfd = e->fd;
        e = e->next;
    }

    r = select(maxfd+1, &rfds, &wfds, &efds, NULL);
    /* error occured */
    if (r == -1) return ERR_SYS;
    /* nothing to process */
    if (r ==  0) return OK;
    /* start from head */
    e = eloop->head;
    while (e) {
        if (e->mask & ELOOP_R && FD_ISSET(e->fd, &rfds) ||
            e->mask & ELOOP_W && FD_ISSET(e->fd, &wfds) ||
            e->mask & ELOOP_E && FD_ISSET(e->fd, &efds))
        {
            /* execute registered callback */
            e->onevent(eloop, e->fd, e->data);

            /* clear sets and remove event */
            FD_CLR(e->fd, &rfds);
            FD_CLR(e->fd, &wfds);
            FD_CLR(e->fd, &efds);
            eloopRemove(eloop, e);

            /* It's probably better to start from the beginning.
             * It prioritizes the events added first */
            e = eloop->head;
        } else {
            e = e->next;
        }     
    }

    return OK;
}

