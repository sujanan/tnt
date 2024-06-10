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
#include <errno.h>
#include <assert.h>
#include "util.h"

/**
 * Logging function
 */
static void tntLogVa(int lvl, const char *fmt, va_list ap) {
    if (lvl < LL) return;

    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    const char *s[] = {"DEBUG", "INFO", "ERROR"};
    FILE *f = lvl == LOG_ERROR ? stderr : stdout;
    fprintf(f, "%5s %s\n", s[lvl], msg);
}

static void tntLog(int lvl, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    tntLogVa(lvl, fmt, ap);
    va_end(ap);
}

/**
 * Log erorrs
 */
void logError(int err, const char *fmt, ...) {
    assert(err < sizeof(tnterrors)/sizeof(tnterrors[0]) && err > 0);

    va_list ap;
    char msg[1024];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    const char *errstr;
    errstr = tnterrors[err];
    if (err == ERR_SYS && errno) 
        errstr = strerror(errno);

    tntLog(LOG_ERROR, "%s: %s", msg, errstr);
}

/**
 * Log info 
 */
void logInfo(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    tntLogVa(LOG_INFO, fmt, ap);
    va_end(ap);
}

/**
 * Log debug 
 */
void logDebug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    tntLogVa(LOG_DEBUG, fmt, ap);
    va_end(ap);
}

/**
 * An implementation of FreeBsd strnstr.
 */
char *strstr_n(char *haystack, const char *needle, size_t n) {
    size_t nlen = strlen(needle);
    if (nlen == 0)
        return haystack;

    char *s = haystack;
    char *e = haystack + n - nlen - 1; 
    for (; s < e; s++) {
        if (!strncmp(s, needle, nlen))
            return s;
    }
    return NULL;
}

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
void urlencode(char *dest, unsigned char *src, int len) {
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
 * Returns the size of a given file
 */
int findFileSize(int *size, FILE *f) {
    /* get current file location */
    int prev = ftell(f);
    if (prev == -1) return ERR_SYS;
    /* seek to end */
    fseek(f, 0L, SEEK_END);
    /* get size */
    *size = ftell(f);
    if (*size == -1) return ERR_SYS;
    /* set back to previous location */
    fseek(f, prev, SEEK_SET);
    return OK;
}

/**
 * Reads the entire file to the given buffer.
 * Make sure buffer has enough space.
 */
int readFile(unsigned char *buf, int bufcap, FILE *f) {
    int r = fread(buf, 1, bufcap, f);
    /* error occured after reading the file */
    if (ferror(f)) return ERR_SYS;
    /* haven't read entire file */
    if (!feof(f)) return ERR_SYS;
    return OK;
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
        if (e->mask & ELOOP_R) FD_SET(e->fd, &rfds);
        if (e->mask & ELOOP_W) FD_SET(e->fd, &wfds);
        if (e->mask & ELOOP_E) FD_SET(e->fd, &efds);
        /* keep track of maxfd */
        if (e->fd > maxfd) maxfd = e->fd;
        e = e->next;
    }

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    r = select(maxfd+1, &rfds, &wfds, &efds, &timeout);
    /* error occured */
    if (r == -1) return ERR_SYS;
    /* nothing to process */
    if (r ==  0) return OK;
    /* start from head */
    e = eloop->head;
    while (e) {
        if ((e->mask & ELOOP_R) && FD_ISSET(e->fd, &rfds) ||
            (e->mask & ELOOP_W) && FD_ISSET(e->fd, &wfds) ||
            (e->mask & ELOOP_E) && FD_ISSET(e->fd, &efds))
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

/**
 * Start the event loop and process until there are no events left.
 */
int eloopRun(struct eloop *eloop) {
    while (eloop->head) {
        int err = eloopProcess(eloop);
        /* error occured no need to continue */
        if (err) return err;
    }
    return OK;
}

/**
 * Fill addrinfo structure for a given host and port.  
 * Returns error returned by underline getaddrinfo call.
 */
int resolve(struct addrinfo **info, char *host, char *port, int socktype) {
    int r;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    return getaddrinfo(host, port, &hints, info);
}

/**
 * Callback to run when socket connects.
 */
static void onConnect(struct eloop *eloop, int fd, void *data) {
    struct netdata *netdata = (struct netdata *) data;
    onconnect *onconnect = netdata->fn;

    int result;
    socklen_t len = sizeof(result);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &result, &len) < 0) {
        close(fd);
        onconnect(ERR_SYS, eloop, -1, netdata->data);
        return;
    }
    onconnect(OK, eloop, fd, netdata->data);
}

/**
 * Try connecting to a given ip and port. Use resolve function to 
 * fill the info structure
 */
void netConnect(struct eloop *eloop, 
                struct addrinfo *info,
                onconnect *onconnect,
                void *data,
                struct netdata *netdata) {
    int r;
    struct addrinfo *p = info;

    netdata->fn = onconnect;
    netdata->data = data;

    for (; p; p = p->ai_next) {
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1)
            continue;
        /* set socket to non-blocking */
        r = fcntl(fd, F_SETFL, O_NONBLOCK);
        if (r == -1) {
            close(fd);
            continue;
        }
        r = connect(fd, p->ai_addr, p->ai_addrlen);
        if (r == -1 && errno != EINPROGRESS)
            close(fd);

        /* add socket to the event loop and wait for it to connect */
        r = eloopAdd(eloop, fd, ELOOP_W, onConnect, netdata);
        if (r)
            close(fd);
        return;
    }

    /* error occured */
    onconnect(ERR_SYS, eloop, -1, netdata->data);
}

/**
 * Callback to run when socket is ready send data.
 */
static void onSendReady(struct eloop *eloop, int fd, void *data) {
    struct netdata *netdata = (struct netdata *) data;
    netSend(eloop, fd, netdata->buf, netdata->buflen, netdata->fn, netdata->data, netdata);
}

/**
 * Sends bytes to a connected socket. Recursively sends until buffer is empty.
 */
void netSend(struct eloop *eloop, 
             int fd, 
             unsigned char *buf,
             int buflen,
             onsend *onsend,
             void *data,
             struct netdata *netdata) {
    int err, n;

    netdata->buf = buf;
    netdata->buflen = buflen;
    netdata->fn = onsend;
    netdata->data = data;

    n = send(fd, netdata->buf, netdata->buflen, MSG_NOSIGNAL);
    if (n == -1) {
        /* send operation didn't complete immediately  */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            err = eloopAdd(eloop, fd, ELOOP_W, onSendReady, netdata);
            if (err) goto error;
        } else {
            err = ERR_SYS;
            goto error;
        }
    } else if (n < netdata->buflen) {
        /* there is more to send */
        netSend(eloop, fd, buf + n, buflen - n, onsend, data, netdata);
    } else {
        /* we sent everything */
        onsend(OK, eloop, fd, netdata->data);
    }
    return;

error:
    onsend(err, eloop, fd, netdata->data);
}

/**
 * Callback to run when socket is ready receive data.
 */
static void onRecvReady(struct eloop *eloop, int fd, void *data) {
    struct netdata *netdata = (struct netdata *) data;
    netRecv(eloop, fd, netdata->buf, netdata->bufcap, netdata->fn, netdata->data, netdata);
}

/**
 * Receive bytes from a connected socket. Recursively receives until buffer is full.
 */
void netRecv(struct eloop *eloop, 
             int fd, 
             unsigned char *buf,
             int bufcap,
             onrecv *onrecv,
             void *data,
             struct netdata *netdata) {
    int err, n;

    netdata->buf = buf;
    netdata->bufcap = bufcap;
    netdata->fn = onrecv;
    netdata->data = data;

    n = recv(fd, netdata->buf + netdata->buflen, netdata->bufcap - netdata->buflen, MSG_NOSIGNAL);
    if (n == -1) {
        /* recv operation didn't complete immediately  */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            err = eloopAdd(eloop, fd, ELOOP_R, onRecvReady, netdata);
            if (err) goto error;
        } else {
            err = ERR_SYS;
            goto error;
        }
    } else if (n == 0) {
        /* socket has been closed */
        err = ERR_SOCK_CLOSED;
        goto error;
    } else if (n + netdata->buflen < netdata->bufcap) {
        netdata->buflen += n;

        /* there is more to recv */
        netRecv(eloop, fd, buf, bufcap, onrecv, data, netdata);
    } else {
        netdata->buflen += n;

        /* we received everything */
        onrecv(OK, eloop, fd, netdata->buf, netdata->buflen, netdata->data);
    }
    return;

error:
    onrecv(err, eloop, fd, netdata->buf, netdata->buflen, netdata->data);
}

static inline void freeHttpdata(struct httpdata *h) {
    free(h->req);
    free(h);
}

static void onHttpGetRecv(int err, 
                          struct eloop *eloop, 
                          int fd, 
                          unsigned char *buf, 
                          int buflen, 
                          void *data) {
    char *head = NULL;
    char *body = NULL;
    int headlen = 0;
    int bodylen = 0;

    struct httpdata *httpdata = (struct httpdata *) data;
    if (err) goto error;

    /* copy tcp buffer to http response buffer */
    memcpy(httpdata->res + httpdata->reslen, buf, buflen);
    httpdata->reslen += buflen;
    char *res = (char *) httpdata->res;
    int reslen = httpdata->reslen;

    /* response is not OK */
    const char *ok = "HTTP/1.1 200 OK";
    if (strncmp(res, ok, strlen(ok))) {
        err = ERR_HTTP_FAILED;
        goto error;
    }

    head = res;
    /* find the separation of head and body */
    char *separator = strstr_n(res, "\r\n\r\n", reslen);
    /* head of the request may not be available or too large for us to extract */
    if (!separator) {
        err = ERR_HTTP_FAILED;
        goto error;
    } 

    /* head of the request */
    headlen = separator - head;
    body = head + headlen + 4;

    /* find Content-Length header within the head */
    char *prefix = "Content-Length: ";
    char *header = strstr_n(head, prefix, headlen);
    /* doesn't have a Content-Length header */
    if (!header) {
        err = ERR_HTTP_FAILED;
        goto error;
    }
    char *contentlen = header + strlen(prefix);

    /* parse Content-Length header */
    int i = 0;
    while (isdigit(contentlen[i]))
        bodylen = bodylen * 10 + contentlen[i++] - '0';

    /* complete length of the HTTP response */
    int len = headlen + 4 + bodylen;

    if (httpdata->reslen < len) {
        /* there is more to read */
        int bufcap = len - httpdata->reslen;
        httpdata->res = realloc(httpdata->res, len);
        if (!httpdata->res)  {
            err = ERR_SYS;
            goto error;
        }

        resetNetdata(&httpdata->tcp);
        netRecv(eloop, fd, httpdata->res + httpdata->reslen, bufcap,
                onHttpGetRecv, httpdata, &httpdata->tcp);
    } else {
        /* response is complete */
        httpdata->onhttp(OK, eloop, httpdata->url, 
                httpdata->res, httpdata->reslen, (unsigned char *) body, httpdata->data);
        close(fd);
        freeHttpdata(httpdata);
    }

    return;
error:
    close(fd);
    httpdata->onhttp(err, eloop, httpdata->url, 
            httpdata->res, httpdata->reslen, (unsigned char *) body, httpdata->data);
    freeHttpdata(httpdata);
}

static void onHttpGetSend(int err, struct eloop *eloop, int fd, void *data) {
    struct httpdata *httpdata = (struct httpdata *) data;
    if (err) goto error;

    unsigned char *res = malloc(1024);
    if (!res) goto error;
    httpdata->res = res;
    httpdata->reslen = 0;

    resetNetdata(&httpdata->tcp);
    netRecv(eloop, fd, httpdata->res, 1024, onHttpGetRecv, httpdata, &httpdata->tcp);

    return;
error:
    httpdata->onhttp(err, eloop, httpdata->url, NULL, 0, NULL, httpdata->data);
    freeHttpdata(httpdata);
}

static void onHttpGetConnect(int err, struct eloop *eloop, int fd, void *data) {
    struct httpdata *httpdata = (struct httpdata *) data;
    if (err) goto error;

    netSend(eloop, fd, httpdata->req, httpdata->reqlen, onHttpGetSend, httpdata, &httpdata->tcp);

    return;
error:
    httpdata->onhttp(err, eloop, httpdata->url, NULL, 0, NULL, httpdata->data);
    freeHttpdata(httpdata);
}

/**
 * This method sends a simple HTTP/1.1 GET request to a given url.
 * It doesn't support extra headers or any other specs in the protocol. 
 * End of stream is only identified by parsing the Content-Length header.
 * Upon success or failure onhttp is called.
 */
void httpGet(struct eloop *eloop, char *url, onhttp *onhttp, void *data) {
    int err;

    /* Extract protocol, host, port, path and query parameters
     * out of given URL.  */  

    char *r, *s = url;
    char *protostr, *hoststr, *portstr, *pathstr, *querystr;
    int protolen, hostlen, portlen, pathlen, querylen;
    protostr = hoststr = portstr = pathstr = querystr = NULL;
    protolen = hostlen = portlen = pathlen = querylen = 0;

    r = strstr(s, "://");
    if (r && strlen(r + 3) > 0) {
        protostr = s;
        protolen = r - s;
        s = r + 3;
        hoststr = s;
        hostlen = strlen(s);
    } else {
        onhttp(ERR_HTTP_URL, eloop, url, NULL, 0, NULL, data);
        return;
    }
    r = strstr(s, ":");
    if (r && strlen(r + 1) > 0) {
        if (s == hoststr) hostlen = r - s;
        s = r + 1;
        portstr = s;
        portlen = strlen(s);
    }
    r = strstr(s, "/");
    if (r && strlen(r + 1) > 0) {
        if (s == hoststr) hostlen = r - s;
        if (s == portstr) portlen = r - s;
        s = r + 1;
        pathstr = s;
        pathlen = strlen(s);
    }
    r = strstr(s, "?");
    if (r && strlen(r + 1) > 0) {
        if (s == hoststr) hostlen = r - s;
        if (s == portstr) portlen = r - s;
        if (s == pathstr) pathlen = r - s;
        s = r + 1;
        querystr = s;
        querylen = strlen(s);
    }

    /* protocol must be 'http' */
    if (!protostr || strncmp(protostr, "http", protolen)) {
        onhttp(ERR_HTTP_URL, eloop, url, NULL, 0, NULL, data);
        return;
    }

    /* calculate request length */
    int reqlen = 
        + strlen("GET ") + 1 + pathlen + 1 + querylen + strlen(" HTTP/1.1\r\n") /* request line */
        + strlen("Host: ") + hostlen + 1 + portlen + strlen("\r\n")             /* host header */
        + strlen("Accept: */*\r\n")                                             /* accept header */
        + strlen("\r\n");                                                       /* separator */

    char host[hostlen+1];
    char port[portlen == 0 ? 3 : portlen+1];              /* set enough size for port 80 */
    char path[1+pathlen+1];                               /* need to have '/' at front */
    char query[querylen > 0 ? 1+querylen+1 : querylen+1]; /* set enough size for '?' as well */
    memset(host, 0, sizeof(host));
    memset(port, 0, sizeof(port));
    memset(path, 0, sizeof(path));
    memset(query, 0, sizeof(query));

    /* copy the port if not set 80 as the port */
    strncpy(host, hoststr, hostlen);
    if (portstr)
        strncpy(port, portstr, portlen);
    else
        strcpy(port, "80");
    /* copy the port with '/' in the front */
    path[0] = '/';
    if (pathstr)
        strncpy(path+1, pathstr, pathlen);
    /* copy the query parameters with '?' in the front */
    if (querystr) {
        query[0] = '?';
        strncpy(query+1, querystr, querylen);
    }

    /* create request */
    char *req = malloc(reqlen+1);
    if (!req) {
        onhttp(ERR_SYS, eloop, url, NULL, 0, NULL, data);
        return;
    }
    snprintf(req, reqlen+1,
        "GET %s%s HTTP/1.1\r\n"
        "Host: %s:%s\r\n"
        "Accept: */*\r\n"
        "\r\n", path, query, host, port);
    reqlen = strlen(req);

    struct httpdata *httpdata = malloc(sizeof(struct httpdata));
    if (!httpdata) {
        err = ERR_SYS;
        goto error;
    }

    struct addrinfo *info = NULL;
    err = resolve(&info, host, port, SOCK_STREAM);
    if (err) {
        err = ERR_GAI;
        goto error;
    }

    memset(httpdata, 0, sizeof(*httpdata));
    httpdata->url = url;
    httpdata->req = (unsigned char *) req;
    httpdata->reqlen = reqlen;
    httpdata->onhttp = onhttp;
    httpdata->data = data;
    
    /* initiate TCP connection */
    netConnect(eloop, info, onHttpGetConnect, httpdata, &httpdata->tcp);

    freeaddrinfo(info);
    return;

error:
    free(req);
    free(httpdata);
    freeaddrinfo(info);
    onhttp(err, eloop, url, NULL, 0, NULL, data);
}

