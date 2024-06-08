#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* Maximum possible character length of an ipv4 or ipv6 address. */
#define IP_STRLEN 40

/* Maximum possible character length of a port. */
#define PORT_STRLEN 6

/* General utility functions */ 
void sha1(unsigned char *data, size_t len, unsigned char digest[20]);
void urlencode(char *dest, char *src, int len);
int findFileSize(int *size, FILE *f);
int readFile(unsigned char *buf, int bufcap, FILE *f);

static void packi32(unsigned char s[4], int32_t i) {
    s[0] = (i >> 24) & 0xFF; s[1] = (i >> 16) & 0xFF;
    s[2] = (i >> 8)  & 0xFF; s[3] = (i)       & 0xFF;
}
static int32_t unpacki32(unsigned char s[4]) {
    return (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
}

/* Types of errors */
#define OK 0                /* no error */
#define ERR_SYS 1           /* std error. errno is set */
#define ERR_GAI 2           /* error in getaddrinfo call */
#define ERR_SOCK_CLOSED 3   /* socket is closed */
#define ERR_HTTP_URL 4      /* invalid HTTP URL */
#define ERR_HTTP_FAILED 5   /* http request didn't given an OK response */
#define ERR_BEN_ENC 6       /* bencode encoding failed */
#define ERR_BEN_DEC 7       /* bencode decoding failed */
#define ERR_PROTO 8         /* protocol error */

/* Error strings for defined errors */
static const char *tnterrors[] = {
    "Ok",
    "System error",
    "Error in getaddrinfo",
    "Socket is closed",
    "Invalid HTTP URL",
    "HTTP request failed",
    "Bencode encoding failed",
    "Bencode decoding failed",
    "Protocol error"
};


/* Log levels */
#define LOG_DEBUG 0   /* shows all the logs */
#define LOG_INFO 1    /* shows info and error logs */
#define LOG_ERROR 2   /* shows only error logs */

/* Log level is set to info */
#define LL LOG_INFO

/* Logging functions */
void logError(int err, const char *fmt, ...);
void logInfo(const char *fmt, ...);
void logDebug(const char *fmt, ...);

struct eloop;

/* Callback function of the event */ 
typedef void onevent(struct eloop *eloop, int fd, void *data);

#define ELOOP_R (1<<0) /* ready for reading */
#define ELOOP_W (1<<1) /* ready for writing */
#define ELOOP_E (1<<2) /* exceptional condition */

/* Event structure */
struct event {
    int fd;             /* file descriptor */
    int mask;           /* ready for reading, writing or an exceptional condition */
    onevent *onevent;   /* callback function */
    void *data;         /* client data */
    struct event *next; /* next event */
    struct event *prev; /* previous event */
};

/* Event Loop structure */
struct eloop {
    struct event *head;     /* head of the list of events */
    struct event *tail;     /* tail of the list of events */
};

/* Event loop functions */
int eloopAdd(struct eloop *eloop, int fd, int mask, onevent *onevent, void *data);
int eloopProcess(struct eloop *eloop);
void eloopRemove(struct eloop *eloop, struct event *e);
int eloopRun(struct eloop *eloop);

/* Callback function to call when a netConnect, netSend or netRecv call finishes */ 
typedef void onconnect(int err, struct eloop *eloop, int fd, void *data);
typedef void onsend(int err, struct eloop *eloop, int fd, void *data);
typedef void onrecv(int err, 
        struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);

/* netdata is an internal structure used for bookkeeping when doing networking calls. 
 * Callers of the net* functions do not have to fill any fields but should allocate it
 * using malloc. */
struct netdata {
    unsigned char *buf;   /* buffer for sending and receiving data */
    int buflen;           /* buffer length. Send data upto buflen */
    int bufcap;           /* buffer capacity. Receive data upto bufcap */
    void *fn;             /* callback function. could be onconnect, onsend or onrecv */
    void *data;           /* client data */
};

/* Reset netdata structure */
static inline void resetNetdata(struct netdata *n) {
    memset(n, 0, sizeof(struct netdata));
}

/* Networking functions */
int resolve(struct addrinfo **info, char *host, char *port, int socktype);
void netConnect(struct eloop *eloop, struct addrinfo *info, 
        onconnect *onconnect, void *data, struct netdata *netdata);
void netSend(struct eloop *eloop, int fd, unsigned char *buf, 
        int buflen, onsend *onsend, void *data, struct netdata *netdata);
void netRecv(struct eloop *eloop, int fd, unsigned char *buf, 
        int bufcap, onrecv *onrecv, void *data, struct netdata *netdata);

/* Callback function of httpGet. res is allocated. Make sure to free when done with it. */ 
typedef void onhttp(int err, struct eloop *eloop, 
        char *url, unsigned char *res, int reslen, unsigned char *body, void *data);

struct httpdata {
    char *url;
    unsigned char *req;
    unsigned char *res;
    int reqlen;
    int reslen; 
    struct netdata tcp;
    onhttp *onhttp;
    void *data;
};

/* HTTP GET */
void httpGet(struct eloop *eloop, char *url, onhttp *onhttp, void *data);

#endif
