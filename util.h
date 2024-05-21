#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
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

/* Types of errors */
#define OK 0                /* no error */
#define ERR_SYS 1           /* std error. errno is set */
#define ERR_GAI 2           /* error in getaddrinfo call */
#define ERR_SOCK_CLOSED 3   /* socket is closed */
#define ERR_HTTP_URL 4      /* invalid HTTP URL */

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

/* Callback function to call when a netConnect, netSend or netRecv call finishes */ 
typedef void onconnect(int err, struct eloop *eloop, int fd, void *data);
typedef void onsend(int err, struct eloop *eloop, int fd, void *data);
typedef void onrecv(int err, 
        struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);

/* netdata is a structure that can be used for bookkeeping 
 * when doing networking calls. It keeps everything related to connect, send and recv.
 * Fill up only the necessary things before calling. */
struct netdata {
    unsigned char *buf;   /* buffer for sending and receiving data */
    int buflen;           /* buffer length. Send data upto buflen */
    int bufcap;           /* buffer capacity. Receive data upto bufcap */
    void *fn;             /* callback function. could be onconnect, onsend or onrecv */
    void *data;           /* client data */
};

/* Networking functions */
int resolve(struct addrinfo **info, char *host, char *port, int socktype);
void netConnect(struct eloop *eloop, 
        struct netdata *netdata, struct addrinfo *info, onconnect *onconnect);
void netSend(struct eloop *eloop, struct netdata *netdata, int fd, onsend *onsend);
void netRecv(struct eloop *eloop, struct netdata *netdata, int fd, onrecv *onrecv);

/* Callback function of httpGet. buf is allocated. Make sure to free when done with it. */ 
typedef void onhttp(int err, char *url, unsigned char *buf, int buflen);

struct httpdata {
    unsigned char *res;
    int reslen;
    struct netdata tcp;
    onhttp *onhttp;
};

/* HTTP GET */
void httpGet(struct eloop *eloop, char *url, onhttp *onhttp);

#endif
