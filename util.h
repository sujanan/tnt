#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

/* General utility functions */ 
void sha1(unsigned char *data, size_t len, unsigned char digest[20]);
void urlencode(char *dest, char *src, int len);

/* Types of errors */
#define OK 0                /* no error */
#define ERR_SYS 1           /* std error. errno is set */
#define ERR_SOCK_CLOSED 2   /* peer has closed the socket */

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
typedef void onconnect(int err, int fd, void *data);
typedef void onsend(int err, int fd, void *data);
typedef void onrecv(int err, int fd, unsigned char *buf, int buflen, void *data);

/* netclient is a structure that can be used for bookkeeping 
 * when doing networking calls. It keeps everything related to connect, send and recv.
 * Fill up only the necessary things before calling. */
struct netclient {
    struct eloop *eloop;  /* reference to event loop */
    unsigned char *buf;   /* buffer for sending and receiving data */
    int buflen;           /* buffer length. Send data upto buflen */
    int bufcap;           /* buffer capacity. Receive data upto bufcap */
    onconnect *onconnect; /* function to call when connects */
    onsend *onsend;       /* function to call when data has sent */
    onrecv *onrecv;       /* function to call when data has received */
    void *data;           /* client data */
};

/* Networking related functions */
int resolve(struct addrinfo **info, char *host, char *port, int socktype);
void netConnect(struct netclient *client, struct addrinfo *info);
void netSend(struct netclient *client, int fd);
void netRecv(struct netclient *client, int fd);

#endif
