#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>

/* General utility functions */ 
void sha1(unsigned char *data, size_t len, unsigned char digest[20]);
void urlencode(char *dest, char *src, int len);

/* Types of errors */
#define OK 0       /* no error */
#define ERR_LIB 1  /* error due to invalid inputs */
#define ERR_SYS 2  /* system error. errno is set */

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
void eloopRemove(struct eloop *eloop, struct event *e);
int eloopProcess(struct eloop *eloop);

#endif
