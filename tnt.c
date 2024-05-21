#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "util.h"

/* Maximum number of bytes to be requested (REQUEST) at once 
 * when downloading a piece. */
#define BLOCKSIZE 16384

/* Piece is a fixed-size chunk of the overall file. */
struct piece {
    int index;          /* piece index */
    int len;            /* piece length */
    int requested;      /* requested number of bytes of the piece */
    int downloaded;     /* downloaded number of bytes of the piece */
    int hash;           /* sha1 value of piece */

    /* A buffer to keep piece data. Capacity of the buffer
     * should be length of the piece. */
    unsigned char *buf; 

    int buflen;         /* current length of the buffer */
};

/* Peer is a participant of the file sharing process.
 * Peer can either download or upload pieces. */
struct peer {
    char id[20];               /* peer id */
    char ip[IP_STRLEN];        /* peer ip */
    char port[PORT_STRLEN];    /* peer port */

    /* A buffer for peer to send and receive data.
     * If the buffer is enough for largest type
     * of message (PIECE), it is enough any other type. */
    unsigned char buf[
        1 +         /* type of the message */
        BLOCKSIZE + /* maximum possible data length */
        4 + 4       /* index and begin fields */
    ];
    int buflen;               /* buffer length. Send data upto buflen */
    int bufcap;               /* buffer capacity. Receive data upto bufcap */

    /* A netdata to use when exchanging messages between peers. */
    struct netdata netdata;

    int choked;               /* whether peer has choked us or not */
    int fd;                   /* socket descriptor */
    struct piece *piece;      /* piece peer currently downloading */
};

/* Tracker keep track of peers of a Torrent. */
struct tracker {
    char *announce;     /* tracker URL */
    struct peer *peers; /* peers */ 
    int plen;           /* peers length */ 
    int ppos;           /* current position of peers */
};

/* tnt is our internal structure to keep track of everything we do.
 * All the peers keep a reference to tnt. */
struct tnt {
    struct tracker tracker;     /* tracker */
    struct piece *pieces;       /* pieces */
    int plen;                   /* pieces length */
    int ppos;                   /* current position of pieces */
    unsigned char peerid[20];   /* our peer id */
    unsigned char infohash[20]; /* infohash of torrent */
    int left;                   /* bytes left to download */
    int downloaded;             /* downloaded bytes */
    int uploaded;               /* uploaded bytes */
};

void onExampleResponse(int err, char *url, unsigned char *buf, int buflen) {
    if (err) {
        printf("error occured: %s\n", strerror(errno));
        return;
    }
}

int main(int argc, char **argv) {
    struct eloop eloop;
    memset(&eloop, 0, sizeof(eloop));

    httpGet(&eloop, "http://example.com", onExampleResponse);

    eloopRun(&eloop);

    return 0;
}
