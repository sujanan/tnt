#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <arpa/inet.h>

#include "util.h"
#include "ben.h"

/* Maximum number of bytes to be requested (REQUEST) at once 
 * when downloading a piece. */
#define BLOCKSIZE 1384

/* Peer to peer port */
#define P2P_PORT 6881

#define INTIIALIZED 1 /* piece is initialized */
#define DOWNLOADING 2 /* downloading the piece */
#define DOWNLOADED 3  /* piece has successfully downloaded */

/* Piece is a fixed-size chunk of the overall file. */
struct piece {
    int index;              /* piece index */
    int len;                /* piece length */
    int requested;          /* requested number of bytes of the piece */
    int downloaded;         /* downloaded number of bytes of the piece */
    unsigned char hash[20]; /* sha1 value of piece */

    /* A buffer to keep piece data. Capacity of the buffer
     * should be length of the piece. */
    unsigned char *buf; 

    int buflen;         /* current length of the buffer */
    int state;          /* current state of the piece */
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
    struct tnt *tnt;          /* reference to tnt structure */
    int idle;                 /* peer has completed work given to it */
};

/* tracker action types */
#define CONNECT 0  
#define ANNOUNCE 1

/* Tracker keep track of peers of a Torrent. */
struct tracker {
    char *announce;     /* tracker URL */
    struct peer *peers; /* peers */ 
    int plen;           /* peers length */ 
    int ppos;           /* current position of peers */
    
    /* A buffer for udp to handle udp tracker requests and responses. */
    unsigned char buf[8192];
    int buflen;         /* buffer length. Send data upto buflen */
    int bufcap;         /* buffer capacity. Receive data upto bufcap */

    /* A netdata to use when exchanging messages. */
    struct netdata netdata;

    int32_t transid;    /* transaction ID */
    int64_t connid;     /* connection ID */
    int32_t action;     /* action type */
};

/* Infomation about a downloading/uploading file */
struct file {
    char *path; /* file path along with name of the file */
    int len;    /* length of the file */
    FILE *ptr;  /* opened pointer of the file */
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
    struct file *files;         /* downloading/uploading files */
    int fileslen;               /* length of files */
    int piecelen;               /* given length of a piece. last piece might be shorter */
    struct dict *metainfo;      /* reference to metainfo dict */
};

/* Reset piece */
void resetPiece(struct piece *piece) {
    free(piece->buf);
    piece->buf = NULL;
    piece->buflen = 0;
    piece->requested = 0;
    piece->downloaded = 0;
    piece->state = INTIIALIZED;
}

/* Initialize peer */
void initPeer(struct peer *p, char *ip, int port, struct tnt *tnt) {
     strcpy(p->ip, ip);
     snprintf(p->port, sizeof(p->port), "%d", port);
     memset(p->buf, 0, sizeof(p->buf));
     p->buflen = 0; 
     p->bufcap = 0;
     memset(&p->netdata, 0, sizeof(p->netdata));
     p->choked = 1;
     p->fd = -1;
     p->piece = NULL;
     p->tnt = tnt;
     p->idle = 0;
}

int initTnt(struct tnt **tnt, struct dict *metainfo);
void die(struct tnt *t, int code);

/* Peer discovery functions */
void onPeers(int err, struct eloop *elooop, struct tnt *tnt);
void discoverPeers(struct eloop *eloop, struct tnt *tnt);

/* http tracker functions */
void httpDiscoverPeers(struct eloop *eloop, struct tnt *tnt);
void httpOnTrackerHttpGet(int err, struct eloop *eloop, 
        char *url, unsigned char *res, int reslen, unsigned char *body, void *data);

/* udp tracker functions */
void udpDiscoverPeers(struct eloop *eloop, struct tnt *tnt);
void udpTrackerRecv(struct eloop *eloop, int fd, struct tnt *tnt);
void udpOnTrackerSend(int err, struct eloop *eloop, int fd, void *data);
void udpOnTrackerConnect(int err, struct eloop *eloop, int fd, void *data);
void udpTrackerSend(struct eloop *eloop, int fd, struct tnt *tnt);
void udpDiscoverPeers(struct eloop *eloop, struct tnt *tnt);

/* Encodes tracker (udp) CONNECT request */
int encodeTrackerConnect(unsigned char *buf, int64_t protoid, int32_t action, int32_t transid) {
    unsigned char *s = buf;
    unsigned char pr[8];
    unsigned char ac[4];
    unsigned char tr[4];
    packi64(pr, protoid);
    memcpy(s, pr, 8);
    s += 8;
    packi32(ac, action);
    memcpy(s, ac, 4);
    s += 4;
    packi32(tr, transid);
    memcpy(s, tr, 4);
    return 8 + 4 + 4;
}

/* Encodes tracker (udp) ANNOUNCE request */
int encodeTrackerAnnounce(unsigned char *buf, 
                          int64_t connid, 
                          int32_t action, 
                          int32_t transid,
                          unsigned char infohash[20],
                          unsigned char peerid[20],
                          int64_t downloaded,
                          int64_t left,
                          int64_t uploaded,
                          int32_t event,
                          int32_t ip,
                          int32_t key,
                          int32_t num_what,
                          int16_t port) {
    unsigned char *s = buf;
    unsigned char connidstr[8], actionstr[4], transidstr[4], leftstr[8], 
                  downloadedstr[8], uploadedstr[8], eventstr[4], 
                  ipstr[4], keystr[4], num_whatstr[4], portstr[2];
    packi64(connidstr, connid);
    memcpy(s, connidstr, 8);
    s += 8;
    packi32(actionstr, action);
    memcpy(s, actionstr, 4);
    s += 4;
    packi32(transidstr, transid);
    memcpy(s, transidstr, 4);
    s += 4;
    memcpy(s, infohash, 20);
    s += 20;
    memcpy(s, peerid, 20);
    s += 20;
    packi64(downloadedstr, downloaded);
    memcpy(s, downloadedstr, 8);
    s += 8;
    packi64(leftstr, left);
    memcpy(s, leftstr, 8);
    s += 8;
    packi64(uploadedstr, uploaded);
    memcpy(s, uploadedstr, 8);
    s += 8;
    packi32(eventstr, event);
    memcpy(s, eventstr, 4);
    s += 4;
    packi32(ipstr, ip);
    memcpy(s, ipstr, 4);
    s += 4;
    packi32(keystr, key);
    memcpy(s, keystr, 4);
    s += 4;
    packi32(num_whatstr, num_what);
    memcpy(s, num_whatstr, 4);
    s += 4;
    packi16(portstr, port);
    memcpy(s, portstr, 2);
    return 98;
}

/* Decodes tracker (udp) ANNOUNCE response head */
void decodeTrackerAnnounceHead(int32_t *action,
                               int32_t *transid,
                               int32_t *interval,
                               int32_t *leechers,
                               int32_t *seeders,
                               unsigned char *buf) {
    unsigned char *s = buf;
    unsigned char ac[4];
    unsigned char tr[4];
    unsigned char in[4];
    unsigned char le[4];
    unsigned char se[4];
    memcpy(ac, s, 4);
    *action = unpacki32(ac);
    s += 4;
    memcpy(tr, s, 4);
    *transid = unpacki32(tr);
    s += 4;
    memcpy(in, s, 4);
    *interval = unpacki32(in);
    s += 4;
    memcpy(le, s, 4);
    *leechers = unpacki32(le);
    s += 4;
    memcpy(se, s, 4);
    *seeders = unpacki32(se);
}

/* Decodes tracker (udp) CONNECT response */
void decodeTrackerConnect(int32_t *action, int32_t *transid, int64_t *connid, unsigned char *buf) {
    unsigned char *s = buf;
    unsigned char ac[4];
    unsigned char tr[4];
    unsigned char co[8];
    memcpy(ac, s, 4);
    *action = unpacki32(ac);
    s += 4;
    memcpy(tr, s, 4);
    *transid = unpacki32(tr);
    s += 4;
    memcpy(co, s, 8);
    *connid = unpacki64(co);
}

/* On tracker udp ANNOUNCE response receive */
void udpOnTrackerRecvAnnounce(int err, 
                              struct eloop *eloop, 
                              int fd, 
                              unsigned char *buf, 
                              int buflen, 
                              void *data) {
    struct tnt *tnt = data;
    struct tracker *tracker = &tnt->tracker;
    if (err) goto error;

    int32_t action;
    int32_t transid;
    int32_t interval;
    int32_t leechers;
    int32_t seeders;
    decodeTrackerAnnounceHead(&action, &transid, &interval, &leechers, &seeders, buf);

    if (action != tracker->action || transid != tracker->transid) {
        err = ERR_PROTO;
        goto error;
    }

    int npeers = leechers + seeders;
    int bodylen = npeers * 6; /* assuming we're requesting ipv4 */
    
    if (buflen == 20) {
        /* buflen is 20 means, it is the first ANNOUNCE response */
        tracker->action = ANNOUNCE;
        tracker->bufcap = 20 + bodylen;
        udpTrackerSend(eloop, fd, tnt);
    } else {
        /* full response is here */
        tracker->peers = malloc(sizeof(struct peer) * npeers);
        if (!tracker->peers) {
            err = ERR_SYS;
            goto error;
        }
        unsigned char *s = buf + 20;
        for (int i = 0; i < npeers; i++) {
            struct peer *p = &tracker->peers[tracker->plen];

            unsigned char ipstr[4];
            unsigned char portstr[4];
            memcpy(ipstr, s, 4);
            s += 4;
            memcpy(portstr, s, 2);
            s += 2;
            uint16_t port = unpacku16(portstr);

            /* convert 32 bit unsigned ipv4 address to string */
            uint32_t ip = htonl(unpacku32(ipstr));
            char ipv4[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip, ipv4, INET_ADDRSTRLEN);

            initPeer(p, ipv4, port, tnt);
            tracker->plen++;
        }
        onPeers(OK, eloop, tnt);
    }

    return;
error:
    onPeers(err, eloop, tnt);
}

/* On tracker udp CONNECT response receive */
void udpOnTrackerRecvConnect(int err, 
                             struct eloop *eloop, 
                             int fd, 
                             unsigned char *buf, 
                             int buflen, 
                             void *data) {
    struct tnt *tnt = data;
    struct tracker *tracker = &tnt->tracker;
    if (err) goto error;

    int32_t action;
    int32_t transid;
    int64_t connid;
    decodeTrackerConnect(&action, &transid, &connid, tracker->buf);

    if (action != tracker->action || transid != tracker->transid) {
        err = ERR_PROTO;
        goto error;
    }
    tracker->action = ANNOUNCE;
    tracker->connid = connid;
    /* bufcap is set 20 for just to obtain a ANNOUNCE
     * response without peers. Once we have the leechers
     * and seeders count, we'll request again with the
     * calculated bufcap. 20 + (seeders + leechers) * 6 */
    tracker->bufcap = 20;
    udpTrackerSend(eloop, fd, tnt);

    return;
error:
    onPeers(err, eloop, tnt);
}

/* Receive data from a udp tracker */
void udpTrackerRecv(struct eloop *eloop, int fd, struct tnt *tnt) {
    struct tracker *tracker = &tnt->tracker;

    if (tracker->action == CONNECT) {
        resetNetdata(&tracker->netdata);
        netRecv(eloop, fd, tracker->buf, 
                tracker->bufcap, udpOnTrackerRecvConnect, tnt, &tracker->netdata); 
    } else if (tracker->action == ANNOUNCE) {
        resetNetdata(&tracker->netdata);
        netRecv(eloop, fd, tracker->buf, 
                tracker->bufcap, udpOnTrackerRecvAnnounce, tnt, &tracker->netdata); 
    }
}

/* On udp tracker request complete */
void udpOnTrackerSend(int err, struct eloop *eloop, int fd, void *data) {
    struct tnt *tnt = data;
    struct tracker *tracker = &tnt->tracker;
    if (err) goto error;

    udpTrackerRecv(eloop, fd, tnt);

    return;
error:
    onPeers(err, eloop, tnt);
}

/* Send data to a udp tracker */
void udpTrackerSend(struct eloop *eloop, int fd, struct tnt *tnt) {
    struct tracker *tracker = &tnt->tracker;

    if (tracker->action == CONNECT) {
        resetNetdata(&tracker->netdata);
        tracker->buflen = encodeTrackerConnect(tracker->buf,
                0x41727101980, tracker->action, tracker->transid);
        netSend(eloop, fd, 
                tracker->buf, tracker->buflen, udpOnTrackerSend, tnt, &tracker->netdata);
    } else if (tracker->action == ANNOUNCE) {
        resetNetdata(&tracker->netdata);
        tracker->buflen = encodeTrackerAnnounce(
            tracker->buf,
            tracker->connid, 
            tracker->action,
            tracker->transid,
            tnt->infohash,
            tnt->peerid,
            tnt->downloaded,
            tnt->left,
            tnt->uploaded,
            0,                /* event - started */
            0,                /* ip - default */
            0,                /* key */
            -1,               /* num_what -default */
            P2P_PORT);        /* port */
        netSend(eloop, fd, 
                tracker->buf, tracker->buflen, udpOnTrackerSend, tnt, &tracker->netdata);
    }
}

/* On connecting to udp tracker */
void udpOnTrackerConnect(int err, struct eloop *eloop, int fd, void *data) {
    struct tnt *tnt = data;
    struct tracker *tracker = &tnt->tracker;
    if (err) goto error;

    time(NULL);
    tracker->transid = rand();
    tracker->action = CONNECT;
    tracker->bufcap = 16; /* CONNECT response size */
    udpTrackerSend(eloop, fd, tnt);
    return;
error:
    onPeers(err, eloop, tnt);
}

/**
 * Discover peers based if the announce URL is udp.
 */
void udpDiscoverPeers(struct eloop *eloop, struct tnt *tnt) {
    int err;
    struct tracker *tracker = &tnt->tracker;
    char *r, *s = tracker->announce;
    char *hoststr, *portstr;
    int hostlen, portlen;
    hoststr = portstr = NULL;
    hostlen = portlen = 0;

    r = strstr(s, "://");
    if (r && strlen(r + 3) > 0) {
        s = r + 3;
        hoststr = s;
        hostlen = strlen(s);
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
    }
    char host[hostlen+1];
    char port[portlen+1];
    memset(host, 0, sizeof(host));
    memset(port, 0, sizeof(port));
    strncpy(host, hoststr, hostlen);
    strncpy(port, portstr, portlen);

    struct addrinfo *info = NULL;
    err = resolve(&info, host, port, SOCK_DGRAM);
    if (err) {
        err = ERR_GAI;
        goto error;
    }

    /* initiate UDP connection */
    resetNetdata(&tracker->netdata);
    netConnect(eloop, info, udpOnTrackerConnect, tnt, &tracker->netdata);

    freeaddrinfo(info);
    return;

error:
    freeaddrinfo(info);
    onPeers(err, eloop, tnt);
}

void httpOnTrackerHttpGet(int err, 
                          struct eloop *eloop, 
                          char *url, 
                          unsigned char *res, 
                          int reslen,
                          unsigned char *body,
                          void *data) {
    if (err) {
        onPeers(err, eloop, data);
        return;
    }

    /* decode response */
    int x = 0;
    struct node root = {.v.d = NULL};
    int bodylen = reslen - (body - res);
    struct bytes raw = {.vals = (char *) body, .len = bodylen, .cap = bodylen};
    err = decode(&raw, &root, &x);
    if (err) goto error;

    struct tnt *tnt = data;
    struct tracker *tracker = &tnt->tracker; 

    /* add peers */
    struct node *node = dictGet(root.v.d, "peers");
    if (node->t == LIST) {
        /* peers as a list */
        struct list *peers = node->v.l;

        tracker->peers = malloc(sizeof(struct peer) * peers->len);
        if (!tracker->peers) {
            err = ERR_SYS;
            goto error;
        }
        for (int i = 0; i < peers->len; i++) {
            struct dict *d = peers->vals[i].v.d;
            struct peer *p = &tracker->peers[tracker->plen++];
            initPeer(p, dictGet(d, "ip")->v.s->vals, dictGet(d, "port")->v.i, tnt);
        }
    } else if (node->t == BYTES) {
        /* TODO: peers as bytes. compact structure */
    }

    onPeers(err, eloop, tnt);
    dictFree(root.v.d);
    free(res);
    return;
error:
    if (root.v.d) dictFree(root.v.d);
    free(res);
    onPeers(err, eloop, tnt);
}

/**
 * Discover peers based if the announce URL is http.
 */
void httpDiscoverPeers(struct eloop *eloop, struct tnt *tnt) {
    struct tracker *tracker = &tnt->tracker;

    /* params */
    char infohash[20*3+1];
    char peerid[20*3+1];
    urlencode(infohash, tnt->infohash, 20);
    urlencode(peerid, tnt->peerid, 20);
    char *port = STR(P2P_PORT);
    int uploaded = tnt->uploaded;
    int downloaded = tnt->downloaded;
    int left = tnt->left;

    /* build URL */

    /* Calculate URL length. 10 is character length of INT_MAX and
     * we have 3 integers.  */ 
    int urllen = strlen(tracker->announce) 
        + strlen("?info_hash=") + strlen(infohash)
        + strlen("&peer_id=") + strlen(peerid)
        + strlen("&port=") + PORT_STRLEN
        + strlen("&uploaded=") + 10
        + strlen("&downloaded=") + 10
        + strlen("&left=") + 10;
    char url[urllen+1];
    snprintf(url, sizeof(url),
        "%s"
        "?info_hash=%s"
        "&peer_id=%s"
        "&port=%s"
        "&uploaded=%d"
        "&downloaded=%d"
        "&left=%d",
        tracker->announce, infohash, peerid, port, uploaded, downloaded, left);

    httpGet(eloop, url, httpOnTrackerHttpGet, tnt);
}

/**
 * Discover peers based on the announce field in tnt.tracker. 
 * It fills the peers field in tracker. Upon success or failure, 
 * onPeers function will get called. Note that discoverPeers is 
 * only called once in our program. 
 */
void discoverPeers(struct eloop *eloop, struct tnt *tnt) {
    struct tracker *tracker = &tnt->tracker;
    if (!strncmp(tracker->announce, "http://", 7)) {
        httpDiscoverPeers(eloop, tnt);
    } else if (!strncmp(tracker->announce, "udp://", 6)) {
        udpDiscoverPeers(eloop, tnt);
    } else {
        onPeers(ERR_NOT_IMPL, eloop, tnt);
    }
}

/**
 * Generate infohash from info dictionary.
 * Here we encode the info dictionary and generate the hash.
 * We can do this because our dictionary maintain insertion
 * order and our encode function respect it when encoding
 * dictionaries. Other data structures maintain order by definition 
 * but the dictionaries don't. Since we have that covered
 * as well, our encode function should ideally generate same
 * bytes we use to decode.
 */
int genInfoHash(unsigned char infohash[20], struct dict *info) {
    int err;

    struct node n = {.v.d = info, .t = DICT};
    unsigned char vals[info->nbytes];
    struct bytes buf = {.vals = (char *) vals, .len = 0, .cap = sizeof(vals)};

    err = encode(&buf, &n);
    if (err) return err;

    sha1((unsigned char *) buf.vals, buf.len, infohash);

    return OK;
}

/**
 * Generate a random 20 byte ID according to 
 * https://www.bittorrent.org/beps/bep_0020.html
 */
void genPeerId(unsigned char id[20]) {
    pid_t pid = getpid();
    id[0] = '-'; 
    id[1] = 'T';
    id[2] = 'T'; 
    id[3] = '0';
    id[5] = '0'; 
    id[6] = '1';
    id[7] = '-';
    /* chose printable ascii range.
     * but we can choose anything between 0 to 256 */
    int lower = 33;
    int upper = 126; 
    for (int i = 8; i < 19; i++) {
        srand(pid+i-8);
        id[i] = lower + (rand() % (upper - lower + 1));
    }
}

/**
 * Creates an initiate int structure using torrent metainfo.
 * This function assumes metainfo is correct.
 */
int initTnt(struct tnt **tnt, struct dict *metainfo) {
    int err;

    *tnt = malloc(sizeof(struct tnt));
    if (!(*tnt)) return ERR_SYS;
    memset(*tnt, 0, sizeof(struct tnt));

    struct tnt *t = *tnt;

    /* tracker */
    char *announce = dictGet(metainfo, "announce")->v.s->vals;
    t->tracker.announce = announce;
    t->tracker.peers = NULL;
    t->tracker.plen = 0;
    t->tracker.ppos = 0;

    struct dict *info = dictGet(metainfo, "info")->v.d;

    /* pieces */
    struct bytes *hashes = dictGet(info, "pieces")->v.s;
    int piecelen = dictGet(info, "piece length")->v.i;
    t->piecelen = piecelen;
    int npieces = hashes->len / 20;
    t->pieces = malloc(sizeof(struct piece) * npieces);
    if (!t->pieces) {
        free(t);
        return ERR_SYS;
    }
    for (int i = 0; i < npieces; i++) {
        struct piece *p = &t->pieces[i];
        p->index = i;
        p->requested = 0;
        p->downloaded = 0;
        memcpy(p->hash, hashes->vals + i*20, 20);
        p->buf = NULL;
        p->buflen = 0;
        /* TODO: last piece might be shorter */
        p->len = piecelen;
        p->state = INTIIALIZED;
    }
    t->plen = npieces;
    t->ppos = 0;

    /* infohash */
    err = genInfoHash(t->infohash, info);
    if (err) {
        free(t->pieces);
        free(t);
        return err;
    }

    /* peerid */
    genPeerId(t->peerid);

    /* files */
    if (dictGet(info, "files")) {
        /* mutiple files */
        struct list *l = dictGet(info, "files")->v.l;
        struct file *files = malloc(sizeof(struct file) * l->len);
        if (!files) {
            free(t->pieces);
            free(t);
            return ERR_SYS;
        }

        for (int i = 0; i < l->len; i++) {
            struct dict *d = l->vals[i].v.d;
            files[i].len = dictGet(d, "length")->v.i;
            files[i].path = dictGet(d, "path")->v.s->vals;
            files[i].ptr = NULL;
            t->fileslen++;
        }
        t->files = files;
    } else {
        /* single file */
        struct file *files = malloc(sizeof(struct file));
        if (!files) {
            free(t->pieces);
            free(t);
            return ERR_SYS;
        }
        files[0].len = dictGet(info, "length")->v.i;
        files[0].path = dictGet(info, "name")->v.s->vals;
        files[0].ptr = NULL;
        t->files = files;
        t->fileslen = 1;
    }

    t->uploaded = 0;
    t->downloaded = 0;
    for (int i = 0; i < t->fileslen; i++)
        t->left += t->files[i].len;
    t->metainfo = metainfo;

    return OK;
}

/**
 * Clean everything up and die.
 */
void die(struct tnt *t, int code) {
    free(t->tracker.peers);
    free(t->pieces);
    free(t->files);
    dictFree(t->metainfo);
    free(t);
    exit(code);
}

/**
 * Open, read and decode a .torrent file.
 */
int readTorrentFile(struct node *n, const char *filename) {
    int err;

    /* open file */
    FILE *f = fopen(filename, "rb");
    if (!f) return ERR_SYS;

    /* get file size */
    int size;
    err = findFileSize(&size, f);
    if (err) return err;
    size += 1;

    /* read file */
    unsigned char buf[size];
    memset(buf, 0, size);
    err = readFile(buf, size, f);
    if (err) return err;

    /* decode */
    int x = 0;
    struct bytes raw = {.vals = (char *) buf, .len = size, .cap = size};
    err = decode(&raw, n, &x);
    if (err) return err;

    fclose(f);
    return OK;
}

/* Some helper functions for peers to log */
void peerError(int err, struct peer *p, const char *fmt, ...) {
    va_list ap;
    char msg[1024];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    logError(err, "[%15s]:%-5s %s", p->ip, p->port, msg);
}
void peerInfo(struct peer *p, const char *fmt, ...) {
    va_list ap;
    char msg[1024];
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    logInfo("[%15s]:%-5s %s", p->ip, p->port, msg);
}

/* message types in BitTorrent protocol */

/* CHOKE/UNCHOKE 
 * ============= 
 * In BitTorrent protocol a peer can either choke another
 * peer or unchoke another peer. If A chokes B, then A
 * will not upload to B. Choking controls uploading/downloading 
 * between peers. This is mainly done to give maximum download 
 * speed to peers who are genuinely interested both uploading 
 * and downloading. Peers that only download without uploading.
 * (free riders) are more likely to be choked frequently.
 * Keep in mind just because A has choked B, it doesn't mean
 * A won't be receiving messages from B. It's more like
 * "I won't answer any of your messages, but I might take them 
 * into account". In our application, we  mostly focus about 
 * downloading. So, we won't be choking other peers but might
 * get choked and unchoked and will ask to get unchoked.
 * (Please note that there is more to this story. Have look
 * at the BitTorrent spec.)
 *
 * INTERESTED/NOT_INTERESTED
 * =========================
 * If a peer doesn't have all the pieces, then it is interested in
 * downloading them. If a peer has all the pieces, then it has
 * no interest in downloading them. The interest messages basically
 * communiate this. It doesn't specifically request a piece, we
 * have request messages for that but it indicate a general interest
 * in downloading or not downloading. 
 *
 * HAVE/BITFIELD
 * =============
 * have and bitfield messages both serve the purpose of informing
 * availibility of pieces to another peer. have messages are small
 * and bitfield messages are large. bitfield message's payload
 * is a bitfield with each index that peer has set to one and 
 * the rest set to zero. bitfield is also the first message after
 * a peer handshake but some peers won't send it. bitfield 
 * messages are not very efficient when a peer has small number
 * of pieces. Then instead of bitfield a series of have can be sent.
 *
 * REQUEST
 * =======
 * A file consist of many pieces but pieces can be further divide into
 * blocks for easier downloads. request messages are for asking a specific
 * block of a piece from another peer that we are interested in downloading. 
 * We can request a block and wait for it to receive via a piece message. 
 * Although, most torrent clients don't typically request a single block
 * and wait for it to receive, they request multiple blocks at once
 * by sending request messages one after another for more efficient
 * data transfers. You can descide how much to request at once.
 * I have heard 5 is optimal number to request at once.
 *
 * PIECE
 * =====
 * A piece message in BitTorrent is the response from a peer containing 
 * the data you requested. It delivers the actual chunk of the file you 
 * asked for.
 *
 * CANCEL
 * ======
 * cancel messages cancel the requests a peer sent using request 
 * messages. cancel messages are useful for a scenario in BitTorrent
 * called 'endgame'. 
 * TODO: I will add a detailed description of the endgame it later.
 */

#define CHOKE 0
#define UNCHOKE 1
#define INTERESTED 2
#define NOT_INTERESTED 3
#define HAVE 4
#define BITFIELD 5
#define REQUEST 6
#define PIECE 7
#define CANCEL 8

/* p2p functions */

/* encode messages */

/* encode handshake */
int encodeHandshake(unsigned char *buf, unsigned char *infohash, unsigned char *peerid);
/* encode message - general function */
int encodeMessage(unsigned char *buf, int head, int kind, unsigned char *payload, int payloadlen);
/* encode different types of messages */
int encodeChoke(unsigned char *buf); /* not yet implementated */
int encodeUnchoke(unsigned char *buf); 
int encodeInterested(unsigned char *buf);
int encodeNotInterested(unsigned char *buf); /* not yet implementated */
int encodeHave(unsigned char *buf, int index); /* not yet implementated */
int encodeBitfield(unsigned char *buf, unsigned char *bitfiled, int len); /* not yet implementated */
int encodeRequest(unsigned char *buf, int index, int begin, int blocksize);
int encodePiece(unsigned char *buf, int index, int begin, unsigned char *piece, int piecelen); /* not yet implementated */
int encodeCancel(unsigned char *buf, int index, int begin, int blocksize);

/* decode messages */

/* decode handshake */
void decodeHandshake(int *pstrlen, 
        char *pstr, unsigned char *infohash, unsigned char *peerid, unsigned char *buf);
/* decode message head */
void decodeHead(int *head, unsigned char *buf);
/* decode message body - general function */
void decodeBody(int *kind, unsigned char *payload, unsigned char *buf, int buflen);
void decodePiecePayload(int *index, int *begin, unsigned char *data, unsigned char *buf, int buflen);

/* connect to peer */
void onConnectPeer(int err, struct eloop *eloop, int fd, void *data);
void connectPeer(struct eloop *eloop, struct peer *p);

/* handshake */
void sendHandshake(struct eloop *eloop, struct peer *p);
void onSendHandshake(int err, struct eloop *eloop, int fd, void *data);
void recvHandshake(struct eloop *eloop, struct peer *p);
void onRecvHandshake(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);

/* send messages */
void initDownload(struct eloop *eloop, struct peer *p);
void download(struct eloop *eloop, struct peer *p);
void rollback(struct eloop *eloop, struct peer *p);
void sendKeeAlive(struct eloop *eloop, struct peer *p);
void sendMessage(struct eloop *eloop, struct peer *p, int kind);
void onSendKeepAlive(int err, struct eloop *eloop, int fd, void *data);
void onSendUnchoke(int err, struct eloop *eloop, int fd, void *data);
void onSendHave(int err, struct eloop *eloop, int fd, void *data);
void onSendInterested(int err, struct eloop *eloop, int fd, void *data);
void onSendRequest(int err, struct eloop *eloop, int fd, void *data);

/* receive messages */
void recvHead(struct eloop *eloop, struct peer *p);
void onRecvHead(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);
void recvBody(struct eloop *eloop, struct peer *p, int buflen);
void onRecvBody(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);

/* Encodes a handshake message. Returns the length. */
int encodeHandshake(unsigned char *buf, unsigned char *infohash, unsigned char *peerid) {
    unsigned char *s = buf;
    s[0] = 19;
    s += 1;
    memcpy(s, "BitTorrent protocol", 19);
    s += 19;
    memset(s, 0, 8);
    s += 8;
    memcpy(s, infohash, 20);
    s += 20;
    memcpy(s, peerid, 20);
    return 68;
}

/* Encodes a BitTorrent p2p message. Returns the length. */
int encodeMessage(unsigned char *buf, int head, int kind, unsigned char *payload, int payloadlen) {
    unsigned char *s = buf;
    unsigned char h[4];
    packi32(h, head);
    memcpy(s, h, 4);
    s += 4;
    s[0] = kind;
    s += 1;
    if (payloadlen > 0)
        memcpy(s, payload, payloadlen);
    return 4 + 1 + payloadlen;
}

/* Encodes unchoke message. Returns the length. */
int encodeUnchoke(unsigned char *buf) { return encodeMessage(buf, 1, UNCHOKE, NULL, 0); }

/* Encodes interested message. Returns the length. */
int encodeInterested(unsigned char *buf) { return encodeMessage(buf, 1, INTERESTED, NULL, 0); }

/* Encodes have message. Returns the length. */
int encodeHave(unsigned char *buf, int index) {
    unsigned char s[4];
    packi32(s, index);
    return encodeMessage(buf, 1+4, HAVE, s, 4);
}

/* Encodes interested message. Returns the length. */
int encodeRequest(unsigned char *buf, int index, int begin, int blocksize) {
    unsigned char s[12];
    unsigned char in[4], be[4], bl[4];
    packi32(in, index);
    packi32(be, begin);
    packi32(bl, blocksize);
    memcpy(s+0, in, 4);
    memcpy(s+4, be, 4);
    memcpy(s+8, bl, 4);
    return encodeMessage(buf, 1+12, REQUEST, s, 12);
}

/* Decode handshake. */
void decodeHandshake(int *pstrlen, 
                     char *pstr, 
                     unsigned char *infohash, 
                     unsigned char *peerid, 
                     unsigned char *buf) {
    unsigned char *s = buf;
    *pstrlen = s[0];
    s += 1;
    memcpy(pstr, s, 19);
    s += 19;
    s += 8;
    memcpy(infohash, s, 20);
    s += 20;
    memcpy(peerid, s, 20);
}

/* Decode message head. */
void decodeHead(int *head, unsigned char *buf) {
    unsigned char h[4];
    memcpy(h, buf, 4);
    *head = unpacki32(h);
}

/* Decode message body. */
void decodeBody(int *kind, unsigned char *payload, unsigned char *buf, int buflen) {
    *kind = buf[0];
    if (!payload) return;
    memcpy(payload, buf+1, buflen-1);
}

/* Select next piece to download. Returns NULL if there are no more pieces. */
struct piece *nextPiece(struct peer *p) {
    struct tnt *tnt = p->tnt; 
    struct piece *piece; 
    for (int i = 0; i < tnt->plen; i++) {
        piece = &tnt->pieces[tnt->ppos];
        tnt->ppos = (tnt->ppos+1) % tnt->plen;
        if (piece->state == INTIIALIZED) {
            piece->state = DOWNLOADING;
            return piece;
        }
    }
    return NULL;
}

void changePeer(struct eloop *eloop, struct peer *p) {
    struct tracker *tracker = &p->tnt->tracker;
    for (int i = 0; i < tracker->plen; i++) {
        if (tracker->peers[i].idle) {
            struct peer *newp = &tracker->peers[i];
            newp->piece = p->piece;
            newp->piece->state = DOWNLOADING;
            peerInfo(p, "handed over downloading piece %d to [%s]:%s", 
                    newp->piece->index, newp->ip, newp->port);
            newp->piece->buf = malloc(newp->piece->len);
            if (newp->piece->buf == NULL) {
                logError(ERR_SYS, "malloc failed");
                return;
            }
            download(eloop, newp);
            return;
        }
    }
    peerInfo(p, "attempted to hand over piece %d but all peers were busy", p->piece->index);
}

/* On body of a message receive */
void onRecvBody(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "message recv failed (body)");
        if (p->piece) {
            p->idle = 0;
            resetPiece(p->piece);
            changePeer(eloop, p);
        }
        return;
    }
    int kind = 0;
    unsigned char payload[buflen - 1]; /* buflen minus the kind byte */
    decodeBody(&kind, payload, p->buf, buflen);
    if (kind == CHOKE) {
        p->choked = 1;
    } else if (kind == UNCHOKE) {
        p->choked = 0;
    } else if (kind == INTERESTED) {
        /* do nothing for now */
    } else if (kind == NOT_INTERESTED) {
        /* do nothing for now */
    } else if (kind == HAVE) {
        /* do nothing for now */
    } else if (kind == BITFIELD) {
        /* do nothing for now */
    } else if (kind == REQUEST) {
        /* do nothing for now */
    } else if (kind == PIECE) {
        unsigned char *s = payload;
        unsigned char in[4], be[4];
        memcpy(in, s, 4);
        int index = unpacki32(in);
        s += 4;
        memcpy(be, s, 4);
        int begin = unpacki32(be);
        s += 4;
        memcpy(p->piece->buf + begin, s, sizeof(payload) - 8);
        p->piece->downloaded += sizeof(payload) - 8;
    } else if (kind == CANCEL) {
        /* do nothing for now */
    } else {
        /* do nothing for now */
    }
    /* call download again to continue the process */
    download(eloop, p);
}

/* Receive body of a message */
void recvBody(struct eloop *eloop, struct peer *p, int buflen) {
    resetNetdata(&p->netdata);
    netRecv(eloop, p->fd, p->buf, buflen, onRecvBody, p, &p->netdata);
}

/* On head of a message receive */
void onRecvHead(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "message recv failed (head)");
        if (p->piece) {
            p->idle = 0;
            resetPiece(p->piece);
            changePeer(eloop, p);
        }
        return;
    }
    int head = 0;
    decodeHead(&head, p->buf);
    /* head is the length of the body we have to read next */
    recvBody(eloop, p, head);
}

/* Receive head of a message */
void recvHead(struct eloop *eloop, struct peer *p) {
    resetNetdata(&p->netdata);
    netRecv(eloop, p->fd, p->buf, 4, onRecvHead, p, &p->netdata);
}

void onSendRequest(int err, struct eloop *eloop, int fd, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "message send failed (REQUEST)");
        if (p->piece) {
            p->idle = 0;
            resetPiece(p->piece);
            changePeer(eloop, p);
        }
        return;
    }
    /* last block could be shorter */
    int blocksize = BLOCKSIZE;
    if (p->piece->len - p->piece->requested < BLOCKSIZE)
        blocksize = p->piece->len - p->piece->requested;
    /* update the requested number of bytes */
    p->piece->requested += blocksize;
    /* call download again */
    download(eloop, p);
}

/* On interested message sent */
void onSendInterested(int err, struct eloop *eloop, int fd, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "message send failed (INTERESTED)");
        return;
    }
    initDownload(eloop, p);
}

/* On unchoke message sent */
void onSendUnchoke(int err, struct eloop *eloop, int fd, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "message send failed (UNCHOKE)");
        return;
    }
    sendMessage(eloop, p, INTERESTED);
}

/* On keep-alive message sent */
void onSendKeepAlive(int err, struct eloop *eloop, int fd, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "message send failed (keep-alive)");
        return;
    }
    peerInfo(p, "keep-alive");
    p->buflen = 0;
    p->bufcap = 0;
}

/* Send keep-alive message */
void sendKeeAlive(struct eloop *eloop, struct peer *p) {
    int buflen = 4;
    p->buf[0] = 0;
    resetNetdata(&p->netdata);
    netSend(eloop, p->fd, p->buf, buflen, onSendKeepAlive, p, &p->netdata);
}

/* Sends a message of a given kind */
void sendMessage(struct eloop *eloop, struct peer *p, int kind) {
    if (kind == UNCHOKE) {
        int buflen = encodeUnchoke(p->buf);
        resetNetdata(&p->netdata);
        netSend(eloop, p->fd, p->buf, buflen, onSendUnchoke, p, &p->netdata);
    } else if (kind == INTERESTED) {
        int buflen = encodeInterested(p->buf);
        resetNetdata(&p->netdata);
        netSend(eloop, p->fd, p->buf, buflen, onSendInterested, p, &p->netdata);
    } else if (kind == REQUEST) {
        /* last block could be shorter */
        int blocksize = BLOCKSIZE;
        if (p->piece->len - p->piece->requested < BLOCKSIZE)
            blocksize = p->piece->len - p->piece->requested;
        int buflen = encodeRequest(
                p->buf, p->piece->index, p->piece->requested, blocksize);
        resetNetdata(&p->netdata);
        netSend(eloop, p->fd, p->buf, buflen, onSendRequest, p, &p->netdata);
    }
}

/* Initialize the download process */
void initDownload(struct eloop *eloop, struct peer *p) {
    p->piece = nextPiece(p);
    if (p->piece) {
        /* allocate piece length size of memory */
        p->piece->buf = malloc(p->piece->len);
        if (!p->piece->buf) {
            peerError(ERR_SYS, p, "malloc failed");
            return;
        }
        download(eloop, p);
    }
}

/* Save piece to disk synchronously */
int savePiece(struct tnt *tnt, struct piece *piece) {
    /* find file based on piece location */
    int curr = 0;
    int index = 0;
    for (int i = 0; i < tnt->fileslen; i++) {
        int l = piece->index * tnt->piecelen;
        if (l >= curr && l < curr + tnt->files[i].len) {
            index = i;
            break;
        }
        curr += tnt->files[i].len;
    }

    struct file *f = &tnt->files[index];
    if (!f->ptr) {
        /* open file if not opened yet */
        f->ptr = fopen(f->path, "wb");
        if (!f->ptr) return ERR_SYS;
    }

    /* seek to the piece location */
    if (fseek(f->ptr, piece->index * tnt->piecelen - curr, SEEK_SET))
        return ERR_SYS;

    fwrite(piece->buf, 1, piece->len, f->ptr);
    /* error occured after writing the file */
    if (ferror(f->ptr)) return ERR_SYS;

    return OK;
}

/* Download pieces block by block */
void download(struct eloop *eloop, struct peer *p) {
    int err;
    if (p->choked) {
        /* We're still choked. Wait until peer unchokes */
        recvHead(eloop, p);
    } else {
        struct piece *piece = p->piece;
        /* Here we're requesting the entire piece length (all the blocks)
         * one after another and then start waiting for piece messages 
         * (requested blocks) to receive. Ideally we should only request 
         * a controlled number of blocks of a piece like this. Either way,
         * reason protocol advise us to queue our request messages is to
         * improve the TCP performance. This is called 'pipelining' */
        if (piece->requested < piece->len) {
            /* send request messages until we have requested all the blocks */
            sendMessage(eloop, p, REQUEST);
        } else if (piece->downloaded < piece->len) {
            /* listen and download blocks */
            recvHead(eloop, p);
        } else {
            /* validate piece */
            unsigned char hash[20];
            sha1(piece->buf, piece->downloaded, hash);
            if (memcmp(hash, piece->hash, 20)) {
                peerError(ERR_PROTO, p, "piece integrity check failed: %d", piece->index);
                return;
            }

            /* save piece to disk */
            err = savePiece(p->tnt, piece);
            if (err) {
                peerError(err, p, "couldn't save piece: %d", piece->index);
                return;
            }
            p->tnt->downloaded += piece->len;
            p->tnt->left -= piece->len;
            free(piece->buf);
            piece->buf = NULL;
            piece->state = DOWNLOADED;

            peerInfo(p, "↓ %5.2f%% #%d", 
                    (double) p->tnt->downloaded / (p->tnt->piecelen * p->tnt->plen) * 100,
                    piece->index);

            /* get the next piece */
            piece = nextPiece(p);
            if (!piece) {
                /* peer has completed pieces assigned to it.
                 * It goes to idle now. So it is available to
                 * download failed pieces. */
                p->idle = 1;
                sendKeeAlive(eloop, p);
                return;
            }

            /* allocate piece length size of memory */
            piece->buf = malloc(piece->len);
            if (!piece->buf) {
                peerError(ERR_SYS, p, "malloc failed");
                return;
            }
            /* set the piece */
            p->piece = piece;

            /* continue the download process */
            download(eloop, p);
        }
    }
}

/* On recvHandshake completes */
void onRecvHandshake(int err, 
                     struct eloop *eloop, 
                     int fd, 
                     unsigned char *buf, 
                     int buflen, 
                     void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "Handshake failed (recv)");
        return;
    }
    int pstrlen = 0;
    char pstr[20];
    unsigned char infohash[20];
    unsigned char peerid[20];
    /* decode handshake and verify */
    decodeHandshake(&pstrlen, pstr, infohash, peerid, p->buf);
    if (pstrlen != 19 || 
            strncmp(pstr, "BitTorrent protocol", 19) || 
            memcmp(infohash, p->tnt->infohash, 20)) {
        peerError(ERR_PROTO, p, "Handshake failed (invalid message)");
        return;
    }
    peerInfo(p, "Handshaked");

    /* We have handshaked. Let's ask our peer to unchoke us. */
    sendMessage(eloop, p, UNCHOKE);
}

/* Receive handshake from connected peer */
void recvHandshake(struct eloop *eloop, struct peer *p) {
    /* receive handshake */
    resetNetdata(&p->netdata);
    netRecv(eloop, p->fd, p->buf, 68, onRecvHandshake, p, &p->netdata); 
}

/* On sendHandshake completes */
void onSendHandshake(int err, struct eloop *eloop, int fd, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "Handshake failed (send)");
        return;
    }
    recvHandshake(eloop, p);
}

/* Send handshake message to connected peer */
void sendHandshake(struct eloop *eloop, struct peer *p) {
    /* encode handshake */
    int buflen = encodeHandshake(p->buf, p->tnt->infohash, p->tnt->peerid);
    /* send handshake */
    resetNetdata(&p->netdata);
    netSend(eloop, p->fd, p->buf, buflen, onSendHandshake, p, &p->netdata);
}

/* On connectPeer completes */
void onConnectPeer(int err, struct eloop *eloop, int fd, void *data) {
    struct peer *p = data;
    if (err) {
        peerError(err, p, "Couldn't connect");
        return;
    }
    /* set connected socket fd */
    p->fd = fd;
    /* start handshake */ 
    sendHandshake(eloop, p);
}

/* Connect to a peer */
void connectPeer(struct eloop *eloop, struct peer *p) {
    int err;
    struct addrinfo *info = NULL;
    err = resolve(&info, p->ip, p->port, SOCK_STREAM);
    if (err) {
        peerError(ERR_GAI, p, "Couldn't connect: %s", gai_strerror(err));
        return;
    }
    resetNetdata(&p->netdata);
    netConnect(eloop, info, onConnectPeer, p, &p->netdata);
}

/**
 * Start downloading/uploading pieces from discovered peers.
 */
void onPeers(int err, struct eloop *eloop, struct tnt *tnt) {
    if (err) {
        logError(err, "Tracker request failed: %s", tnt->tracker.announce);
        die(tnt, 1);
    }
    struct tracker *tracker = &tnt->tracker;
    for (int i = 0; i < tracker->plen; i++) {
        /* get next peer and connect to it */
        struct peer *p = &tracker->peers[tracker->ppos++];
        connectPeer(eloop, p);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <torrent>\n", argv[0]);
        return 1;
    }

    int err;

    /* read torrent file */
    struct node node;
    const char *filename = argv[1];
    err = readTorrentFile(&node, filename);

    /* initiate tnt structure from metainfo */
    struct dict *metainfo = node.v.d;
    struct tnt *tnt;
    err = initTnt(&tnt, metainfo);

    /* creates event loop */
    struct eloop eloop;
    memset(&eloop, 0, sizeof(struct eloop));

    discoverPeers(&eloop, tnt);
    
    eloopRun(&eloop);

    die(tnt, 0);
    return 0;
}
