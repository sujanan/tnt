#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>

#include "util.h"

#define KEY_LEN 512  /* maximum allowed length for a dict key */
#define DICT_CAP 64  /* size of the dict */

#define INT 1   /* int type node */
#define LIST 2  /* list type node */
#define DICT 3  /* dict type node */
#define BYTES 4 /* bytes type node */

/* node is container to hold either int, list, dict or bytes 
 * when decoding bencoded data */
struct node {
    int t;               /* type of the node */
    union {
        int i;           /* int */
        struct list *l;  /* list */
        struct dict *d;  /* dict */
        struct bytes *s; /* bytes */
    } v;                 /* value of the node */
};

/* Keeps a list of nodes. Can be created with a initial capacity and
 * will grow as values get added. */
struct list {
    struct node *vals;  /* values */
    int len;            /* length of the list */
    int cap;            /* capacity of the list */
};

/* Entry in the dict. Keeps key and value */
struct dictentry {
    char k[KEY_LEN];        /* string type key. has a fixed size length */
    struct node v;          /* node type value */
    int set;                /* whether the entry has a value or empty */
    struct dictentry *next; /* next entry, as in appended order */
};

/* Implementation of a simple dictionary. dict size is fixed.
 * It doesn't have any mechanism to resize as values get added.
 * When the size limit hit, it will simply fail with an assertion error.
 * When a conflict occurs it uses linear probing to find the next entry. 
 * Keys can only be strings and are fixed size. It also maintain
 * the appended order and values cannot be removed. */
struct dict {
    struct dictentry entries[DICT_CAP]; /* entries of the dict */
    int len;                            /* number of entries in the dict */

    /* Number of bytes dictionary takes if it is to be encoded
     * using bencode. nbytes is useful for generating info hash. */
    int nbytes;

    struct dictentry *head;             /* first entry of the dict */
};

/* Fixed size array of bytes that maintains the length and capacity. */
struct bytes {
    char *vals; /* values */
    int len;    /* length of array */
    int cap;    /* capacity of array */
};

/* list functions */
struct list *listCreate(int cap);
struct list *listAdd(struct list *l, struct node n);
void listFree(struct list *l);

/* dict functions */
struct dict *dictCreate();
void dictPut(struct dict *d, char *k, struct node v);
void dictFree(struct dict *d);
struct node *dictGet(struct dict *d, char *k);

/* bytes functions */
struct bytes *bytesCreate(int cap);
void bytesFree(struct bytes *s);

/**
 * Creates a list structrue of a given capacity.
 */
struct list *listCreate(int cap) {
    struct list *l = malloc(sizeof(struct list));
    if (!l) return NULL;
    l->vals = malloc(sizeof(struct node) * cap);
    if (!l->vals) return NULL;
    l->len = 0;
    l->cap = cap;
    return l;
}

/**
 * Add a node to the list. If needed it resize 
 * by doubing the current capacity.
 */
struct list *listAdd(struct list *l, struct node n) {
    if (l->len >= l->cap) {
        l->vals = realloc(l->vals, l->cap * 2);
        l->cap = l->cap * 2;
    }
    if (!l->vals) return NULL;
    l->vals[l->len++] = n;
    return l;
}

/**
 * Free a list. Recursively free nodes as well.
 */
void listFree(struct list *l) {
    if (!l) return;
    struct node *n;
    for (int i = 0; i < l->len; i++) {
        n = &l->vals[i];
        if (n->t == DICT)
            dictFree(n->v.d);
        else if (n->t == LIST)
            listFree(n->v.l);
        else if (n->t == BYTES)
            bytesFree(n->v.s);
    }
    free(l->vals);
    free(l);
}

/**
 * Hash function of dict.
 * http://www.cse.yorku.ca/~oz/hash.html
 */
static unsigned long djb2(unsigned char *k) {
    unsigned long h = 5381;
    unsigned long c;
    while ((c = *k++)) h = ((h << 5) + h) + c;
    return h;
}

/**
 * Creates a dict structure.
 */
struct dict *dictCreate() {
    struct dict *d = malloc(sizeof(struct dict));
    if (!d) return NULL;
    memset(d, 0, sizeof(struct dict));
    return d;
}

/**
 * Put a node to the dict. Replaces the value when key
 * alreay exists.
 */
void dictPut(struct dict *d, char *k, struct node v) {
    /* key should be a string and should be less than KEY_LEN */
    assert(strlen(k) < KEY_LEN);
    /* dict doesn't resize. When hit capacity it simply fails */
    assert(d->len+1 <= DICT_CAP);

    int i = djb2((unsigned char *) k) % DICT_CAP;
    while (d->entries[i].set && strcmp(d->entries[i].k, k))
        i = (i+1) % DICT_CAP;

    strcpy(d->entries[i].k, k);
    d->entries[i].v = v;
    d->entries[i].set = 1;
    d->len++;
    d->entries[i].next = d->head;
    d->head = &d->entries[i];
}

/**
 * Get a node from the dict. If the doesn't exist, NULL is returned.
 */
struct node *dictGet(struct dict *d, char *k) {
    /* key should be a string and should be less than KEY_LEN */
    assert(strlen(k) < KEY_LEN);

    int i = djb2((unsigned char *) k) % DICT_CAP;
    while (d->entries[i].set && strcmp(d->entries[i].k, k))
        i = (i+1) % DICT_CAP;
    return d->entries[i].set ? &d->entries[i].v : NULL;
}

/**
 * Free a dict. Recursively free nodes as well.
 */
void dictFree(struct dict *d) {
    if (!d) return;
    struct node *n;
    for (int i = 0; i < DICT_CAP; i++) {
        if (!d->entries[i].set) continue;
        n = &d->entries[i].v;
        if (n->t == DICT)
            dictFree(n->v.d);
        else if (n->t == LIST)
            listFree(n->v.l);
        else if (n->t == BYTES)
            bytesFree(n->v.s);
    }
    free(d);
}

/**
 * Creates a bytes structure.
 */
struct bytes *bytesCreate(int cap) {
    struct bytes *b = malloc(sizeof(struct bytes));
    if (!b) return NULL;
    b->vals = malloc(cap);
    if (!b->vals) return NULL;
    b->len = 0;
    b->cap = cap;
    memset(b->vals, 0, cap);
    return b;
}

/**
 * Free a bytes structure.
 */
inline void bytesFree(struct bytes *s) { 
    if (!s) return;
    free(s->vals);
    free(s); 
}

/**
 * Converts a node into bytes using bencode encoding format.
 * This method assumes that the raw bytes structure has enough capacity
 * for all the data to be encoded. If it doesn't have enough space
 * it fails with an assertion error. Ideally though we should either
 * handle these errors or resize our bytes structure. 
 */
int encode(struct bytes *raw, struct node *n) {
    int r;

    if (n->t == INT) {
        /* node is integer type */

        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'i';

        /* find length of the integer */
        int len = snprintf(NULL, 0, "%d", n->v.i);
        /* convert integer to string */
        char s[len+1];
        sprintf(s, "%d", n->v.i);

        /* copy the characters to raw */
        assert(raw->len+len < raw->cap);
        for (int i = 0; i < len; i++) 
            raw->vals[raw->len++] = s[i];

        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'e';
    } else if (n->t == LIST) {
        /* node is list type */

        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'l';
        for (int i = 0; i < n->v.l->len; i++) {
            r = encode(raw, &n->v.l->vals[i]);
            if (r) return r;
        }

        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'e';
    } else if (n->t == DICT) {
        /* node is dict type */

        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'd';

        /* It's better to encode the dict in the intersion order. 
         * It allows us to produce predictable results. */
        struct dictentry *entries[n->v.d->len];

        /* head entry is the last added */
        struct dictentry *e = n->v.d->head;
        /* add elements from right to left to maintain the insertion order */
        int i = n->v.d->len-1;
        while (e) {
            entries[i--] = e;
            e = e->next;
        }
        for (i = 0; i < n->v.d->len; i++) {
            e = entries[i];

            /* We create a bytes type key from our key, so we can use our encode 
             * function to encode key strings like any other bytes. */
            char k[KEY_LEN];
            struct bytes s = {.vals = k, s.cap = KEY_LEN};
            strcpy(s.vals, e->k);
            s.len = strlen(e->k);
            struct node kn = {.v.s = &s, .t = BYTES};
            r = encode(raw, &kn);
            if (r) return r;
            r = encode(raw, &e->v);
            if (r) return r;
        }

        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'e';
    } else if (n->t == BYTES) {
        /* node is bytes type */

        /* find length of the string length integer */
        int len = snprintf(NULL, 0, "%d", n->v.s->len);
        char s[len+1];
        /* convert integer to string */
        sprintf(s, "%d", n->v.s->len);

        /* copy the length and integer characters to raw */
        assert(raw->len+len+1 < raw->cap);
        for (int i = 0; i < len; i++) 
            raw->vals[raw->len++] = s[i];
        raw->vals[raw->len++] = ':';
        assert(raw->len+n->v.s->len < raw->cap);
        for (int i = 0; i < n->v.s->len; i++) 
            raw->vals[raw->len++] = n->v.s->vals[i];
    } else {
        /* node type is unknown */
        return ERR_BEN_ENC;
    }

    return OK;
}

/**
 * Decode a bencoded array of bytes.Nodes memory is allocated 
 * except the given one. x act as cursor to go through 
 * the bytes whlie recursively decoding the structure.
 * Make sure x is initialized to zero.
 */
int decode(struct bytes *raw, struct node *n, int *x) {
    int r;
    if (*x >= raw->len) return ERR_BEN_DEC;
    unsigned char b = raw->vals[*x];
    if (b == 'i') {
        /* decoding an integer */
        int i = 0;

        (*x)++; /* consume 'i' */
        b = raw->vals[*x];
        while (b != 'e') {
            i = i*10 + b - '0';
            (*x)++; /* consume digit */
            if (*x >= raw->len) return ERR_BEN_DEC;
            b = raw->vals[*x];
        }
        (*x)++; /* consume 'e' */

        n->v.i = i;
        n->t = INT;
    } else if (b == 'l') {
        /* decoding a list */
        struct list *l = listCreate(128);
        if (!l) return ERR_SYS;

        (*x)++; /* consume 'l' */
        while (b != 'e') {
            struct node item;
            r = decode(raw, &item, x);
            if (r) return r;
            l = listAdd(l, item);
            if (!l) return ERR_BEN_DEC;
            if (*x >= raw->len) return ERR_BEN_DEC;
            b = raw->vals[*x];
        }
        (*x)++; /* consume 'e' */

        n->v.l = l;
        n->t = LIST;
    } else if (b == 'd') {
        /* decoding a dict */
        struct dict *d = dictCreate();
        if (!d) return ERR_SYS;

        int start = *x;
        (*x)++; /* consume 'd' */
        while (b != 'e') {
            struct node k, v;
            r = decode(raw, &k, x);
            if (r) return r;
            r = decode(raw, &v, x);
            if (r) return r;
            assert(k.v.s->len <= KEY_LEN);
            dictPut(d, k.v.s->vals, v);
            if (*x >= raw->len) return ERR_BEN_DEC;
            b = raw->vals[*x];
            bytesFree(k.v.s);
        }
        (*x)++; /* consume 'e' */
        int end = *x;

        d->nbytes = end - start;
        n->v.d = d;
        n->t = DICT;
    } else {
        /* decoding a string */

        /* find length of the string by reading upto ':' */
        int l = 0;
        if (*x >= raw->len) return ERR_BEN_DEC;
        b = raw->vals[*x];
        while (b != ':') {
            l = l*10 + b - '0';
            (*x)++; /* consume digit */
            if (*x >= raw->len) return ERR_BEN_DEC;
            b = raw->vals[*x];
        }
        (*x)++; /* consume ':' */

        /* reading the string upto the length we extracted */
        struct bytes *s = bytesCreate(l+1);
        if (!s) return ERR_BEN_DEC;
        s->vals[s->cap-1] = 0;
        for (int k = *x; k < *x+l; k++) {
            if (k >= raw->len) return ERR_BEN_DEC;
            b = raw->vals[k];
            s->vals[s->len++] = b;
        }
        *x += l; /* consume all the bytes */

        n->v.s = s;
        n->t = BYTES;
    }

    return OK;
}

/* Maximum number of bytes to be requested (REQUEST) at once 
 * when downloading a piece. */
#define BLOCKSIZE 16384

/* Peer to peer port */
#define P2P_PORT "6881"

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
};

/* Tracker keep track of peers of a Torrent. */
struct tracker {
    char *announce;     /* tracker URL */
    struct peer *peers; /* peers */ 
    int plen;           /* peers length */ 
    int ppos;           /* current position of peers */
};

/* Infomation about a downloading/uploading file */
struct file {
    char *path; /* file path along with name of the file */
    int len;    /* length of the file */
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
    struct dict *metainfo;      /* reference to metainfo dict */
};

int initTnt(struct tnt **tnt, struct dict *metainfo);
void die(struct tnt *t, int code);

/* Peer discovery functions */
void discoverPeers(struct eloop *eloop, struct tnt *tnt);
void onPeers(int err, struct eloop *elooop, struct tnt *tnt);

/**
 * Extract peers from the decoded dictionary and fill
 * the tnt structure.
 */
int addPeers(struct tnt *tnt, struct dict *res) {
    struct tracker *tracker = &tnt->tracker; 
    struct node *node = dictGet(res, "peers");
    if (node->t == LIST) {
        /* peers as a list */
        struct list *peers = node->v.l;

        tracker->peers = malloc(sizeof(struct peer) * peers->len);
        if (!tracker->peers) return ERR_SYS;
        for (int i = 0; i < peers->len; i++) {
            struct dict *d = peers->vals[i].v.d;
            struct peer *p = &tracker->peers[tracker->plen++];

            /* ip */
            strcpy(p->ip, dictGet(d, "ip")->v.s->vals);

            /* port */
            snprintf(p->port, sizeof(p->port), "%d", dictGet(d, "port")->v.i);

            /* buf */
            memset(p->buf, 0, sizeof(p->buf));
            p->buflen = 0; 
            p->bufcap = 0;

            /* netdata */
            memset(&p->netdata, 0, sizeof(p->netdata));

            /* start as choked */
            p->choked = 1;
            p->fd = -1;
            p->piece = NULL;
            /* set tnt structure */
            p->tnt = tnt;
        }
    } else if (node->t == BYTES) {
        /* peers as bytes. compact structure */
    }

    return OK;
}

void onTrackerHttpGet(int err, 
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
    struct bytes raw = {.vals = body, .len = bodylen, .cap = bodylen};
    err = decode(&raw, &root, &x);
    if (err) goto error;

    struct tnt *tnt = data;

    /* add peers */
    err = addPeers(tnt, root.v.d);
    if (err) goto error;

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
 * Discover peers based on the announce field in tnt.tracker. 
 * It fills the peers field in tracker. Only supports HTTP. 
 * Upon success or failure, onPeers function will get called. 
 * Note that discoverPeers is only called once in our program. 
 * If we wish to call it periodically, we can add it as a time event 
 * in the event loop. Right now we don't have the ability to do time events.
 */
void discoverPeers(struct eloop *eloop, struct tnt *tnt) {
    struct tracker *tracker = &tnt->tracker;

    /* protocol is not HTTP */
    if (strncmp(tracker->announce, "http://", 7)) {
        onPeers(ERR_HTTP_URL, eloop, tnt);
        return;  
    }

    /* params */
    char infohash[20*3+1];
    char peerid[20*3+1];
    urlencode(infohash, tnt->infohash, 20);
    urlencode(peerid, tnt->peerid, 20);
    char *port = P2P_PORT;
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

    httpGet(eloop, url, onTrackerHttpGet, tnt);
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
    struct bytes buf = {.vals = vals, .len = 0, .cap = sizeof(vals)};

    err = encode(&buf, &n);
    if (err) return err;

    sha1(buf.vals, buf.len, infohash);

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
    struct bytes raw = {.vals = buf, .len = size, .cap = size};
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

/* decode message head */
void decodeHead(int *head, unsigned char *buf);
/* decode message body - general function */
void decodeBody(int *kind, unsigned char *payload, unsigned char *buf, int buflen);

/* connect to peer */
void onConnectPeer(int err, struct eloop *eloop, int fd, void *data);
void connectPeer(struct eloop *eloop, struct peer *p);

/* handshake */
void sendHandshake(struct eloop *eloop, struct peer *p);
void onSendHandshake(int err, struct eloop *eloop, int fd, void *data);
void recvHandshake(struct eloop *eloop, struct peer *p);
void onRecvHandshake(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);

/* send messages */
void sendMessage(struct eloop *eloop, struct peer *p, int kind);
void onSendUnchoke(int err, struct eloop *eloop, int fd, void *data);
void onSendInterested(int err, struct eloop *eloop, int fd, void *data);
void onSendRequest(int err, struct eloop *eloop, int fd, void *data);

/* receive messages */
void recvHead(struct eloop, struct peer *p);
void onRecvHead(int err, struct eloop *eloop, int fd, unsigned char *buf, int buflen, void *data);
void recvBody(struct eloop, struct peer *p);
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
    memcpy(payload, buf, buflen);
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
    peerInfo(p, "Handshaked");
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
        peerError(err, p, "Couldn't connect: %s", gai_strerror(err));
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
