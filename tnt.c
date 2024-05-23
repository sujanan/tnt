#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
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

int initTnt(struct tnt **tnt, struct dict *metainfo);

/* Peer discovery functions */
void discoverPeers(struct eloop *eloop, struct tnt *tnt);
void onPeers(int err, struct eloop *elooop, struct tnt *tnt);

void onPeers(int err, struct eloop *elooop, struct tnt *tnt) {
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
     * we have 3 integers. 6*2 is for '?', '&' and '=' characters.  */ 
    int urllen = strlen(tracker->announce) + strlen(infohash) + strlen(peerid) + PORT_STRLEN + 10*3 + 6*2 + 1;
    char url[urllen];
    snprintf(url, sizeof(url),
        "%s"
        "?info_hash=%s"
        "&peer_id=%s"
        "&port=%s"
        "&uploaded=%d"
        "&downloaded=%d"
        "&left=%d",
        tracker->announce, infohash, peerid, port, uploaded, downloaded, left);
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
 * Creates an initiate int structure using torrent metainfo.
 * This function assumes metainfo is correct.
 */
int initTnt(struct tnt **tnt, struct dict *metainfo) {
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
    if (t->pieces) {
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
    /* peerid */
    /* files */
    /* other */

    return OK;
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

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <torrent>\n", argv[0]);
        return 1;
    }

    int err;

    struct node node;
    const char *filename = argv[1];
    err = readTorrentFile(&node, filename);

    struct dict *metainfo = node.v.d;
    struct dict *info = dictGet(metainfo, "info")->v.d;
    unsigned char infohash[20];

    genInfoHash(infohash, info);
    for (int i = 0; i < 20; i++)
        printf("%d", infohash[i]);

    dictFree(node.v.d);
    return 0;
}
