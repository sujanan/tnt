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

#define OK 0
#define ERR 1

#define LOG(lvl, ...)                                             \
    do {                                                          \
        printf("%c:%4d| ", lvl, __LINE__);                        \
        printf(__VA_ARGS__);                                      \
        if (lvl == 'E' && errno) printf(": %s", strerror(errno)); \
        printf("\n");                                             \
    } while (0)

#define I(...) LOG('I', __VA_ARGS__)
#define D(...) LOG('D', __VA_ARGS__)
#define E(...) LOG('E', __VA_ARGS__)

typedef int32_t i32;
typedef uint32_t u32;
#define ROTL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

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

typedef struct node node;
typedef struct list list;
typedef struct dict_entry dict_entry;
typedef struct dict dict;
typedef struct bytes bytes;

#define KEY_LEN 512
#define DICT_CAP 64

#define INT 1
#define LIST 2
#define DICT 3
#define BYTES 4
typedef struct node {
    int t;
    union {
        int i;
        list *l;
        dict *d;
        bytes *s;
    } v;
} node;

typedef struct list {
    node *vals;
    int len;
    int cap;
} list;

typedef struct dict_entry {
    char k[KEY_LEN];
    node v;
    int set;
    dict_entry *next;
} dict_entry;

typedef struct dict {
    dict_entry entries[DICT_CAP];
    int len;
    dict_entry *head;
} dict;

typedef struct bytes {
    char *vals;
    char *r;
    int len;
    int cap;
} bytes;

list *list_create(int cap) {
    list *l = malloc(sizeof(list));
    if (!l) return NULL;
    l->vals = malloc(sizeof(node) * cap);
    if (!l->vals) return NULL;
    l->len = 0;
    l->cap = cap;
    return l;
}

list *list_add(list *l, node n) {
    if (l->len >= l->cap) {
        l->vals = realloc(l->vals, l->cap*2);
        l->cap = l->cap*2;
    }
    if (!l->vals) return NULL;
    l->vals[l->len++] = n;
    return l;
}

unsigned long djb2(unsigned char *k) {
    unsigned long h = 5381;
    unsigned long c;
    while ((c = *k++)) h = ((h<<5)+h)+c;
    return h;
}

dict *dict_create() {
    dict *d = malloc(sizeof(dict));
    if (!d) return NULL;
    memset(d, 0, sizeof(dict));
    return d;
}

void dict_put(dict *d, char *k, node v) {
    assert(strlen(k) < KEY_LEN);
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

node *dict_get(dict *d, char *k) {
    assert(strlen(k) < KEY_LEN);
    int i = djb2((unsigned char *) k) % DICT_CAP;
    while (d->entries[i].set && strcmp(d->entries[i].k, k))
        i = (i+1) % DICT_CAP;
    return d->entries[i].set ? &d->entries[i].v : NULL;
}

bytes *bytes_create(int cap) {
    bytes *b = malloc(sizeof(bytes));
    if (!b) return NULL;
    b->vals = malloc(cap);
    if (!b->vals) return NULL;
    b->r = b->vals;
    b->len = 0;
    b->cap = cap;
    memset(b->vals, 0, cap);
    return b;
}

void bytes_reset(bytes *s) {
    s->len = 0;
    s->cap = 0;
}

void list_free(list *l);
void dict_free(dict *d);
void bytes_free(bytes *s);

void list_free(list *l) {
    if (!l) return;
    node *n;
    for (int i = 0; i < l->len; i++) {
        n = &l->vals[i];
        if (n->t == DICT)
            dict_free(n->v.d);
        else if (n->t == LIST)
            list_free(n->v.l);
        else if (n->t == BYTES)
            bytes_free(n->v.s);
    }
    free(l->vals);
    free(l);
}

void dict_free(dict *d) {
    if (!d) return;
    node *n;
    for (int i = 0; i < DICT_CAP; i++) {
        if (!d->entries[i].set) continue;
        n = &d->entries[i].v;
        if (n->t == DICT)
            dict_free(n->v.d);
        else if (n->t == LIST)
            list_free(n->v.l);
        else if (n->t == BYTES)
            bytes_free(n->v.s);
    }
    free(d);
}

void bytes_free(bytes *s) {
    if (!s) return;
    free(s->r);
    free(s);
}

int encode(bytes *raw, node *n) {
    int r;
    if (n->t == INT) {
        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'i';
        /* find length of the integer */
        int len = snprintf(NULL, 0, "%d", n->v.i);
        /* convert integer to string */
        char s[len+1];
        sprintf(s, "%d", n->v.i);
        /* copy the chars to raw */
        assert(raw->len+len < raw->cap);
        for (int i = 0; i < len; i++) 
            raw->vals[raw->len++] = s[i];
        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'e';
    } else if (n->t == LIST) {
        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'l';
        for (int i = 0; i < n->v.l->len; i++) {
            r = encode(raw, &n->v.l->vals[i]);
            if (r) return r;
        }
        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'e';
    } else if (n->t == DICT) {
        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'd';
        /* It's better to encode the dict in the intersion order. 
         * It allows us to produce predictable results. */
        dict_entry *entries[n->v.d->len];
        /* head entry is the last added */
        dict_entry *e = n->v.d->head;
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
            bytes s = {.vals = k, .r = k, s.cap = KEY_LEN};
            strcpy(s.vals, e->k);
            s.len = strlen(e->k);
            node kn = {.v.s = &s, .t = BYTES};
            r = encode(raw, &kn);
            if (r) return r;
            r = encode(raw, &e->v);
            if (r) return r;
        }
        assert(raw->len < raw->cap);
        raw->vals[raw->len++] = 'e';
    } else if (n->t == BYTES) {
        /* find length of the string length integer */
        int len = snprintf(NULL, 0, "%d", n->v.s->len);
        char s[len+1];
        /* convert integer to string */
        sprintf(s, "%d", n->v.s->len);
        /* copy the chars to raw */
        assert(raw->len+len+1 < raw->cap);
        for (int i = 0; i < len; i++) 
            raw->vals[raw->len++] = s[i];
        raw->vals[raw->len++] = ':';
        assert(raw->len+n->v.s->len < raw->cap);
        for (int i = 0; i < n->v.s->len; i++) 
            raw->vals[raw->len++] = n->v.s->vals[i];
    } else return ERR;
    return OK;
}

int decode(bytes *raw, node *n, int *x) {
    int r;
    if (*x >= raw->len) return ERR;
    unsigned char b = raw->vals[*x];
    if (b == 'i') {
        int i = 0;
        (*x)++; /* consume 'i' */
        b = raw->vals[*x];
        while (b != 'e') {
            i = i*10 + b - '0';
            (*x)++; /* consume digit */
            if (*x >= raw->len) return ERR;
            b = raw->vals[*x];
        }
        (*x)++; /* consume 'e' */
        n->v.i = i;
        n->t = INT;
    } else if (b == 'l') {
        list *l = list_create(128);
        if (!l) return ERR;
        (*x)++; /* consume 'l' */
        while (b != 'e') {
            node item;
            r = decode(raw, &item, x);
            if (r) return r;
            l = list_add(l, item);
            if (!l) return ERR;
            if (*x >= raw->len) return ERR;
            b = raw->vals[*x];
        }
        (*x)++; /* consume 'e' */
        n->v.l = l;
        n->t = LIST;
    } else if (b == 'd') {
        dict *d = dict_create();
        (*x)++; /* consume 'd' */
        while (b != 'e') {
            node k, v;
            r = decode(raw, &k, x);
            if (r) return r;
            r = decode(raw, &v, x);
            if (r) return r;
            assert(k.v.s->len <= KEY_LEN);
            dict_put(d, k.v.s->vals, v);
            if (*x >= raw->len) return ERR;
            b = raw->vals[*x];
            bytes_free(k.v.s);
        }
        (*x)++; /* consume 'e' */
        n->v.d = d;
        n->t = DICT;
    } else {
        int l = 0;
        if (*x >= raw->len) return ERR;
        b = raw->vals[*x];
        while (b != ':') {
            l = l*10 + b - '0';
            (*x)++; /* consume digit */
            if (*x >= raw->len) return ERR;
            b = raw->vals[*x];
        }
        (*x)++; /* consume ':' */
        bytes *s = bytes_create(l+1);
        if (!s) return ERR;
        s->vals[s->cap-1] = 0;
        for (int k = *x; k < *x+l; k++) {
            if (k >= raw->len) return ERR;
            b = raw->vals[k];
            s->vals[s->len++] = b;
        }
        *x += l; /* consume all the bytes */
        n->v.s = s;
        n->t = BYTES;
    }
    return OK;
}

#define ELOOP_R 1<<0 /* reading */
#define ELOOP_W 1<<1 /* writing */
#define ELOOP_E 1<<2 /* expectional */

typedef struct event event; 
typedef struct eloop eloop; 

typedef void event_cb(int r, event *e);

typedef struct event {
    int fd;  
    int mask;
    bytes *buf;
    event *next;
    event *prev;
    event_cb *cb;
    void *data;
} event;

typedef struct eloop {
    event *head;
    event *tail;
} eloop;

int eloop_add(eloop *l, int fd, int mask, event_cb *cb, bytes *buf, void *data) {
    event *e = malloc(sizeof(event));
    if (!e) return ERR;
    memset(e, 0, sizeof(event));
    e->fd = fd;
    e->mask = mask;
    e->cb = cb;
    e->buf = buf;
    e->data = data;

    if (!l->head && !l->tail) {
        l->head = e;
        l->tail = e;
    } else {
        l->tail->next = e;
        e->prev = l->tail;
        l->tail = e;
    }
    return OK;
}

void eloop_rm(eloop *l, event *e) {
    assert(l->head);
    assert(l->tail);
    if (e->prev) {
        if (e == l->tail) l->tail = e->prev;
        e->prev->next = e->next;
    }
    if (e->next) {
        if (e == l->head) l->head = e->next;
        e->next->prev = e->prev;
    }
    if (!e->prev && !e->next) {
        assert(l->head == e);
        assert(l->tail == e);
        l->head = NULL;
        l->tail = NULL;
    }
    free(e);
}

int eloop_proc(eloop *l) {
    int r;
    /* file descriptor sets to fill with select call */
    fd_set rfds, wfds, efds;

    /* initialize sets */
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    event *e = l->head;
    int maxfd = 0;
    /* add fd to sets and track maxfd */
    while (e) {
        if (e->fd & ELOOP_R) FD_SET(e->fd, &rfds);
        if (e->fd & ELOOP_W) FD_SET(e->fd, &wfds);
        if (e->fd & ELOOP_E) FD_SET(e->fd, &efds);
        if (e->fd > maxfd) maxfd = e->fd;
        e = e->next;
    }

    r = select(maxfd+1, &rfds, &wfds, &efds, NULL);
    /* error occured */
    if (r == -1) return ERR;
    /* nothing to process */
    if (r ==  0) return OK;
    /* start from head */
    e = l->head;
    while (e) {
        if (e->mask & ELOOP_R && FD_ISSET(e->fd, &rfds) ||
            e->mask & ELOOP_W && FD_ISSET(e->fd, &wfds) ||
            e->mask & ELOOP_E && FD_ISSET(e->fd, &efds))
        {
            /* execute registered callback */
            e->cb(OK, e);
            /* clear sets */
            FD_CLR(e->fd, &rfds);
            FD_CLR(e->fd, &wfds);
            FD_CLR(e->fd, &efds);
            eloop_rm(l, e);
            /* start from the begining */
            e = l->head;
        } else {
            e = e->next;
        }     
    }
    return OK;
}

int eloop_run(eloop *l) {
    int r;
    /* util event loop is not empty, process */
    while (l->head) {
        r = eloop_proc(l);
        if (r) return r;
    }
    return OK;
}

eloop L; 

int resolve(struct addrinfo **info, char *host, char *port, int socktype) {
    int r;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    return getaddrinfo(host, port, &hints, info);
}

void t_recv_rec(int r, event *e) {
    event_cb *cb = e->data;
    if (r) goto error;
    ssize_t n = recv(e->fd, e->buf->vals, e->buf->cap, MSG_NOSIGNAL);
    if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        r = eloop_add(&L, e->fd, e->mask, t_recv_rec, e->buf, e->data);
        if (r) goto error;
    } else if (n == -1) {
        goto error;
    } else if (n < e->buf->cap) {
        e->buf->len += n;
        t_recv_rec(r, e);
    } else {
        cb(r, e);
    }
    return;
error:
    cb(ERR, e);
}

void t_send_rec(int r, event *e) {
    event_cb *cb = e->data;
    if (r) goto error;
    ssize_t n = send(e->fd, e->buf->vals, e->buf->len, MSG_NOSIGNAL);
    if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        r = eloop_add(&L, e->fd, e->mask, t_send_rec, e->buf, e->data);
        if (r) goto error;
    } else if (n == -1) {
        goto error;
    } else if (n < e->buf->len) {
        e->buf->vals += n;
        e->buf->len -= n;
        t_send_rec(r, e);
    } else {
        cb(r, e);
    }
    return;
error:
    cb(ERR, e);
}

void t_recv(int fd, bytes *buf, event_cb *cb) {
    event e = {.fd = fd, .mask = ELOOP_R, .buf = buf, 
        .cb = cb, .data = cb, .next = NULL, .prev = NULL};
    t_recv_rec(OK, &e);
}

void t_send(int fd, bytes *buf, event_cb *cb) {
    event e = {.fd = fd, .mask = ELOOP_W, .buf = buf, 
        .cb = cb, .data = cb, .next = NULL, .prev = NULL};
    t_send_rec(OK, &e);
}

int t_conn(struct addrinfo *info, event_cb *cb) {
    int r = OK;
    struct addrinfo *p = info;
    for (; p; p = p->ai_next) {
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == -1) continue;
        r = fcntl(fd, F_SETFL, O_NONBLOCK);
        if (r == -1) {
            close(fd);
            continue;
        }
        r = connect(fd, p->ai_addr, p->ai_addrlen);
        if (r == -1 && errno != EINPROGRESS) {
            close(fd);
            continue;
        }
        r = eloop_add(&L, fd, ELOOP_W, cb, NULL, NULL);
        if (r) close(fd);
        break;
    }
    freeaddrinfo(info);
    return r;
}

int readbin(char *name, bytes *buf) {
    FILE *f = fopen(name, "rb");
    if (!f) return ERR;
    size_t r = fread(buf->vals, 1, buf->cap, f);
    if (ferror(f)) return ERR;
    if (!feof(f)) return ERR;
    buf->len = r;
    fclose(f);
    return OK;
}

int gen_infohash(dict *info, unsigned char h[20]) {
    int r;
    node n = {.v.d = info, .t = DICT};
    bytes *buf = bytes_create(2*1024*1024);
    if (!buf) return ERR;
    r = encode(buf, &n);
    if (r) {
    	bytes_free(buf);
	    return r;
    }
    sha1((unsigned char *) buf->vals, buf->len, h);
    bytes_free(buf);
    return OK;
}

#define BLOCKSIZE 16384

typedef struct file {
    char *path;
    int len;
} file;

typedef struct peer {
    char id[20];
    char ip[40];
    char port[6];
} peer;

typedef struct piece {
    int i;
    int len;
    char s[BLOCKSIZE];
    bytes buf;
    int downloaded;
    int requested;
} piece;

typedef struct tnt {
    dict *metainfo;
    int left;
    int uploaded;
    int downloaded;
    char *announce;
    int len;
    int piecelen;
    file *files;
    piece *pieces;
    bytes *hashes;
    int npieces;
    unsigned char infohash[20];
} tnt;

tnt *tnt_create(dict *mi, unsigned char infohash[20]) {
    tnt *t = malloc(sizeof(tnt));
    if (!t) return NULL;
    memset(t, 0, sizeof(tnt));

    node *n;
    dict *info;

    n = dict_get(mi, "info");
    assert(n != NULL);
    info = n->v.d;

    n = dict_get(mi, "announce");
    if (n) t->announce = n->v.s->vals;

    n = dict_get(info, "piece length");
    assert(n != NULL);
    t->piecelen = n->v.i;

    n = dict_get(info, "pieces");
    assert(n != NULL);
    t->hashes = n->v.s;

    n = dict_get(info, "files");
    if (n) {
        file *files = malloc(sizeof(file) * n->v.l->len);
        if (!files) {
            free(t);
            return NULL;
        }

        node *nf, *np, *nl;
        for (int i = 0; i < n->v.l->len; i++) {
            nf = &n->v.l->vals[i];
            np = dict_get(nf->v.d, "path");
            nl = dict_get(nf->v.d, "length");
            assert(np != NULL);
            assert(nl != NULL);
            files[i].len = nl->v.i;
            files[i].path = np->v.s->vals;
            t->len += nl->v.i;
        }
        t->files = files;
    } else {
        file *files = malloc(sizeof(file));
        if (!files) {
            free(t);
            return NULL;
        }

        node *np, *nl;
        np = dict_get(info, "name");
        nl = dict_get(info, "length");
        assert(np != NULL);
        assert(nl != NULL);
        files[0].len = nl->v.i; 
        files[0].path = np->v.s->vals;
        t->len = nl->v.i;
        t->files = files;
    }

    int npieces = t->hashes->len / 20;
    t->pieces = malloc(sizeof(piece) * npieces);
    if (!t->pieces) {
        free(t->files);
        free(t);
        return NULL;
    }
    for (int i = 0; i < npieces; i++) {
        t->pieces[i].i = i;
        t->pieces[i].len = t->piecelen; 
        t->pieces[i].downloaded = 0;
        memset(t->pieces[i].s, 0, BLOCKSIZE);
        t->pieces[i].buf.vals = t->pieces[i].s;
        t->pieces[i].buf.len = 0;
        t->pieces[i].buf.cap = 0;
        t->pieces[i].requested = 0;
    }
    t->pieces[npieces-1].len = t->len - t->piecelen * (npieces-1);
    t->npieces = npieces;

    t->left = t->len;
    t->downloaded = 0;
    t->uploaded = 0;
    t->metainfo = mi;
    memcpy(t->infohash, infohash, 20);

    return t;
}

void tnt_free(tnt *t) {
    if (!t) return;
    dict_free(t->metainfo);
    free(t->files);
    free(t->pieces);
    free(t);
}

#define HTTP 1
#define HTTPS 2
#define UDP 3
#define DHT 4

void split_uri(char *uri, int *proto, char host[256], char port[6], char path[1024]) {
    if (!uri) {
        *proto = DHT;
        return;
    }
    int len = strlen(uri);
    assert(len > 0);
    int i = 0, j = 0;
    while (uri[i++] != ':')
        assert(len > i);
    i--;
    if (!strncmp(uri, "http", i))
        *proto = HTTP;
    else if (!strncmp(uri, "https", i))
        *proto = HTTPS;
    else if (!strncmp(uri, "udp", i))
        *proto = UDP;
    i += 3;
    assert(len > i);
    j = 0;
    while (uri[i] != ':' && uri[i] != '/') {
        host[j] = uri[i];
        i++;
        j++;
        assert(len > i);
    }
    host[j] = 0;
    j = 0;
    if (uri[i] == ':') {
        i++;
        while (i < len && uri[i] != '/') {
            port[j] = uri[i];
            i++;
            j++;
        }
        port[j] = 0;
    }
    j = 0;
    while (i < len && uri[i] != '?') {
        path[j] = uri[i];
        i++;
        j++;
    }
    path[j] = 0;
}

int discov_peers_http(struct addrinfo *info, tnt *t) {
    return OK;
}

int discov_peers(tnt *t) {
    int r;
    int proto;
    char host[256];
    char port[6];
    char path[1024];
    split_uri(t->announce, &proto, host, port, path);
    if (proto == HTTP) {
        struct addrinfo *info = NULL;
        r = resolve(&info, host, port, SOCK_STREAM);
        if (r) {
            E("couldn't resolve DNS for '%s': %s", host, gai_strerror(r));
            return ERR;
        }
        return discov_peers_http(info, t);
    } else {
        E("tracker protocol is not supported");
        return ERR;
    }
    return OK;
}

int main(int argc, char **argv) {
    int r;

    if (argc != 2) {
        fprintf(stderr, "%s [torrent]\n", argv[0]);
        return 1;
    }

    node n;
    int x = 0;
    bytes *buf = bytes_create(2*1024*1024);
    char *filename = argv[1];
    r = readbin(filename, buf);
    if (r) {
        E("couldn't read file: %s", filename);
        goto error;
    }
    r = decode(buf, &n, &x);
    if (r) {
        E("couldn't decode file: %s", filename);
        goto error;
    }

    node *info = dict_get(n.v.d, "info");
    assert(info != NULL);
    unsigned char infohash[20];
    r = gen_infohash(info->v.d, infohash);
    if (r) {
        E("couldn't generate infohash for file: %s", filename);
        goto error;
    }

    tnt *t = tnt_create(n.v.d, infohash);
    if (!t) goto error;

    r = discov_peers(t);
    if (r) goto error;
    
    r = eloop_run(&L);
    if (r) {
        E("runtime failed");
        goto error;
    }

    tnt_free(t);
    bytes_free(buf);
    return 0;
error:
    tnt_free(t);
    bytes_free(buf);
    return 1;
}
