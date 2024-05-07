#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define OK 0
#define ERR 1

#define LOG(lvl, ...)                                             \
    do {                                                          \
        printf("%c:%3d| ", lvl, __LINE__);                        \
        printf(__VA_ARGS__);                                      \
        if (lvl == 'E' && errno) printf(": %s", strerror(errno)); \
        printf("\n");                                             \
    } while (0)

#define I(...) LOG('I', __VA_ARGS__)
#define D(...) LOG('D', __VA_ARGS__)
#define E(...) LOG('E', __VA_ARGS__)

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

void sha1(char *vals, size_t len, char out[20]) {
    uint32_t a = 0x67452301;
    uint32_t b = 0xEFCDAB89;
    uint32_t c = 0x98BADCFE;
    uint32_t d = 0x10325476;
    uint32_t e = 0xC3D2E1F0;
    uint32_t tmp, f, k, w[80];
    for (size_t i = 0; i < len+9; i += 64) {
        for (size_t t = 0; t < 16; t++) {
            if (i + t < len)
                w[t] = vals[i+t] & 0xFF;
            else if (i + t == len)
                w[t] = 0x80;
            else
                w[t] = 0;
        }
        for (size_t t = 16; t < 80; t++)
            w[t] = ROTL(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
        uint32_t h[5] = {a, b, c, d, e};
        for (size_t t = 0; t < 80; t++) {
            if (t < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            tmp = ROTL(a, 5) + f + e + k + w[t];
            e = d;
            d = c;
            c = ROTL(b, 30);
            b = a;
            a = tmp;
        }
        uint32_t hash[20/4];
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        memcpy(out, hash, 20);
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
    b->len = 0;
    b->cap = cap;
    memset(b->vals, 0, cap);
    return b;
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
            bytes s = {.vals = k, s.cap = KEY_LEN};
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
            free(k.v.s);
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
        bytes *s = bytes_create(l);
        if (!s) return ERR;
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

int gen_infohash(dict *info) {
    int r;
    node n = {.v.d = info, .t = DICT};
    bytes *buf = bytes_create(2*1024*1024);
    if (!buf) return ERR;
    r = encode(buf, &n);
    if (r) return r;
    char h[20];
    sha1(buf->vals, buf->len, h);
    free(buf);
    return OK;
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

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "%s [torrent]\n", argv[0]);
        return 1;
    }
    int r;
    bytes *buf = bytes_create(2*1024*1024);
    bytes *fub = bytes_create(2*1024*1024);
    char *filename = argv[1];
    r = readbin(filename, buf);
    if (r) E("error reading file: %s", filename);
    int x = 0;
    node n;
    memset(&n, 0, sizeof(node));
    r = decode(buf, &n, &x);
    if (r) E("error decoding file: %s", filename);
    r = encode(fub, &n);
    if (r) E("error encoding node");
    assert(buf->len == fub->len);
    for (int i = 0; i < buf->len; i++)
        assert(buf->vals[i] == fub->vals[i]);
    node *info = dict_get(n.v.d, "info");
    assert(info != NULL);
    gen_infohash(info->v.d);
    return 0;
}