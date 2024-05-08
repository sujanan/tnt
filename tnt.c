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

typedef int32_t i32;
typedef uint32_t u32;
#define ROTL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

int sha1(unsigned char *data, size_t len, unsigned char digest[20]) {
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
    char hex[41];
    char h[20];
    sha1(buf->vals, buf->len, h);
    D("%d", h[0]);
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