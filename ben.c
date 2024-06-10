#include <assert.h>

#include "util.h"
#include "ben.h"

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
