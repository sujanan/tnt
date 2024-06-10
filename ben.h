#ifndef BEN_H
#define BEN_H

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

int encode(struct bytes *raw, struct node *n);
int decode(struct bytes *raw, struct node *n, int *x);

#endif
