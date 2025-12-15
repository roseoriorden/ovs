/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2015, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HMAP_H
#define HMAP_H 1

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "openvswitch/util.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* A hash map node, to be embedded inside the data structure being mapped. */
struct hmap_node {
    uint32_t hash;                /* Hash value. */
    uint32_t index;               /* The position within the bucket layout */
};

/* Returns the hash value embedded in 'node'. */
static inline size_t hmap_node_hash(const struct hmap_node *node)
{
    return node->hash;
}

#define HMAP_NODE_NULL -1
#define HMAP_NODE_NULL_INITIALIZER { 0, HMAP_NODE_NULL }

/* Returns true if 'node' has been set to null by hmap_node_nullify() and has
 * not been un-nullified by being inserted into an hmap. */
static inline bool
hmap_node_is_null(const struct hmap_node *node)
{
    return node->index == HMAP_NODE_NULL;
}

/* Marks 'node' with a distinctive value that can be tested with
 * hmap_node_is_null().  */
static inline void
hmap_node_nullify(struct hmap_node *node)
{
    node->index = HMAP_NODE_NULL;
}

struct bucket {
    uint8_t bitfield;           /* The child bucket and presence bits. */
    uint8_t hash_byte[7];       /* A byte of hash for each entry. */
    void *nodes[7];             /* Pointers to nodes. The last spot can instead
                                   point to a child bucket. */
};

/* A hash map. */
struct hmap {
    struct bucket *buckets; /* Must point to 'one' iff 'mask' == 0. */
    struct bucket one;
    size_t mask;
    size_t n;
};

/* Initializer for an empty hash map. */
#define HMAP_INITIALIZER(HMAP) \
    { (struct bucket *const) &(HMAP)->one, {0}, 0, 0 }

/* Initializer for an immutable struct hmap 'HMAP' that contains 'N' nodes
 * linked together starting at 'NODE'.  The hmap only has a single chain of
 * hmap_nodes, so 'N' should be small. */
#define HMAP_CONST(HMAP, N, NODE) {                                 \
        CONST_CAST(struct bucket *, &(HMAP)->one), NODE, 0, N }

/* Initialization. */
void hmap_init(struct hmap *);
void hmap_destroy(struct hmap *);
void hmap_clear(struct hmap *);
void hmap_swap(struct hmap *a, struct hmap *b);
void hmap_moved(struct hmap *hmap);
static inline size_t hmap_count(const struct hmap *);
static inline bool hmap_is_empty(const struct hmap *);

/* Adjusting capacity. */
void hmap_expand_at(struct hmap *, const char *where);
#define hmap_expand(HMAP) hmap_expand_at(HMAP, OVS_SOURCE_LOCATOR)

void hmap_shrink_at(struct hmap *, const char *where);
#define hmap_shrink(HMAP) hmap_shrink_at(HMAP, OVS_SOURCE_LOCATOR)

void hmap_reserve_at(struct hmap *, size_t capacity, const char *where);
#define hmap_reserve(HMAP, CAPACITY) \
    hmap_reserve_at(HMAP, CAPACITY, OVS_SOURCE_LOCATOR)

/* Insertion and deletion. */
static inline void hmap_insert_at(struct hmap *, struct hmap_node *,
                                  uint32_t hash, const char *where);
#define hmap_insert(HMAP, NODE, HASH) \
    hmap_insert_at(HMAP, NODE, HASH, OVS_SOURCE_LOCATOR)

static inline void hmap_insert_fast(struct hmap *,
                                    struct hmap_node *, uint32_t hash);
static inline bool bucket_descend(struct bucket **bucket, uint32_t *index);
static inline void hmap_remove(struct hmap *, struct hmap_node *);

void hmap_node_moved(struct hmap *, struct hmap_node *, struct hmap_node *);
static inline void hmap_replace(struct hmap *, const struct hmap_node *old,
                                struct hmap_node *new_node);

struct hmap_node *hmap_random_node(const struct hmap *);

/* Search.
 *
 * HMAP_FOR_EACH_WITH_HASH iterates NODE over all of the nodes in HMAP that
 * have hash value equal to HASH.  HMAP_FOR_EACH_IN_BUCKET iterates NODE over
 * all of the nodes in HMAP that would fall in the same bucket as HASH.  MEMBER
 * must be the name of the 'struct hmap_node' member within NODE.
 *
 * These macros may be used interchangeably to search for a particular value in
 * an hmap, see, e.g. shash_find() for an example.  Usually, using
 * HMAP_FOR_EACH_WITH_HASH provides an optimization, because comparing a hash
 * value is usually cheaper than comparing an entire hash map key.  But for
 * simple hash map keys, it makes sense to use HMAP_FOR_EACH_IN_BUCKET because
 * it avoids doing two comparisons when a single simple comparison suffices.
 *
 * The loop should not change NODE to point to a different node or insert or
 * delete nodes in HMAP (unless it "break"s out of the loop to terminate
 * iteration).
 *
 * HASH is only evaluated once.
 *
 * When the loop terminates normally, meaning the iteration has completed
 * without using 'break', NODE will be NULL.  This is true for all of the
 * HMAP_FOR_EACH_*() macros.
 */
#define HMAP_FOR_EACH_WITH_HASH(NODE, MEMBER, HASH, HMAP)                     \
    for (INIT_MULTIVAR(NODE, MEMBER, hmap_first_with_hash(HMAP, HASH),        \
                       struct hmap_node);                                     \
         CONDITION_MULTIVAR(NODE, MEMBER, ITER_VAR(NODE) != NULL);            \
         UPDATE_MULTIVAR(NODE, hmap_next_with_hash(HMAP, ITER_VAR(NODE))))

#define HMAP_FOR_EACH_IN_BUCKET(NODE, MEMBER, HASH, HMAP)                     \
    for (INIT_MULTIVAR(NODE, MEMBER, hmap_first_in_bucket(HMAP, HASH),        \
                       struct hmap_node);                                     \
         CONDITION_MULTIVAR(NODE, MEMBER, ITER_VAR(NODE) != NULL);            \
         UPDATE_MULTIVAR(NODE, hmap_next_in_bucket(HMAP, ITER_VAR(NODE))))

static inline struct hmap_node *hmap_first_with_hash(const struct hmap *,
                                                     uint32_t hash);
static inline struct hmap_node *hmap_next_with_hash(const struct hmap *hmap,
                                                    const struct hmap_node
                                                    *node);
static inline struct hmap_node *hmap_first_in_bucket(const struct hmap *,
                                                     uint32_t hash);
static inline struct hmap_node *hmap_next_in_bucket(const struct hmap *hmap,
                                                    const struct hmap_node *);

bool hmap_contains(const struct hmap *, const struct hmap_node *);

/* Iteration.
 *
 * The *_INIT variants of these macros additionally evaluate the expressions
 * supplied following the HMAP argument once during the loop initialization.
 * This makes it possible for data structures that wrap around hmaps to insert
 * additional initialization into their iteration macros without having to
 * completely rewrite them.  In particular, it can be a good idea to insert
 * BUILD_ASSERT_TYPE checks for map and node types that wrap hmap, since
 * otherwise it is possible for clients to accidentally confuse two derived
 * data structures that happen to use the same member names for struct hmap and
 * struct hmap_node. */

/* Iterates through every node in HMAP. */
#define HMAP_FOR_EACH(NODE, MEMBER, HMAP) \
    HMAP_FOR_EACH_INIT(NODE, MEMBER, HMAP, (void) 0)
#define HMAP_FOR_EACH_INIT(NODE, MEMBER, HMAP, ...)                           \
    for (INIT_MULTIVAR_EXP(NODE, MEMBER, hmap_first(HMAP), struct hmap_node,  \
                           __VA_ARGS__);                                      \
         CONDITION_MULTIVAR(NODE, MEMBER, ITER_VAR(NODE) != NULL);            \
         UPDATE_MULTIVAR(NODE, hmap_next(HMAP, ITER_VAR(NODE))))

/* Safe when NODE may be freed (not needed when NODE may be removed from the
 * hash map but its members remain accessible and intact). */
#define HMAP_FOR_EACH_SAFE_LONG(NODE, NEXT, MEMBER, HMAP) \
    HMAP_FOR_EACH_SAFE_LONG_INIT (NODE, NEXT, MEMBER, HMAP, (void) NEXT)

#define HMAP_FOR_EACH_SAFE_LONG_INIT(NODE, NEXT, MEMBER, HMAP, ...)           \
    for (INIT_MULTIVAR_SAFE_LONG_EXP(NODE, NEXT, MEMBER, hmap_first(HMAP),    \
                                     struct hmap_node, __VA_ARGS__);          \
         CONDITION_MULTIVAR_SAFE_LONG(NODE, NEXT, MEMBER,                     \
                                      ITER_VAR(NODE) != NULL,                 \
                            ITER_VAR(NEXT) = hmap_next(HMAP, ITER_VAR(NODE)), \
                                      ITER_VAR(NEXT) != NULL);                \
         UPDATE_MULTIVAR_SAFE_LONG(NODE, NEXT))

/* Short versions of HMAP_FOR_EACH_SAFE. */
#define HMAP_FOR_EACH_SAFE_SHORT(NODE, MEMBER, HMAP)                          \
    HMAP_FOR_EACH_SAFE_SHORT_INIT (NODE, MEMBER, HMAP, (void) 0)

#define HMAP_FOR_EACH_SAFE_SHORT_INIT(NODE, MEMBER, HMAP, ...)                \
    for (INIT_MULTIVAR_SAFE_SHORT_EXP(NODE, MEMBER, hmap_first(HMAP),         \
                                      struct hmap_node, __VA_ARGS__);         \
         CONDITION_MULTIVAR_SAFE_SHORT(NODE, MEMBER,                          \
                                       ITER_VAR(NODE) != NULL,                \
                      ITER_NEXT_VAR(NODE) = hmap_next(HMAP, ITER_VAR(NODE))); \
         UPDATE_MULTIVAR_SAFE_SHORT(NODE))

#define HMAP_FOR_EACH_SAFE(...)                                               \
    OVERLOAD_SAFE_MACRO(HMAP_FOR_EACH_SAFE_LONG,                              \
                        HMAP_FOR_EACH_SAFE_SHORT,                             \
                        4, __VA_ARGS__)


/* Continues an iteration from just after NODE. */
#define HMAP_FOR_EACH_CONTINUE(NODE, MEMBER, HMAP) \
    HMAP_FOR_EACH_CONTINUE_INIT(NODE, MEMBER, HMAP, (void) 0)
#define HMAP_FOR_EACH_CONTINUE_INIT(NODE, MEMBER, HMAP, ...)                  \
    for (INIT_MULTIVAR_EXP(NODE, MEMBER, hmap_next(HMAP, &(NODE)->MEMBER),    \
                           struct hmap_node, __VA_ARGS__);                    \
         CONDITION_MULTIVAR(NODE, MEMBER, ITER_VAR(NODE) != NULL);            \
         UPDATE_MULTIVAR(NODE, hmap_next(HMAP, ITER_VAR(NODE))))

struct hmap_pop_helper_iter__ {
    size_t bucket;
    struct hmap_node *node;
};

static inline void
hmap_pop_helper__(struct hmap *hmap, struct hmap_pop_helper_iter__ *iter) {

    for (; iter->bucket <= hmap->mask; (iter->bucket)++) {
        struct hmap_node *node = hmap_first_in_bucket(hmap, iter->bucket);

        if (node) {
            hmap_remove(hmap, node);
            iter->node = node;
            return;
        }
    }
    iter->node = NULL;
}

#define HMAP_FOR_EACH_POP(NODE, MEMBER, HMAP)                                 \
    for (struct hmap_pop_helper_iter__ ITER_VAR(NODE) = { 0, NULL };          \
         hmap_pop_helper__(HMAP, &ITER_VAR(NODE)),                            \
         (ITER_VAR(NODE).node != NULL) ?                                      \
            (((NODE) = OBJECT_CONTAINING(ITER_VAR(NODE).node,                 \
                                         NODE, MEMBER)),1):                   \
            (((NODE) = NULL), 0);)

static inline struct hmap_node *hmap_first(const struct hmap *);
static inline struct hmap_node *hmap_next(const struct hmap *,
                                          const struct hmap_node *);

struct hmap_position {
    unsigned int bucket;
    unsigned int offset;
};

struct hmap_node *hmap_at_position(const struct hmap *,
                                   struct hmap_position *);

/* Returns the number of nodes currently in 'hmap'. */
static inline size_t
hmap_count(const struct hmap *hmap)
{
    return hmap->n;
}

/* Returns the maximum number of nodes that 'hmap' may hold before it should be
 * rehashed. */
static inline size_t
hmap_capacity(const struct hmap *hmap)
{
    return hmap->mask * 2 + 1;
}

/* Returns true if 'hmap' currently contains no nodes,
 * false otherwise.
 * Note: While hmap in general is not thread-safe without additional locking,
 * hmap_is_empty() is. */
static inline bool
hmap_is_empty(const struct hmap *hmap)
{
    return hmap->n == 0;
}

void hmap_insert_child(struct hmap *hmap, struct hmap_node *node, uint32_t hash);

/* Inserts 'node', with the given 'hash', into 'hmap'.  'hmap' is never
 * expanded automatically. */
static inline void
hmap_insert_fast(struct hmap *hmap, struct hmap_node *node, uint32_t hash)
{
    struct bucket *bucket = &hmap->buckets[hash & hmap->mask];

    /* Find the first empty position in the root bucket. */
    uint8_t inverted_bits = ~(bucket->bitfield);
    size_t empty_index = rightmost_1bit_idx((uint64_t) inverted_bits);

    if (OVS_UNLIKELY(empty_index > 5)) {
        hmap_insert_child(hmap, node, hash);
        return;
    }
    /* insert as normal at empty_index. */
    bucket->nodes[empty_index] = node;

    /* Grab the top byte of the hash and add it to the hash byte array. */
    bucket->hash_byte[empty_index] = (uint8_t) ((hash >> 24) & 0xFF);
    node->hash = hash;

    /* Calculate the node's index.
     * Bucket #0:   0   1   2   3   4   5
     * Bucket #1:   6   7   8   9  10  11
     * Bucket #3:  12  13  14  15  16  17  18
     * etc. */
    node->index = empty_index;

    /* Set the position bit. */
    bucket->bitfield |= (1 << empty_index);
    hmap->n++;
}

/* Inserts 'node', with the given 'hash', into 'hmap', and expands 'hmap' if
 * necessary to optimize search performance.
 *
 * ('where' is used in debug logging.  Commonly one would use hmap_insert() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
static inline void
hmap_insert_at(struct hmap *hmap, struct hmap_node *node, uint32_t hash,
               const char *where)
{
    hmap_insert_fast(hmap, node, hash);
    if (hmap->n / 6 > hmap->mask) {
        hmap_expand_at(hmap, where);
    }
}

static inline bool
bucket_descend(struct bucket **bucket, uint32_t *index) {
    if (*index < 6) {
        return true;
    }
    for (;;) {
        int sub = 7;
        if ((*bucket)->bitfield & (1 << 7)) {
            sub = 6;
        }
        if (*index < sub) {
            return true;
        }
        *index -= sub;
        if (sub == 7) {
            return false;
        }
        *bucket = (struct bucket *) (*bucket)->nodes[6];
    }
}

/* Removes 'node' from 'hmap'.  Does not shrink the hash table; call
 * hmap_shrink() directly if desired. */
static inline void
hmap_remove(struct hmap *hmap, struct hmap_node *node)
{
    struct bucket *bucket = &hmap->buckets[node->hash & hmap->mask];

    uint32_t index_diff = node->index;
    if (OVS_UNLIKELY(index_diff > 5)) {
        if (!bucket_descend(&bucket, &index_diff)) {
            return;
        }
    }

    if (bucket->nodes[index_diff] == node) {
        bucket->nodes[index_diff] = NULL;

        bucket->bitfield &= ~(1 << index_diff);
        bucket->hash_byte[index_diff] = 0;
        hmap->n--;
    }
}

/* Puts 'new_node' in the position in 'hmap' currently occupied by 'old_node'.
 * The 'new_node' must hash to the same value as 'old_node'.  The client is
 * responsible for ensuring that the replacement does not violate any
 * client-imposed invariants (e.g. uniqueness of keys within a map).
 *
 * Afterward, 'old_node' is not part of 'hmap', and the client is responsible
 * for freeing it (if this is desirable). */
static inline void
hmap_replace(struct hmap *hmap,
             const struct hmap_node *old_node, struct hmap_node *new_node)
{
    struct bucket *bucket = &hmap->buckets[old_node->hash & hmap->mask];

    uint32_t index = old_node->index;
    if (OVS_UNLIKELY(index > 5)) {
        if (!bucket_descend(&bucket, &index)) {
            return;
        }
    }

    bucket->nodes[index] = new_node;
    new_node->hash = old_node->hash;
    new_node->index = old_node->index;
    bucket->hash_byte[index] = (uint8_t) (old_node->hash >> 24) & 0xFF;
}

static inline struct hmap_node *
hmap_next_with_hash__(const struct hmap *hmap, uint32_t index, uint32_t hash)
{
    struct bucket *bucket = &hmap->buckets[hash & hmap->mask];
    if (OVS_UNLIKELY(index > 5)) {
        if (!bucket_descend(&bucket, &index)) {
            return NULL;
        }
    }

    uint8_t field = bucket->bitfield;
    if (index > 0) {
        field &= ~((1 << index) - 1);
    }

    while (field) {
        index = rightmost_1bit_idx(field);

        if (OVS_UNLIKELY(index == 7)) {
            /* The root bucket is full and there's a child bucket. Move on to
             * the child. */
            bucket = (struct bucket *) bucket->nodes[6];
            field = bucket->bitfield;
            continue;
        }

        /* Check if the hash byte matches. */
        if (((hash >> 24) & 0xFF) == bucket->hash_byte[index]) {
            /* Now compare the the nodes. */
            struct hmap_node *node = (struct hmap_node *) bucket->nodes[index];
            if (hash == node->hash) {
                return CONST_CAST(struct hmap_node *, node);
            }
        }
        /* If it doesn't match, unset that bit in field so it will check the
         * next bit on the next iteration. */
        field = zero_rightmost_1bit(field);
    }
    return NULL;
}

/* Returns the first node in 'hmap' with the given 'hash', or a null pointer if
 * no nodes have that hash value. */
static inline struct hmap_node *
hmap_first_with_hash(const struct hmap *hmap, uint32_t hash)
{
    return hmap_next_with_hash__(hmap, 0, hash);
}

static inline struct hmap_node *
hmap_next_in_bucket__(const struct hmap *hmap, uint32_t index, uint32_t hash)
{
    struct bucket *bucket = &hmap->buckets[hash & hmap->mask];
    if (OVS_UNLIKELY(index > 5)) {
        if (!bucket_descend(&bucket, &index)) {
            return NULL;
        }
    }

   /* Clear all bits up to but not including index. */
    uint8_t field = bucket->bitfield;
    if (index > 0) {
        field &= ~((1 << index) - 1);
    }

    while (field) {
        index = rightmost_1bit_idx(field);
        if (index <= 6) {
            struct hmap_node *node = (struct hmap_node *) bucket->nodes[index];
            return CONST_CAST(struct hmap_node *, node);
        } else if (index == 7) {
            /* There's no next node in the current bucket. So move onto the
             * child. */
            bucket = (struct bucket *) bucket->nodes[6];
            field = bucket->bitfield;
        }
    }
    return NULL;
}

/* Returns the first node in 'hmap' in the bucket in which the given 'hash'
 * would land, or a null pointer if that bucket is empty. */
static inline struct hmap_node *
hmap_first_in_bucket(const struct hmap *hmap, uint32_t hash)
{
    return hmap_next_in_bucket__(hmap, 0, hash);
}

/* Returns the next node in the same bucket as 'node', or a null pointer if
 * there are no more nodes in that bucket.
 *
 * If the hash map has been reallocated since 'node' was visited, some nodes
 * may be skipped; if new nodes with the same hash value have been added, they
 * will be skipped.  (Removing 'node' from the hash map does not prevent
 * calling this function, since node->next is preserved, although freeing
 * 'node' of course does.) */
static inline struct hmap_node *
hmap_next_in_bucket(const struct hmap *hmap, const struct hmap_node *node)
{
    return hmap_next_in_bucket__(hmap, node->index + 1, node->hash);
}

/* Returns the next node in the same hash map as 'node' with the same hash
 * value, or a null pointer if no more nodes have that hash value.
 *
 * If the hash map has been reallocated since 'node' was visited, some nodes
 * may be skipped; if new nodes with the same hash value have been added, they
 * will be skipped.  (Removing 'node' from the hash map does not prevent
 * calling this function, since node->next is preserved, although freeing
 * 'node' of course does.) */
static inline struct hmap_node *
hmap_next_with_hash(const struct hmap *hmap, const struct hmap_node *node)
{
    return hmap_next_with_hash__(hmap, node->index + 1, node->hash);
}

static inline struct hmap_node *
hmap_next__(const struct hmap *hmap, size_t start)
{
    size_t i;
    for (i = start; i <= hmap->mask; i++) {
        struct hmap_node *node = hmap_first_in_bucket(hmap, i);
        if (node) {
            return node;
        }
    }
    return NULL;
}

/* Returns the first node in 'hmap', in arbitrary order, or a null pointer if
 * 'hmap' is empty. */
static inline struct hmap_node *
hmap_first(const struct hmap *hmap)
{
    return hmap_next__(hmap, 0);
}

/* Returns the next node in 'hmap' following 'node', in arbitrary order, or a
 * null pointer if 'node' is the last node in 'hmap'.
 *
 * If the hash map has been reallocated since 'node' was visited, some nodes
 * may be skipped or visited twice.  (Removing 'node' from the hash map does
 * not prevent calling this function, since node->next is preserved, although
 * freeing 'node' of course does.) */
static inline struct hmap_node *
hmap_next(const struct hmap *hmap, const struct hmap_node *node)
{
    struct hmap_node *next = hmap_next_in_bucket(hmap, node);
    if (next) {
        return next;
    }
    return hmap_next__(hmap, (node->hash & hmap->mask) + 1);
}
#ifdef  __cplusplus
}
#endif

#endif /* hmap.h */
