/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2015, 2019 Nicira, Inc.
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

#include <config.h>
#include "openvswitch/hmap.h"
#include <stdint.h>
#include <string.h>
#include "coverage.h"
#include "random.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(hmap);

COVERAGE_DEFINE(hmap_pathological);
COVERAGE_DEFINE(hmap_expand);
COVERAGE_DEFINE(hmap_shrink);
COVERAGE_DEFINE(hmap_reserve);

/* Initializes 'hmap' as an empty hash table. */
void
hmap_init(struct hmap *hmap)
{
    memset(&hmap->one, 0, sizeof(hmap->one));
    hmap->buckets = &hmap->one;
    hmap->mask = 0;
    hmap->n = 0;
}

/* Frees memory reserved by 'hmap'.  It is the client's responsibility to free
 * the nodes themselves, if necessary. */
void
hmap_destroy(struct hmap *hmap)
{
    if (!hmap) {
        return;
    }
    for (size_t i = 0; i <= hmap->mask; i++) {
        struct bucket *bucket = &hmap->buckets[i];
        while (bucket->bitfield & (1 << 7)) {
            struct bucket *child = (struct bucket *) bucket->nodes[6];
            if (bucket != &hmap->buckets[i]) {
                free(bucket);
            }
            bucket = child;
        }
        if (bucket != &hmap->buckets[i]) {
            free(bucket);
        }
    }
    if (hmap->buckets != &hmap->one) {
        free(hmap->buckets);
    }
}

/* Removes all node from 'hmap', leaving it ready to accept more nodes.  Does
 * not free memory allocated for 'hmap'.
 *
 * This function is appropriate when 'hmap' will soon have about as many
 * elements as it did before.  If 'hmap' will likely have fewer elements than
 * before, use hmap_destroy() followed by hmap_init() to save memory and
 * iteration time. */
void
hmap_clear(struct hmap *hmap)
{
    if (!hmap->n) {
        return;
    }
    /* Fix, this is so redundant */
    for (size_t i = 0; i <= hmap->mask; i++) {
        struct bucket *bucket = &hmap->buckets[i];
        while (bucket->bitfield & (1 << 7)) {
            memset(bucket->hash_byte, 0, sizeof bucket->hash_byte);
            bucket->bitfield &= ~((1 << 7) - 1);
            /* I guess setting the node *s to null isn't needed but it feels good */
            for (size_t j = 0; j < 6; j++) {
                bucket->nodes[j] = NULL;
            }
            bucket = (struct bucket*) bucket->nodes[6];
        }
        memset(bucket->hash_byte, 0, sizeof bucket->hash_byte);
        bucket->bitfield &= ~((1 << 7) - 1);
        /* I guess setting the node *s to null isn't needed but it feels good */
        for (size_t j = 0; j < 6; j++) {
            bucket->nodes[j] = NULL;
        }
    }
    hmap->n = 0;
}

/* Exchanges hash maps 'a' and 'b'. */
void
hmap_swap(struct hmap *a, struct hmap *b)
{
    struct hmap tmp = *a;
    *a = *b;
    *b = tmp;
    hmap_moved(a);
    hmap_moved(b);
}

/* Adjusts 'hmap' to compensate for having moved position in memory (e.g. due
 * to realloc()). */
void
hmap_moved(struct hmap *hmap)
{
    if (!hmap->mask) {
        hmap->buckets = &hmap->one;
    }
}

static void
resize(struct hmap *hmap, size_t new_mask, const char *where)
{
    struct hmap tmp;
    size_t i;

    ovs_assert(is_pow2(new_mask + 1));

    hmap_init(&tmp);
    if (new_mask) {
        size_t bucket_count = new_mask + 1;
        tmp.buckets = malloc(bucket_count * sizeof *tmp.buckets);
        tmp.mask = new_mask;
        memset(tmp.buckets, 0, bucket_count * sizeof *tmp.buckets);
    }
    int n_big_buckets = 0;
    int biggest_count = 0;
    int n_biggest_buckets = 0;
    for (i = 0; i <= hmap->mask; i++) {
        struct hmap_node *node, copy;
        int count = 0;
        for (node = hmap_first_in_bucket(hmap, i); node;
             node = hmap_next_in_bucket(hmap, &copy)) {
            copy = *node;
            hmap_insert_fast(&tmp, node, node->hash);
            count++;
        }
        if (count > 6) {
            n_big_buckets++;
            if (count > biggest_count) {
                biggest_count = count;
                n_biggest_buckets = 1;
            } else if (count == biggest_count) {
                n_biggest_buckets++;
            }
        }
    }
    hmap_swap(hmap, &tmp);
    hmap_destroy(&tmp);

    if (n_big_buckets) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
        COVERAGE_INC(hmap_pathological);
        VLOG_DBG_RL(&rl, "%s: %d bucket%s with 6+ nodes, "
                    "including %d bucket%s with %d nodes "
                    "(%"PRIuSIZE" nodes total across %"PRIuSIZE" buckets)",
                    where,
                    n_big_buckets, n_big_buckets > 1 ? "s" : "",
                    n_biggest_buckets, n_biggest_buckets > 1 ? "s" : "",
                    biggest_count,
                    hmap->n, hmap->mask + 1);
    }
}

static size_t
calc_mask(size_t capacity)
{
    size_t mask = capacity / 6;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
#if SIZE_MAX > UINT32_MAX
    mask |= mask >> 32;
#endif

    /* If we need to dynamically allocate buckets we might as well allocate at
     * least 4 of them. */
    mask |= (mask & 1) << 1;

    return mask;
}

/* Expands 'hmap', if necessary, to optimize the performance of searches.
 *
 * ('where' is used in debug logging.  Commonly one would use hmap_expand() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
void
hmap_expand_at(struct hmap *hmap, const char *where)
{
    size_t new_mask = calc_mask(hmap->n);
    if (new_mask > hmap->mask) {
        COVERAGE_INC(hmap_expand);
        resize(hmap, new_mask, where);
    }
}

/* Shrinks 'hmap', if necessary, to optimize the performance of iteration.
 *
 * ('where' is used in debug logging.  Commonly one would use hmap_shrink() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
void
hmap_shrink_at(struct hmap *hmap, const char *where)
{
    size_t new_mask = calc_mask(hmap->n);
    if (new_mask < hmap->mask) {
        COVERAGE_INC(hmap_shrink);
        resize(hmap, new_mask, where);
    }
}

/* Expands 'hmap', if necessary, to optimize the performance of searches when
 * it has up to 'n' elements.  (But iteration will be slow in a hash map whose
 * allocated capacity is much higher than its current number of nodes.)
 *
 * ('where' is used in debug logging.  Commonly one would use hmap_reserve() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
void
hmap_reserve_at(struct hmap *hmap, size_t n, const char *where)
{
    size_t new_mask = calc_mask(n);
    if (new_mask > hmap->mask) {
        COVERAGE_INC(hmap_reserve);
        resize(hmap, new_mask, where);
    }
}

/* Adjusts 'hmap' to compensate for 'old_node' having moved position in memory
 * to 'node' (e.g. due to realloc()). */
void
hmap_node_moved(struct hmap *hmap,
                struct hmap_node *old_node, struct hmap_node *node)
{
    struct bucket *bucket = &hmap->buckets[node->hash & hmap->mask];

    size_t index_diff = node->index;
    if (!bucket_descend(&bucket, &index_diff)) {
        return;
    }

    if (bucket->nodes[index_diff] == old_node) {
        bucket->nodes[index_diff] = node;
        bucket->hash_byte[index_diff] = (uint8_t) (node->hash >> 24) & 0xFF;
    }
}

/* Chooses and returns a randomly selected node from 'hmap', which must not be
 * empty.
 *
 * I wouldn't depend on this algorithm to be fair, since I haven't analyzed it.
 * But it does at least ensure that any node in 'hmap' can be chosen. */
struct hmap_node *
hmap_random_node(const struct hmap *hmap)
{
    struct hmap_node *node;
    size_t random_bucket_idx;

    /* Choose a random non-empty bucket. Save its index. */
    for (;;) {
        random_bucket_idx = random_uint32() & hmap->mask;
        if (hmap_first_in_bucket(hmap, random_bucket_idx)) {
            break;
        }
    }

    /* Find the number of nodes in the bucket. */
    size_t node_count = 0;
    for (node = hmap_first_in_bucket(hmap, random_bucket_idx); node;
         node = hmap_next_in_bucket(hmap, node)) {
        node_count++;
    }

    if (!node_count) {
        return NULL;
    }

    /* Choose a random index and get that node. */
    node = hmap_first_in_bucket(hmap, random_bucket_idx);
    size_t random_node_idx = random_uint32() % node_count;
    for (size_t i = 0; i < random_node_idx; i++) {
        node = hmap_next_in_bucket(hmap, node);
    }

    return node;
}

/* Returns the next node in 'hmap' in hash order, or NULL if no nodes remain in
 * 'hmap'.  Uses '*pos' to determine where to begin iteration, and updates
 * '*pos' to pass on the next iteration into them before returning.
 *
 * It's better to use plain HMAP_FOR_EACH and related functions, since they are
 * faster and better at dealing with hmaps that change during iteration.
 *
 * Before beginning iteration, set '*pos' to all zeros. */
struct hmap_node *
hmap_at_position(const struct hmap *hmap,
                 struct hmap_position *pos)
{
    size_t offset;
    size_t b_idx;

    offset = pos->offset;
    for (b_idx = pos->bucket; b_idx <= hmap->mask; b_idx++) {
        struct hmap_node *node = hmap_first_in_bucket(hmap, b_idx);
        size_t n_idx;

        for (n_idx = 0; node != NULL;
             n_idx++, node = hmap_next_in_bucket(hmap, node)) {
            if (n_idx == offset) {
                if (hmap_next_in_bucket(hmap, node)) {
                    pos->bucket = node->hash & hmap->mask;
                    pos->offset = offset + 1;
                } else {
                    pos->bucket = (node->hash & hmap->mask) + 1;
                    pos->offset = 0;
                }
                return node;
            }
        }
        offset = 0;
    }

    pos->bucket = 0;
    pos->offset = 0;
    return NULL;
}

/* Returns true if 'node' is in 'hmap', false otherwise. */
bool
hmap_contains(const struct hmap *hmap, const struct hmap_node *node)
{
    struct hmap_node *p;

    for (p = hmap_first_in_bucket(hmap, node->hash); p;
         p = hmap_next_in_bucket(hmap, p)) {
        if (p == node) {
            return true;
        }
    }

    return false;
}

void hmap_insert_child(struct hmap *hmap, struct hmap_node *node, size_t hash)
{
    struct bucket *bucket = &hmap->buckets[hash & hmap->mask];
    size_t bucket_count = 0;
    while (bucket) {
        uint8_t inverted_bits = ~(bucket->bitfield);
        size_t index = rightmost_1bit_idx((uint64_t) inverted_bits);
        if (index == 6 && bucket->bitfield & (1 << 7)) {
            bucket = (struct bucket *) bucket->nodes[6];
            bucket_count++;
        } else if (index == 7) {
            /* Save a pointer to the node being moved to child bucket. */
            struct bucket *tmp = (struct bucket *) bucket->nodes[6];

            /* Set child bucket status bit as 1. */
            bucket->bitfield |= (1 << 7);

            /* Save the hash byte before clearing it. */
            uint8_t tmp_hash_byte = bucket->hash_byte[6];

            /* Set hash byte and presence bit as 0. */
            bucket->hash_byte[6] = 0;
            bucket->bitfield &= ~(1 << 6);

            /* Clear out node to make room for child bucket. */
            bucket->nodes[6] = (struct bucket *) malloc(sizeof *bucket);
            bucket = (struct bucket *) bucket->nodes[6];
            memset(bucket, 0, sizeof(struct bucket));

            /* Set child bucket's first node to be the one I moved. */
            bucket->nodes[0] = (void *)tmp;

            /* Set appropriate presence bit. */
            bucket->bitfield |= 1;

            /* Restore hash byte in child bucket. */
            bucket->hash_byte[0] = tmp_hash_byte;
            bucket->nodes[1] = node;

            /* Get one byte of hash and add it to the hash byte array. */
            bucket->hash_byte[1] = (uint8_t) ((hash >> 24) & 0xFF);
            node->hash = hash;

            /* Calculate the node's index.
             * Bucket #0:   0   1   2   3   4   5
             * Bucket #1:   6   7   8   9  10  11
             * Bucket #3:  12  13  14  15  16  17  18
             * etc. */
            node->index = 6 * (bucket_count + 1) + 1;

            bucket->bitfield |= (1 << 1);
            hmap->n++;
            return;
        } else if (index <= 6) {
            /* Insert as normal at index. */
            bucket->nodes[index] = node;

            /* Get one byte of hash and add it to the hash byte array. */
            bucket->hash_byte[index] = (uint8_t) ((hash >> 24) & 0xFF);
            node->hash = hash;

            /* Calculate the node's index.
             * Bucket #0:  0  1  2  3  4  5
             * Bucket #1:  6  7  8  9 10 11
             * Bucket #3: 12 13 14 15 16 17 18 */
            node->index = 6 * bucket_count + index;

            bucket->bitfield |= (1 << index);
            hmap->n++;
            return;
        }
    }
}
