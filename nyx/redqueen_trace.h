#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "qemu/osdep.h"

#include "nyx/khash.h"
#include <libxdc.h>

typedef unsigned __int128 uint128_t;
typedef uint128_t         khint128_t;

#define INIT_NUM_OF_STORED_TRANSITIONS 0xfffff

/*! @function
  @abstract     64-bit integer hash function
  @param  key   The integer [khint64_t]
  @return       The hash value [khint_t]
 */
#define kh_int128_hash_func(key)                     \
    (khint32_t)((key) >> 33 ^ (key) ^ (key) << 11) ^ \
        (((key >> 64)) >> 33 ^ ((key >> 64)) ^ ((key >> 64)) << 11)
/*! @function
  @abstract     64-bit integer comparison function
 */
#define kh_int128_hash_equal(a, b) ((a) == (b))

/*! @function
  @abstract     Instantiate a hash map containing 64-bit integer keys
  @param  name  Name of the hash table [symbol]
  @param  khval_t  Type of values [type]
 */
#define KHASH_MAP_INIT_INT128(name, khval_t)                      \
    KHASH_INIT(name, khint128_t, khval_t, 1, kh_int128_hash_func, \
               kh_int128_hash_equal)

KHASH_MAP_INIT_INT128(RQ_TRACE, uint64_t)

#define INIT_TRACE_IP 0xFFFFFFFFFFFFFFFFULL

typedef struct redqueen_trace_s {
    khash_t(RQ_TRACE) * lookup;
    size_t     num_ordered_transitions;
    size_t     max_ordered_transitions;
    uint128_t *ordered_transitions;
} redqueen_trace_t;

/* libxdc outputs no bitmap in trace mode */
void alt_bitmap_reset(void);
void alt_bitmap_init(void *ptr, uint32_t size);

redqueen_trace_t *redqueen_trace_new(void);
void              redqueen_trace_free(redqueen_trace_t *self);
void              redqueen_trace_register_transition(redqueen_trace_t   *self,
                                                     disassembler_mode_t mode,
                                                     uint64_t            from,
                                                     uint64_t            to);

void redqueen_trace_init(void);
void redqueen_set_trace_mode(void);
void redqueen_unset_trace_mode(void);

void redqueen_trace_flush(void);
void redqueen_trace_reset(void);
