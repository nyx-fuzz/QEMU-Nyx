#include "qemu/osdep.h"

#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "sysemu/block-backend.h"
#include "nyx/debug.h"
#include "nyx/snapshot/block/block_cow.h"
#include "nyx/state/state.h"


// #define COW_CACHE_DEBUG
// #define COW_CACHE_VERBOSE

#define CHUNK_SIZE 0x1000
// 0x200
#define PAGE_MASK 0xFFFFFFFFFFFFF000

uint64_t global_cow_primary_size            = COW_CACHE_PRIMARY_MINIMUM_SIZE;
bool     global_cow_primary_size_adjustable = true;

void set_global_cow_cache_primary_size(uint64_t new_size)
{
    if (global_cow_primary_size_adjustable &&
        new_size > COW_CACHE_PRIMARY_MINIMUM_SIZE && (new_size & 0xFFF) == 0)
    {
        global_cow_primary_size            = new_size;
        global_cow_primary_size_adjustable = false;
    }
}

static inline uint64_t get_global_cow_cache_primary_size(void)
{
    return global_cow_primary_size;
}

cow_cache_t *cow_cache_new(const char *filename)
{
    cow_cache_t *self          = malloc(sizeof(cow_cache_t));
    self->lookup_primary       = kh_init(COW_CACHE);
    self->lookup_secondary     = kh_init(COW_CACHE);
    self->lookup_secondary_tmp = kh_init(COW_CACHE);

    self->cow_primary_size = COW_CACHE_PRIMARY_MINIMUM_SIZE;
    self->data_primary = mmap(NULL, self->cow_primary_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    assert(self->data_primary != MAP_FAILED);

    self->data_secondary = mmap(NULL, COW_CACHE_SECONDARY_SIZE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    assert(self->data_secondary != MAP_FAILED);

    self->data_secondary_tmp = mmap(NULL, COW_CACHE_SECONDARY_SIZE,
                                    PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    assert(self->data_secondary_tmp != MAP_FAILED);

    self->filename             = strdup(basename(filename));
    self->offset_primary       = 0;
    self->offset_secondary     = 0;
    self->offset_secondary_tmp = 0;

    if (getenv("NYX_DISABLE_BLOCK_COW")) {
        nyx_warn("Nyx block COW layer disabled for %s "
                 "(write operations are not cached!)\n",
                 filename);
        self->enabled = false;
    } else {
        self->enabled = true;
    }
    self->enabled_fuzz     = false;
    self->enabled_fuzz_tmp = false;


#ifdef DEBUG_COW_LAYER
    self->read_calls      = 0;
    self->write_calls     = 0;
    self->read_calls_tmp  = 0;
    self->write_calls_tmp = 0;
#endif

    return self;
}

static char *gen_file_name(cow_cache_t *self,
                           const char  *filename_prefix,
                           const char  *filename_postfix)
{
    char *tmp1;
    char *tmp2;

    assert(asprintf(&tmp2, "%s", self->filename) != -1);

    for (int i = 0; i < strlen(tmp2); i++) {
        if (tmp2[i] == '/') {
            tmp2[i] = '_';
        }
    }

    assert(asprintf(&tmp1, "%s_%s.%s", filename_prefix, tmp2, filename_postfix) != -1);
    free(tmp2);

    return tmp1;
}

void read_primary_buffer(cow_cache_t *self, const char *filename_prefix, bool switch_mode)
{
    assert(!self->enabled_fuzz);
    global_cow_primary_size_adjustable = false;

    char *tmp1;
    char *tmp2;

    tmp1 = gen_file_name(self, filename_prefix, "khash");
    tmp2 = gen_file_name(self, filename_prefix, "pcow");

    kh_destroy(COW_CACHE, self->lookup_primary);

    struct stat buffer;
    assert(stat(tmp2, &buffer) == 0);

    if (buffer.st_size > get_global_cow_cache_primary_size()) {
        nyx_error("in-memory CoW buffer is smaller than snapshot file "
                  "(0x%lx < 0x%lx)\n",
                  get_global_cow_cache_primary_size(), buffer.st_size);
        assert(false);
    }

    if (buffer.st_size) {
        self->lookup_primary = kh_load(COW_CACHE, tmp1);
    } else {
        self->lookup_primary = kh_init(COW_CACHE);
    }

    int fd = open(tmp2, O_RDONLY);

    if (switch_mode) {
        munmap(self->data_primary, self->cow_primary_size);
        self->cow_primary_size = get_global_cow_cache_primary_size();
        self->data_primary =
            mmap(0, self->cow_primary_size, PROT_READ, MAP_SHARED, fd, 0);
        assert(self->data_primary);
    } else {
        if (get_global_cow_cache_primary_size() != self->cow_primary_size) {
            munmap(self->data_primary, self->cow_primary_size);
            self->cow_primary_size = get_global_cow_cache_primary_size();
            self->data_primary     = mmap(NULL, self->cow_primary_size,
                                          PROT_READ | PROT_WRITE,
                                          MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
            assert(self->data_primary != MAP_FAILED);
        }

        void *ptr =
            mmap(0, COW_CACHE_PRIMARY_MINIMUM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
        assert(ptr);
        memcpy(self->data_primary, ptr, buffer.st_size);
        munmap(ptr, COW_CACHE_PRIMARY_MINIMUM_SIZE);
    }
    close(fd);

    self->offset_primary = buffer.st_size;

    if (switch_mode) {
        switch_to_fuzz_mode(self);
    }

    free(tmp1);
    free(tmp2);
}

void dump_primary_buffer(cow_cache_t *self, const char *filename_prefix)
{
    assert(self->enabled_fuzz);

    char *tmp1;
    char *tmp2;

    tmp1 = gen_file_name(self, filename_prefix, "khash");
    tmp2 = gen_file_name(self, filename_prefix, "pcow");

    if (self->offset_primary) {
        kh_write(COW_CACHE, self->lookup_primary, tmp1);
    } else {
        fclose(fopen(tmp1, "wb"));
    }

    FILE *fp = fopen(tmp2, "wb");
    if (fp == NULL) {
        nyx_error("%s: Could not open file %s\n", __func__, tmp2);
        assert(false);
    }

    if (self->offset_primary) {
        fwrite(self->data_primary, CHUNK_SIZE, self->offset_primary / CHUNK_SIZE, fp);
    }

    fclose(fp);

    free(tmp1);
    free(tmp2);
}

void cow_cache_reset(cow_cache_t *self)
{
    if (!self->enabled_fuzz)
        return;
    /* TODO */
    assert(self->enabled_fuzz);

    if (self->enabled_fuzz) {
#ifdef DEBUG_COW_LAYER
        nyx_debug("%s: read_calls =>\t%ld\n", __func__, self->read_calls);
        nyx_debug("%s: write_calls =>\t%ld\n", __func__, self->write_calls);
        nyx_debug("%s: read_calls_tmp =>\t%ld\n", __func__, self->read_calls_tmp);
        nyx_debug("%s: write_calls_tmp =>\t%ld\n", __func__, self->write_calls_tmp);
#endif

        if (!self->enabled_fuzz_tmp) {
            self->offset_secondary = 0;
            kh_clear(COW_CACHE, self->lookup_secondary);

#ifdef DEBUG_COW_LAYER
            self->read_calls  = 0;
            self->write_calls = 0;
#endif
        } else {
            self->offset_secondary_tmp = 0;
            kh_clear(COW_CACHE, self->lookup_secondary_tmp);

#ifdef DEBUG_COW_LAYER
            nyx_debug("CLEAR lookup_secondary_tmp\n");
            self->read_calls_tmp  = 0;
            self->write_calls_tmp = 0;
#endif
        }
    }
}


void cow_cache_enable_tmp_mode(cow_cache_t *self)
{
    assert(self->enabled_fuzz);
    self->enabled_fuzz_tmp = true;
}

void cow_cache_disable_tmp_mode(cow_cache_t *self)
{
    assert(self->enabled_fuzz);
    assert(self->enabled_fuzz_tmp);
    cow_cache_reset(self);
    self->enabled_fuzz_tmp = false;
}

void cow_cache_enable(cow_cache_t *self)
{
    cow_cache_reset(self);
    self->enabled = true;
}


void cow_cache_disable(cow_cache_t *self)
{
    cow_cache_reset(self);
    self->enabled = false;
}

typedef struct BlkRwCo {
    BlockBackend    *blk;
    int64_t          offset;
    QEMUIOVector    *qiov;
    int              ret;
    BdrvRequestFlags flags;
} BlkRwCo;

typedef struct BlkAioEmAIOCB {
    BlockAIOCB common;
    BlkRwCo    rwco;
    int        bytes;
    bool       has_returned;
} BlkAioEmAIOCB;

extern void blk_aio_write_entry(void *opaque);
extern int  blk_check_byte_request(BlockBackend *blk, int64_t offset, size_t size);
extern void blk_aio_complete(BlkAioEmAIOCB *acb);

/* read from primary buffer */
static inline void read_from_primary_buffer(cow_cache_t     *self,
                                            BlockBackend    *blk,
                                            int64_t          offset,
                                            unsigned int     bytes,
                                            QEMUIOVector    *qiov,
                                            BdrvRequestFlags flags,
                                            uint64_t         offset_addr,
                                            uint64_t         iov_offset)
{
    khiter_t k;

    k = kh_get(COW_CACHE, self->lookup_primary, offset_addr);
    if (k != kh_end(self->lookup_primary)) {
#ifdef COW_CACHE_DEBUG
        nyx_debug("[PRE ] READ DIRTY COW PAGE: ADDR: %lx IOVEC OFFSET: %lx DATA "
                  "OFFSET: %lx\n",
                  offset_addr, iov_offset, self->offset_primary);
#endif
        qemu_iovec_from_buf(qiov, iov_offset,
                            self->data_primary + kh_value(self->lookup_primary, k),
                            CHUNK_SIZE);
    }
    return;
}

/* try to read from secondary buffer
 * read from primary buffer if the data is not available yet */
static inline void read_from_secondary_buffer(cow_cache_t     *self,
                                              BlockBackend    *blk,
                                              int64_t          offset,
                                              unsigned int     bytes,
                                              QEMUIOVector    *qiov,
                                              BdrvRequestFlags flags,
                                              uint64_t         offset_addr,
                                              uint64_t         iov_offset)
{
    /* read from L2 TMP buffer */
    khiter_t k;
    if (self->enabled_fuzz_tmp) {
        k = kh_get(COW_CACHE, self->lookup_secondary_tmp, offset_addr);
        if (k != kh_end(self->lookup_secondary_tmp)) {
#ifdef COW_CACHE_DEBUG
            nyx_debug("[FTMP] READ DIRTY COW PAGE: ADDR: %lx IOVEC OFFSET: %lx DATA "
                      "OFFSET: %lx\n",
                      offset_addr, iov_offset, self->offset_secondary);
#endif
            qemu_iovec_from_buf(qiov, iov_offset,
                                self->data_secondary_tmp +
                                    kh_value(self->lookup_secondary_tmp, k),
                                CHUNK_SIZE);
            return;
        }
    }

    /* read from L2 buffer */
    k = kh_get(COW_CACHE, self->lookup_secondary, offset_addr);
    if (k != kh_end(self->lookup_secondary)) {
#ifdef COW_CACHE_DEBUG
        nyx_debug("[FUZZ] READ DIRTY COW PAGE: ADDR: %lx IOVEC OFFSET: %lx DATA "
                  "OFFSET: %lx\n",
                  offset_addr, iov_offset, self->offset_secondary);
#endif
        qemu_iovec_from_buf(qiov, iov_offset,
                            self->data_secondary + kh_value(self->lookup_secondary, k),
                            CHUNK_SIZE);
        return;
    }

    /* read from L1 buffer */
    k = kh_get(COW_CACHE, self->lookup_primary, offset_addr);
    if (k != kh_end(self->lookup_primary)) {
#ifdef COW_CACHE_DEBUG
        nyx_debug("[PRE ] READ DIRTY COW PAGE: ADDR: %lx IOVEC OFFSET: %lx DATA "
                  "OFFSET: %lx\n",
                  offset_addr, iov_offset, self->offset_primary);
#endif
        qemu_iovec_from_buf(qiov, iov_offset,
                            self->data_primary + kh_value(self->lookup_primary, k),
                            CHUNK_SIZE);
    }
}

/* read data from cow cache */
static int cow_cache_read(cow_cache_t     *self,
                          BlockBackend    *blk,
                          int64_t          offset,
                          unsigned int     bytes,
                          QEMUIOVector    *qiov,
                          BdrvRequestFlags flags)
{
#ifdef DEBUG_COW_LAYER
    if (self->enabled_fuzz) {
        if (!self->enabled_fuzz_tmp) {
            self->read_calls++;
        } else {
            self->read_calls_tmp++;
        }
    }
#endif
    blk_co_preadv(blk, offset, bytes, qiov, flags);

    if ((qiov->size % CHUNK_SIZE)) {
#ifdef COW_CACHE_DEBUG
        nyx_debug("%s: FAILED %lx!\n", __func__, qiov->size);
#endif
        return 0;
    }
    assert(!(qiov->size % CHUNK_SIZE));

    uint64_t iov_offset = 0;
    for (uint64_t offset_addr = offset; offset_addr < (offset + (qiov->size));
         offset_addr += CHUNK_SIZE)
    {
        if (self->enabled_fuzz) {
            read_from_secondary_buffer(self, blk, offset, CHUNK_SIZE, qiov, flags,
                                       offset_addr, iov_offset);
        } else {
            read_from_primary_buffer(self, blk, offset, CHUNK_SIZE, qiov, flags,
                                     offset_addr, iov_offset);
        }

        iov_offset += CHUNK_SIZE;
    }

    return 0;
}


/* write to primary buffer */
static inline void write_to_primary_buffer(cow_cache_t     *self,
                                           BlockBackend    *blk,
                                           int64_t          offset,
                                           unsigned int     bytes,
                                           QEMUIOVector    *qiov,
                                           BdrvRequestFlags flags,
                                           uint64_t         offset_addr,
                                           uint64_t         iov_offset)
{
    int      ret;
    khiter_t k;

    k = kh_get(COW_CACHE, self->lookup_primary, offset_addr);
    if (unlikely(k == kh_end(self->lookup_primary))) {
        /* create page */
        k = kh_put(COW_CACHE, self->lookup_primary, offset_addr, &ret);
#ifdef COW_CACHE_DEBUG
        nyx_debug("ADD NEW COW PAGE: ADDR: %lx IOVEC OFFSET: %lx DATA OFFSET: %lx\n",
                  offset_addr, iov_offset, self->offset_primary);
#endif


        kh_value(self->lookup_primary, k) = self->offset_primary;

        self->offset_primary += CHUNK_SIZE;

#ifdef COW_CACHE_VERBOSE
        nyx_debug(
            "COW CACHE IS 0x%lx BYTES (KB: %ld / MB: %ld / GB: %ld) IN SIZE!\n",
            self->offset, self->offset >> 10, self->offset >> 20, self->offset >> 30);
#endif

        /* IN CASE THE BUFFER IS FULL -> ABORT! */
        assert(self->offset_primary < self->cow_primary_size);
    }

#ifdef COW_CACHE_DEBUG
    nyx_debug("LOAD COW PAGE: ADDR: %lx IOVEC OFFSET: %lx DATA OFFSET: %lx (%s)\n",
              offset_addr, iov_offset, kh_value(self->lookup_primary, k),
              self->filename);
#endif

    /* write to cached page */
    qemu_iovec_to_buf(qiov, iov_offset,
                      self->data_primary + kh_value(self->lookup_primary, k),
                      CHUNK_SIZE);
}

static inline void write_to_secondary_buffer(cow_cache_t     *self,
                                             BlockBackend    *blk,
                                             int64_t          offset,
                                             unsigned int     bytes,
                                             QEMUIOVector    *qiov,
                                             BdrvRequestFlags flags,
                                             uint64_t         offset_addr,
                                             uint64_t         iov_offset)
{
    int ret;

    if (!self->enabled_fuzz_tmp) {
        /* L2 mode */

        /* IN CASE THE BUFFER IS FULL -> ABORT! */
        if (self->offset_secondary >= COW_CACHE_SECONDARY_SIZE) {
            GET_GLOBAL_STATE()->cow_cache_full = true;
            abort();
            return;
        }

        khiter_t k_secondary = kh_get(COW_CACHE, self->lookup_secondary, offset_addr);
        if (unlikely(k_secondary == kh_end(self->lookup_secondary))) {
            /* if page is not cached in secondary buffer yet */
            k_secondary = kh_put(COW_CACHE, self->lookup_secondary, offset_addr, &ret);
            kh_value(self->lookup_secondary, k_secondary) = self->offset_secondary;
            self->offset_secondary += CHUNK_SIZE;
        }
        /* write to cache */
        qemu_iovec_to_buf(qiov, iov_offset,
                          self->data_secondary +
                              kh_value(self->lookup_secondary, k_secondary),
                          CHUNK_SIZE);
    } else {
        /* L2 TMP mode */

        /* IN CASE THE BUFFER IS FULL -> ABORT! */
        if (self->offset_secondary_tmp >= COW_CACHE_SECONDARY_SIZE) {
            GET_GLOBAL_STATE()->cow_cache_full = true;
            abort();
            return;
        }

        khiter_t k_secondary_tmp =
            kh_get(COW_CACHE, self->lookup_secondary_tmp, offset_addr);
        if (unlikely(k_secondary_tmp == kh_end(self->lookup_secondary_tmp))) {
            /* if page is not cached in secondary tmp buffer yet */
            k_secondary_tmp =
                kh_put(COW_CACHE, self->lookup_secondary_tmp, offset_addr, &ret);
            kh_value(self->lookup_secondary_tmp, k_secondary_tmp) =
                self->offset_secondary_tmp;
            self->offset_secondary_tmp += CHUNK_SIZE;
        }

        /* write to cache */
        qemu_iovec_to_buf(qiov, iov_offset,
                          self->data_secondary_tmp +
                              kh_value(self->lookup_secondary_tmp, k_secondary_tmp),
                          CHUNK_SIZE);
    }
}

/* write data to cow cache */
static int cow_cache_write(cow_cache_t     *self,
                           BlockBackend    *blk,
                           int64_t          offset,
                           unsigned int     bytes,
                           QEMUIOVector    *qiov,
                           BdrvRequestFlags flags)
{
#ifdef DEBUG_COW_LAYER
    if (self->enabled_fuzz) {
        if (!self->enabled_fuzz_tmp) {
            self->write_calls++;
        } else {
            self->write_calls_tmp++;
        }
    }
#endif

    if ((qiov->size % CHUNK_SIZE)) {
#ifdef COW_CACHE_DEBUG
        nyx_debug("%s: FAILED %lx!\n", __func__, qiov->size);
#endif
        return 0;
    }
    if ((qiov->size % CHUNK_SIZE) && GET_GLOBAL_STATE()->in_fuzzing_mode) {
        GET_GLOBAL_STATE()->cow_cache_full = true;
        nyx_warn("%s write in %lx CHUNKSIZE\n", __func__, qiov->size);
        return 0;
    } else {
        assert(!(qiov->size % CHUNK_SIZE));
    }

    uint64_t iov_offset = 0;
    for (uint64_t offset_addr = offset; offset_addr < (offset + (qiov->size));
         offset_addr += CHUNK_SIZE)
    {
        if (self->enabled_fuzz) {
            write_to_secondary_buffer(self, blk, offset, CHUNK_SIZE, qiov, flags,
                                      offset_addr, iov_offset);
        } else {
            write_to_primary_buffer(self, blk, offset, CHUNK_SIZE, qiov, flags,
                                    offset_addr, iov_offset);
        }

        iov_offset += CHUNK_SIZE;
    }

    return 0;
}

void switch_to_fuzz_mode(cow_cache_t *self)
{
    self->enabled_fuzz = true;
    assert(!mprotect(self->data_primary, self->cow_primary_size, PROT_READ));
    nyx_debug("switching to secondary CoW buffer\n");
}

void cow_cache_read_entry(void *opaque)
{
    BlkAioEmAIOCB *acb  = opaque;
    BlkRwCo       *rwco = &acb->rwco;

#ifdef COW_CACHE_DEBUG
    nyx_debug("%s %lx %lx\n", __func__, rwco->offset, acb->bytes);
#endif

    rwco->ret = cow_cache_read(*((cow_cache_t **)(rwco->blk)), rwco->blk,
                               rwco->offset, acb->bytes, rwco->qiov, rwco->flags);

    blk_aio_complete(acb);
}


void cow_cache_write_entry(void *opaque)
{
    BlkAioEmAIOCB *acb  = opaque;
    BlkRwCo       *rwco = &acb->rwco;

#ifdef COW_CACHE_DEBUG
    nyx_debug("%s\n", __func__);
#endif

    rwco->ret = cow_cache_write(*((cow_cache_t **)(rwco->blk)), rwco->blk,
                                rwco->offset, acb->bytes, rwco->qiov, rwco->flags);

    blk_aio_complete(acb);
}
