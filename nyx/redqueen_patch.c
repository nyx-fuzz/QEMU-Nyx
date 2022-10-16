#include "qemu/osdep.h"
#include "redqueen_patch.h"
#include "debug.h"
#include "file_helper.h"
#include "patcher.h"
#include "redqueen.h"

/*
 * Private Helper Functions Declarations
 */

void _load_and_set_patches(patcher_t *self);

/*
 * Public Functions
 */

void pt_enable_patches(patcher_t *self)
{
    _load_and_set_patches(self);
    patcher_apply_all(self);
}

void pt_disable_patches(patcher_t *self)
{
    patcher_restore_all(self);
}


/*
 * Private Helper Functions Definitions
 */


void _load_and_set_patches(patcher_t *self)
{
    size_t    num_addrs = 0;
    uint64_t *addrs     = NULL;
    parse_address_file(redqueen_workdir.redqueen_patches, &num_addrs, &addrs);
    if (num_addrs) {
        patcher_set_addrs(self, addrs, num_addrs);
        free(addrs);
    }
}
