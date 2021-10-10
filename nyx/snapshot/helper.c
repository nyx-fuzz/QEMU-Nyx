#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "qemu/main-loop.h"

#include "qemu/bitmap.h"
#include "exec/ram_addr.h"
#include "qemu/rcu_queue.h"
#include "migration/migration.h"

#include "nyx/memory_access.h"

#include "nyx/snapshot/helper.h"
#include "nyx/fast_vm_reload.h"

//#define DEBUG_NYX_SNAPSHOT_HELPER

uint64_t get_ram_size(void){
  RAMBlock *block;
  uint64_t guest_ram_size = 0;
  QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
    guest_ram_size += block->used_length;
#ifdef DEBUG_NYX_SNAPSHOT_HELPER
    printf("Block: %s (%lx)\n", block->idstr, block->used_length);
#endif
  }
#ifdef DEBUG_NYX_SNAPSHOT_HELPER
  printf("%s - guest_ram_size: %lx\n", __func__, guest_ram_size);
#endif
  return guest_ram_size;
}
