#include "nyx/snapshot/memory/backend/nyx_dirty_ring.h"
#include "nyx/snapshot/helper.h"

#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"

#include <sys/ioctl.h>
#include <linux/kvm.h>

#define FAST_IN_RANGE(address, start, end) (address < end && address >= start)

/* dirty ring specific defines */
#define KVM_DIRTY_LOG_PAGE_OFFSET 64 
#define KVM_EXIT_DIRTY_RING_FULL 31
#define KVM_RESET_DIRTY_RINGS _IO(KVMIO, 0xc7)
#define KVM_CAP_DIRTY_LOG_RING 192

/* global vars */
int dirty_ring_size = 0;
int dirty_ring_max_size_global = 0;
struct kvm_dirty_gfn *kvm_dirty_gfns = NULL; /* dirty ring mmap ptr */
uint32_t kvm_dirty_gfns_index = 0;
uint32_t kvm_dirty_gfns_index_mask = 0;


static int vm_enable_dirty_ring(int vm_fd, uint32_t ring_size){
	struct kvm_enable_cap cap = { 0 };

	cap.cap = KVM_CAP_DIRTY_LOG_RING;
	cap.args[0] = ring_size;

	int ret = ioctl(vm_fd, KVM_ENABLE_CAP, &cap);
	if(ret != 0){
		printf("[QEMU-Nyx] Error: KVM_ENABLE_CAP ioctl failed\n");
	}

  return ring_size;
}

static int check_dirty_ring_size(int kvm_fd, int vm_fd){
	int ret = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_DIRTY_LOG_RING); 
	if(ret < 0 ){
		printf("[QEMU-Nyx] Error: KVM_CAP_DIRTY_LOG_RING failed (dirty ring not supported?)\n");
		exit(1);
	}

	printf("[QEMU-Nyx] Max Dirty Ring Size -> %d (Entries: %d)\n", ret, ret/(int)sizeof(struct kvm_dirty_gfn));

	uint64_t dirty_ring_max_size = ret; //kvm_dirty_ring_size * sizeof(struct kvm_dirty_gfn);

	/* DIRTY RING -> 1MB in size results in 256M trackable memory */
	ret = vm_enable_dirty_ring(vm_fd, dirty_ring_max_size);

	if(ret < 0 ){
		printf("[QEMU-Nyx] Error: Enabling dirty ring (size: %ld) failed\n", dirty_ring_max_size);
		exit(1);
	}

  dirty_ring_max_size_global = dirty_ring_max_size;
	return ret;
}

static void allocate_dirty_ring(int kvm_vcpu, int vm_fd){
	assert(dirty_ring_size);

	if (dirty_ring_size) {
    kvm_dirty_gfns = mmap(NULL, dirty_ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, kvm_vcpu, PAGE_SIZE * KVM_DIRTY_LOG_PAGE_OFFSET);
    if (kvm_dirty_gfns == MAP_FAILED) {
			printf("[QEMU-Nyx] Error: Dirty ring mmap failed!\n");
      exit(1);
    }
  }
	printf("[QEMU-Nyx] Dirty ring mmap region located at %p\n", kvm_dirty_gfns);

	int ret = ioctl(vm_fd, KVM_RESET_DIRTY_RINGS, 0); 
	assert(ret == 0);
}

/* pre_init operation */
void nyx_dirty_ring_early_init(int kvm_fd, int vm_fd){
  dirty_ring_size = check_dirty_ring_size(kvm_fd, vm_fd);
}

void nyx_dirty_ring_pre_init(int kvm_fd, int vm_fd){
	allocate_dirty_ring(kvm_fd, vm_fd);

	kvm_dirty_gfns_index = 0;
	kvm_dirty_gfns_index_mask = ((dirty_ring_max_size_global/sizeof(struct kvm_dirty_gfn)) - 1);

}

static inline void dirty_ring_collect(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist, uint64_t slot, uint64_t gfn){

	/* sanity check */
	assert((slot&0xFFFF0000) == 0);

	slot_t* kvm_region_slot = &self->kvm_region_slots[slot&0xFFFF];

	if(test_and_set_bit(gfn, (void*)kvm_region_slot->bitmap) == false){

		kvm_region_slot->stack[kvm_region_slot->stack_ptr] = gfn;
		kvm_region_slot->stack_ptr++;
	}
}

static void dirty_ring_flush_and_collect(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist, int vm_fd){
	struct kvm_dirty_gfn *entry = NULL;
  int cleared = 0;

	while(true){

		entry = &kvm_dirty_gfns[kvm_dirty_gfns_index & kvm_dirty_gfns_index_mask];

		if((entry->flags & 0x3) == 0){
			break;
		}

		if((entry->flags & 0x1) == 1){
			dirty_ring_collect(self, shadow_memory_state, blocklist, entry->slot, entry->offset);
      cleared++;
			entry->flags |= 0x2; // reset dirty entry 
		}
		else{
			printf("[QEMU-Nyx] [%p] kvm_dirty_gfn -> flags: %d slot: %d offset: %lx {ERROR}\n", entry, entry->flags, entry->slot, entry->offset);
			fflush(stdout);
			exit(1);
		}

		kvm_dirty_gfns_index++;
	}

	int ret = ioctl(vm_fd, KVM_RESET_DIRTY_RINGS, 0); 
  assert(ret == cleared);
}

static void dirty_ring_flush(int vm_fd){
	struct kvm_dirty_gfn *entry = NULL;
  int cleared = 0;

	while(true){

		entry = &kvm_dirty_gfns[kvm_dirty_gfns_index & kvm_dirty_gfns_index_mask];

		if((entry->flags & 0x3) == 0){
			break;
		}

		if((entry->flags & 0x1) == 1){
      cleared++;
			entry->flags |= 0x2; // reset dirty entry 
		}
		else{
			printf("[QEMU-Nyx] [%p] kvm_dirty_gfn -> flags: %d slot: %d offset: %lx {ERROR}\n", entry, entry->flags, entry->slot, entry->offset);
			fflush(stdout);
			exit(1);
		}

		kvm_dirty_gfns_index++;
	}

	int ret = ioctl(vm_fd, KVM_RESET_DIRTY_RINGS, 0); 
  	assert(ret == cleared);
}

/* init operation */
nyx_dirty_ring_t* nyx_dirty_ring_init(shadow_memory_t* shadow_memory){
  nyx_dirty_ring_t* self = malloc(sizeof(nyx_dirty_ring_t));
  memset(self, 0, sizeof(nyx_dirty_ring_t));

  assert(kvm_state);


  KVMMemoryListener *kml = kvm_get_kml(0);
  KVMSlot *mem;

  for (int i = 0; i < kvm_get_max_memslots(); i++) {
		mem = &kml->slots[i];

		if(mem->start_addr == 0 && mem->memory_size == 0){
			break;
		}

		self->kvm_region_slots_num++;
	}

	self->kvm_region_slots = malloc(sizeof(slot_t) * self->kvm_region_slots_num);
	memset(self->kvm_region_slots, 0, sizeof(slot_t) * self->kvm_region_slots_num);

	for (int i = 0; i < kvm_get_max_memslots(); i++) {
		mem = &kml->slots[i];

		if(mem->start_addr == 0 && mem->memory_size == 0){
			break;
		}

		self->kvm_region_slots[i].enabled = (mem->flags&KVM_MEM_READONLY) == 0;
		self->kvm_region_slots[i].bitmap = malloc(BITMAP_SIZE(mem->memory_size));
		self->kvm_region_slots[i].stack = malloc(DIRTY_STACK_SIZE(mem->memory_size));

		memset(self->kvm_region_slots[i].bitmap, 0, BITMAP_SIZE(mem->memory_size));
		memset(self->kvm_region_slots[i].stack, 0, DIRTY_STACK_SIZE(mem->memory_size));

		self->kvm_region_slots[i].bitmap_size = BITMAP_SIZE(mem->memory_size);

		self->kvm_region_slots[i].stack_ptr = 0;

		if(self->kvm_region_slots[i].enabled){
			bool ram_region_found = false;
			for(int j = 0; j < shadow_memory->ram_regions_num; j++){

				if(FAST_IN_RANGE(mem->start_addr, shadow_memory->ram_regions[j].base, (shadow_memory->ram_regions[j].base+shadow_memory->ram_regions[j].size))){
					assert(FAST_IN_RANGE((mem->start_addr+mem->memory_size-1), shadow_memory->ram_regions[j].base, (shadow_memory->ram_regions[j].base+shadow_memory->ram_regions[j].size)));

					self->kvm_region_slots[i].region_id = j;
					self->kvm_region_slots[i].region_offset = mem->start_addr - shadow_memory->ram_regions[j].base;
					ram_region_found = true;
					break;
				}
			}	
			assert(ram_region_found);
		}
	}

	/*
	for(int i = 0; i < self->kvm_region_slots_num; i++){
		printf("[%d].enabled       = %d\n", i, self->kvm_region_slots[i].enabled);
		printf("[%d].bitmap        = %p\n", i, self->kvm_region_slots[i].bitmap);
		printf("[%d].stack         = %p\n", i, self->kvm_region_slots[i].stack);
		printf("[%d].stack_ptr     = %ld\n", i, self->kvm_region_slots[i].stack_ptr);
		if(self->kvm_region_slots[i].enabled){
			printf("[%d].region_id     = %d\n", i, self->kvm_region_slots[i].region_id);
			printf("[%d].region_offset = 0x%lx\n", i, self->kvm_region_slots[i].region_offset);
		}
		else{
			printf("[%d].region_id     = -\n", i);
			printf("[%d].region_offset = -\n", i);
		}
	}
	*/

	dirty_ring_flush(kvm_get_vm_fd(kvm_state));
  return self;
}

static uint32_t restore_memory(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){
    uint32_t num_dirty_pages = 0;
	void* host_addr = NULL;
	void* snapshot_addr = NULL;
	uint64_t physical_addr = 0;
	uint64_t gfn = 0;
	uint64_t entry_offset_addr = 0;

	for(uint8_t j = 0; j < self->kvm_region_slots_num; j++){
		slot_t* kvm_region_slot = &self->kvm_region_slots[j];
		if(kvm_region_slot->enabled && kvm_region_slot->stack_ptr){
			for(uint64_t i = 0; i < kvm_region_slot->stack_ptr; i++){
				gfn = kvm_region_slot->stack[i];

        entry_offset_addr = kvm_region_slot->region_offset + (gfn<<12);

        physical_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].base + entry_offset_addr;

        if(snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) == true){
					continue;
				}

				host_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].host_region_ptr + entry_offset_addr;
			
				if(shadow_memory_state->incremental_enabled){
    			snapshot_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].incremental_region_ptr + entry_offset_addr;
				}
				else{
    			snapshot_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].snapshot_region_ptr + entry_offset_addr;
				}

    			memcpy(host_addr, snapshot_addr, TARGET_PAGE_SIZE);

				clear_bit(gfn, (void*)kvm_region_slot->bitmap);
				num_dirty_pages++;
			}
			kvm_region_slot->stack_ptr = 0;
		}
	}
	return num_dirty_pages;
}

static void save_root_pages(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){
	void* host_addr = NULL;
	void* incremental_addr = NULL;
	uint64_t physical_addr = 0;
	uint64_t gfn = 0;
	uint64_t entry_offset_addr = 0;

	for(uint8_t j = 0; j < self->kvm_region_slots_num; j++){
		slot_t* kvm_region_slot = &self->kvm_region_slots[j];
		if(kvm_region_slot->enabled && kvm_region_slot->stack_ptr){
			for(uint64_t i = 0; i < kvm_region_slot->stack_ptr; i++){
				gfn = kvm_region_slot->stack[i];

        entry_offset_addr = kvm_region_slot->region_offset + (gfn<<12);

        physical_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].base + entry_offset_addr;

        if(snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) == true){
					continue;
				}

				host_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].host_region_ptr + entry_offset_addr;
        incremental_addr = shadow_memory_state->ram_regions[kvm_region_slot->region_id].incremental_region_ptr + entry_offset_addr;

				shadow_memory_track_dirty_root_pages(shadow_memory_state, entry_offset_addr, kvm_region_slot->region_id);
        memcpy(incremental_addr, host_addr, TARGET_PAGE_SIZE);

				clear_bit(gfn, (void*)kvm_region_slot->bitmap);
			}
			kvm_region_slot->stack_ptr = 0;
		}
	}
}

//entry = &ring->dirty_gfns[ring->reset_index & (ring->size - 1)];


uint32_t nyx_snapshot_nyx_dirty_ring_restore(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){
/*
	static int perf_counter = 0;

	if((perf_counter%1000) == 0){
		fprintf(stderr, "perf_counter -> %d\n", perf_counter); //, self->test_total, self->test);
	}

	perf_counter++;
*/

  	dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist, kvm_get_vm_fd(kvm_state));
	return restore_memory(self, shadow_memory_state, blocklist);
}

void nyx_snapshot_nyx_dirty_ring_save_root_pages(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){

  dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist, kvm_get_vm_fd(kvm_state));
	save_root_pages(self, shadow_memory_state, blocklist);
}

/* enable operation */

/* restore operation */


void nyx_snapshot_nyx_dirty_ring_flush(void){
		dirty_ring_flush(kvm_get_vm_fd(kvm_state));
}

void nyx_snapshot_nyx_dirty_ring_flush_and_collect(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){
		dirty_ring_flush_and_collect(self, shadow_memory_state, blocklist, kvm_get_vm_fd(kvm_state));
}
