#include "nyx/kvm_nested.h"
#include "cpu.h"
#include <linux/kvm.h>
#include "nyx/debug.h"
#include "exec/ram_addr.h"
#include "qemu/rcu_queue.h"
#include "nyx/state/state.h"
#include "sysemu/kvm.h"
#include "pt.h"

#define PPAGE_SIZE 0x1000
#define PENTRIES 0x200
#define PLEVEL_4_SHIFT 12
#define PLEVEL_3_SHIFT 21
#define PLEVEL_2_SHIFT 30
#define PLEVEL_1_SHIFT 39
#define SIGN_EXTEND_TRESHOLD 0x100
#define SIGN_EXTEND 0xFFFF000000000000ULL
#define PAGETABLE_MASK 0xFFFFFFFFFF000ULL
#define CHECK_BIT(var,pos) !!(((var) & (1ULL<<(pos))))


struct vmcs_hdr {
	uint32_t revision_id:31;
	uint32_t shadow_vmcs:1;
};

struct __attribute__((__packed__)) vmcs12 {
	/* According to the Intel spec, a VMCS region must start with the
	 * following two fields. Then follow implementation-specific data.
	 */
	struct vmcs_hdr hdr;
	uint32_t abort;

	uint32_t launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
	uint32_t padding[7]; /* room for future expansion */

	uint64_t io_bitmap_a;
	uint64_t io_bitmap_b;
	uint64_t msr_bitmap;
	uint64_t vm_exit_msr_store_addr;
	uint64_t vm_exit_msr_load_addr;
	uint64_t vm_entry_msr_load_addr;
	uint64_t tsc_offset;
	uint64_t virtual_apic_page_addr;
	uint64_t apic_access_addr;
	uint64_t posted_intr_desc_addr;
	uint64_t ept_pointer;
	uint64_t eoi_exit_bitmap0;
	uint64_t eoi_exit_bitmap1;
	uint64_t eoi_exit_bitmap2;
	uint64_t eoi_exit_bitmap3;
	uint64_t xss_exit_bitmap;
	uint64_t guest_physical_address;
	uint64_t vmcs_link_pointer;
	uint64_t guest_ia32_debugctl;
	uint64_t guest_ia32_pat;
	uint64_t guest_ia32_efer;
	uint64_t guest_ia32_perf_global_ctrl;
	uint64_t guest_pdptr0;
	uint64_t guest_pdptr1;
	uint64_t guest_pdptr2;
	uint64_t guest_pdptr3;
	uint64_t guest_bndcfgs;
	uint64_t host_ia32_pat;
	uint64_t host_ia32_efer;
	uint64_t host_ia32_perf_global_ctrl;
	uint64_t vmread_bitmap;
	uint64_t vmwrite_bitmap;
	uint64_t vm_function_control;
	uint64_t eptp_list_address;
	uint64_t pml_address;
	uint64_t padding64[3]; /* room for future expansion */
	/*
	 * To allow migration of L1 (complete with its L2 guests) between
	 * machines of different natural widths (32 or 64 bit), we cannot have
	 * unsigned long fields with no explict size. We use uint64_t (aliased
	 * uint64_t) instead. Luckily, x86 is little-endian.
	 */
	uint64_t cr0_guest_host_mask;
	uint64_t cr4_guest_host_mask;
	uint64_t cr0_read_shadow;
	uint64_t cr4_read_shadow;
	uint64_t cr3_target_value0;
	uint64_t cr3_target_value1;
	uint64_t cr3_target_value2;
	uint64_t cr3_target_value3;
	uint64_t exit_qualification;
	uint64_t guest_linear_address;
	uint64_t guest_cr0;
	uint64_t guest_cr3;
	uint64_t guest_cr4;
	uint64_t guest_es_base;
	uint64_t guest_cs_base;
	uint64_t guest_ss_base;
	uint64_t guest_ds_base;
	uint64_t guest_fs_base;
	uint64_t guest_gs_base;
	uint64_t guest_ldtr_base;
	uint64_t guest_tr_base;
	uint64_t guest_gdtr_base;
	uint64_t guest_idtr_base;
	uint64_t guest_dr7;
	uint64_t guest_rsp;
	uint64_t guest_rip;
	uint64_t guest_rflags;
	uint64_t guest_pending_dbg_exceptions;
	uint64_t guest_sysenter_esp;
	uint64_t guest_sysenter_eip;
	uint64_t host_cr0;
	uint64_t host_cr3;
	uint64_t host_cr4;
	uint64_t host_fs_base;
	uint64_t host_gs_base;
	uint64_t host_tr_base;
	uint64_t host_gdtr_base;
	uint64_t host_idtr_base;
	uint64_t host_ia32_sysenter_esp;
	uint64_t host_ia32_sysenter_eip;
	uint64_t host_rsp;
	uint64_t host_rip;
	uint64_t paddingl[8]; /* room for future expansion */
	uint32_t pin_based_vm_exec_control;
	uint32_t cpu_based_vm_exec_control;
	uint32_t exception_bitmap;
	uint32_t page_fault_error_code_mask;
	uint32_t page_fault_error_code_match;
	uint32_t cr3_target_count;
	uint32_t vm_exit_controls;
	uint32_t vm_exit_msr_store_count;
	uint32_t vm_exit_msr_load_count;
	uint32_t vm_entry_controls;
	uint32_t vm_entry_msr_load_count;
	uint32_t vm_entry_intr_info_field;
	uint32_t vm_entry_exception_error_code;
	uint32_t vm_entry_instruction_len;
	uint32_t tpr_threshold;
	uint32_t secondary_vm_exec_control;
	uint32_t vm_instruction_error;
	uint32_t vm_exit_reason;
	uint32_t vm_exit_intr_info;
	uint32_t vm_exit_intr_error_code;
	uint32_t idt_vectoring_info_field;
	uint32_t idt_vectoring_error_code;
	uint32_t vm_exit_instruction_len;
	uint32_t vmx_instruction_info;
	uint32_t guest_es_limit;
	uint32_t guest_cs_limit;
	uint32_t guest_ss_limit;
	uint32_t guest_ds_limit;
	uint32_t guest_fs_limit;
	uint32_t guest_gs_limit;
	uint32_t guest_ldtr_limit;
	uint32_t guest_tr_limit;
	uint32_t guest_gdtr_limit;
	uint32_t guest_idtr_limit;
	uint32_t guest_es_ar_bytes;
	uint32_t guest_cs_ar_bytes;
	uint32_t guest_ss_ar_bytes;
	uint32_t guest_ds_ar_bytes;
	uint32_t guest_fs_ar_bytes;
	uint32_t guest_gs_ar_bytes;
	uint32_t guest_ldtr_ar_bytes;
	uint32_t guest_tr_ar_bytes;
	uint32_t guest_interruptibility_info;
	uint32_t guest_activity_state;
	uint32_t guest_sysenter_cs;
	uint32_t host_ia32_sysenter_cs;
	uint32_t vmx_preemption_timer_value;
	uint32_t padding32[7]; /* room for future expansion */
	uint16_t virtual_processor_id;
	uint16_t posted_intr_nv;
	uint16_t guest_es_selector;
	uint16_t guest_cs_selector;
	uint16_t guest_ss_selector;
	uint16_t guest_ds_selector;
	uint16_t guest_fs_selector;
	uint16_t guest_gs_selector;
	uint16_t guest_ldtr_selector;
	uint16_t guest_tr_selector;
	uint16_t guest_intr_status;
	uint16_t host_es_selector;
	uint16_t host_cs_selector;
	uint16_t host_ss_selector;
	uint16_t host_ds_selector;
	uint16_t host_fs_selector;
	uint16_t host_gs_selector;
	uint16_t host_tr_selector;
	uint16_t guest_pml_index;
};


static void write_address(uint64_t address, uint64_t size, uint64_t prot){
	static uint64_t next_address = PAGETABLE_MASK;
	static uint64_t last_address = 0x0; 
	static uint64_t last_prot = 0;
	if(address != next_address || prot != last_prot){
		/* do not print guard pages or empty pages without any permissions */
		if(last_address && (CHECK_BIT(last_prot, 1) || !CHECK_BIT(last_prot, 63))){
			if(CHECK_BIT(last_prot, 1) && !CHECK_BIT(last_prot, 63)){
				QEMU_PT_PRINTF(NESTED_VM_PREFIX, "%016lx - %016lx %c%c%c [WARNING]",
					last_address, next_address,
		            CHECK_BIT(last_prot, 1) ? 'W' : '-', 
		            CHECK_BIT(last_prot, 2) ? 'U' : 'K', 
		            !CHECK_BIT(last_prot, 63)? 'X' : '-');
			}
			else{
				QEMU_PT_PRINTF(NESTED_VM_PREFIX, "%016lx - %016lx %c%c%c",
					last_address, next_address,
		            CHECK_BIT(last_prot, 1) ? 'W' : '-', 
		            CHECK_BIT(last_prot, 2) ? 'U' : 'K', 
		            !CHECK_BIT(last_prot, 63)? 'X' : '-');
			}
		}
		last_address = address;
	}
	next_address = address+size;
	last_prot = prot;
	
}

void print_48_paging(uint64_t cr3){
    uint64_t paging_entries_level_1[PENTRIES];
    uint64_t paging_entries_level_2[PENTRIES];
    uint64_t paging_entries_level_3[PENTRIES];
    uint64_t paging_entries_level_4[PENTRIES];

    uint64_t address_identifier_1, address_identifier_2, address_identifier_3, address_identifier_4;
    uint32_t i1, i2, i3,i4;

    cpu_physical_memory_rw((cr3&PAGETABLE_MASK), (uint8_t *) paging_entries_level_1, PPAGE_SIZE, false);
    for(i1 = 0; i1 < 512; i1++){
        if(paging_entries_level_1[i1]){
            address_identifier_1 = ((uint64_t)i1) << PLEVEL_1_SHIFT;
            if (i1 & SIGN_EXTEND_TRESHOLD){
                address_identifier_1 |= SIGN_EXTEND;
            }
            if(CHECK_BIT(paging_entries_level_1[i1], 0)){ /* otherwise swapped out */ 
                cpu_physical_memory_rw((paging_entries_level_1[i1]&PAGETABLE_MASK), (uint8_t *) paging_entries_level_2, PPAGE_SIZE, false);
                for(i2 = 0; i2 < PENTRIES; i2++){
                    if(paging_entries_level_2[i2]){
                        address_identifier_2 = (((uint64_t)i2) << PLEVEL_2_SHIFT) + address_identifier_1;
                        if (CHECK_BIT(paging_entries_level_2[i2], 0)){ /* otherwise swapped out */ 
                            if((paging_entries_level_2[i2]&PAGETABLE_MASK) == (paging_entries_level_1[i1]&PAGETABLE_MASK)){
                                /* loop */
                                continue;
                            }

                            if (CHECK_BIT(paging_entries_level_2[i2], 7)){
                                    write_address(address_identifier_2, 0x40000000, (uint64_t)paging_entries_level_2[i2] & ((1ULL<<63) | (1ULL<<2) | (1ULL<<1)));
                            }
                            else{
                                /* otherwise this PDPE references a 1GB page */
                                cpu_physical_memory_rw((paging_entries_level_2[i2]&PAGETABLE_MASK), (uint8_t *) paging_entries_level_3, PPAGE_SIZE, false);
								for(i3 = 0; i3 < PENTRIES; i3++){
									if(paging_entries_level_3[i3]){
									    address_identifier_3 = (((uint64_t)i3) << PLEVEL_3_SHIFT) + address_identifier_2;
									    if (CHECK_BIT(paging_entries_level_3[i3], 0)){ /* otherwise swapped out */ 
									        if (CHECK_BIT(paging_entries_level_3[i3], 7)){
									        	write_address(address_identifier_3, 0x200000, (uint64_t)paging_entries_level_3[i3] & ((1ULL<<63) | (1ULL<<2) | (1ULL<<1)));
									        }
									        else{
												cpu_physical_memory_rw((paging_entries_level_3[i3]&PAGETABLE_MASK), (uint8_t *) paging_entries_level_4, PPAGE_SIZE, false);
											    for(i4 = 0; i4 < PENTRIES; i4++){
											        if(paging_entries_level_4[i4]){
											            address_identifier_4 = (((uint64_t)i4) << PLEVEL_4_SHIFT) + address_identifier_3;
											            if (CHECK_BIT(paging_entries_level_4[i4], 0)){
											                write_address(address_identifier_4, 0x1000, (uint64_t)paging_entries_level_4[i4] & ((1ULL<<63) | (1ULL<<2) | (1ULL<<1)));
											            }
											        }
											    }
									        }
										}
									}
								}

                            }
                        }
                    }
                }
            }
        }
    }
	write_address(0, 0x1000, 0);
}

/*
static bool change_page_permissions(uint64_t phys_addr, CPUState *cpu){
    RAMBlock *block;

    //MemTxAttrs attrs = MEMTXATTRS_UNSPECIFIED;

    QLIST_FOREACH_RCU(block, &ram_list.blocks, next) {
        if(!memcmp(block->idstr, "pc.ram", 6)){
        	printf("FOUND AND MODIFIED! %lx\n", mprotect((void*)(((uint64_t)block->host) + phys_addr), 0x1000, PROT_NONE));
            break;
        }
    }
    
    return true;
}
*/

uint64_t get_nested_guest_rip(CPUState *cpu){

	X86CPU *cpux86 = X86_CPU(cpu);
	CPUX86State *env = &cpux86->env;

	kvm_vcpu_ioctl(cpu, KVM_GET_NESTED_STATE, env->nested_state);
	
	struct vmcs12* saved_vmcs = (struct vmcs12*)&(env->nested_state->data);

	return saved_vmcs->guest_rip;
}

uint64_t get_nested_host_rip(CPUState *cpu){

	X86CPU *cpux86 = X86_CPU(cpu);
	CPUX86State *env = &cpux86->env;

	kvm_vcpu_ioctl(cpu, KVM_GET_NESTED_STATE, env->nested_state);
	
	struct vmcs12* saved_vmcs = (struct vmcs12*)&(env->nested_state->data);

	return saved_vmcs->host_rip;
}

uint64_t get_nested_host_cr3(CPUState *cpu){

	X86CPU *cpux86 = X86_CPU(cpu);
	CPUX86State *env = &cpux86->env;

	kvm_vcpu_ioctl(cpu, KVM_GET_NESTED_STATE, env->nested_state);
	
	struct vmcs12* saved_vmcs = (struct vmcs12*)&(env->nested_state->data);

	return saved_vmcs->host_cr3;
}

void set_nested_rip(CPUState *cpu, uint64_t rip){

	X86CPU *cpux86 = X86_CPU(cpu);
	CPUX86State *env = &cpux86->env;

	//kvm_vcpu_ioctl(cpu, KVM_GET_NESTED_STATE, env->nested_state);
	
	struct vmcs12* saved_vmcs = (struct vmcs12*)&(env->nested_state->data);

	saved_vmcs->guest_rip = rip;

	//return saved_vmcs->guest_rip;
}

void kvm_nested_get_info(CPUState *cpu){

	X86CPU *cpux86 = X86_CPU(cpu);
	CPUX86State *env = &cpux86->env;

	kvm_vcpu_ioctl(cpu, KVM_GET_NESTED_STATE, env->nested_state);
	
	struct vmcs12* saved_vmcs = (struct vmcs12*)&(env->nested_state->data);
	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "VMCS host_cr3:\t%lx", saved_vmcs->host_cr3);
	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "VMCS host_cr4:\t%lx", saved_vmcs->host_cr4);
	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "VMCS host_ia32_efer:\t%lx", saved_vmcs->host_ia32_efer);
	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "VMCS host_cr0:\t%lx", saved_vmcs->host_cr0);

	return;

	//cpu->parent_cr3 = saved_vmcs->host_cr3+0x1000;
	GET_GLOBAL_STATE()->parent_cr3 = saved_vmcs->host_cr3+0x1000;
	fprintf(stderr, "saved_vmcs->guest_cr3: %lx %lx %lx\n", saved_vmcs->guest_cr3, saved_vmcs->host_cr3, env->cr[3]);
	pt_set_cr3(cpu, saved_vmcs->host_cr3+0x1000, false); /* USERSPACE */
	//pt_set_cr3(cpu, saved_vmcs->host_cr3+0x1000, false); /* KERNELSPACE QEMU fuzzing fix...fucking kpti (https://gruss.cc/files/kaiser.pdf)!!! */

	/* let's modify page permissions of our CR3 referencing PTs */
	//change_page_permissions(cpu->parent_cr3, cpu);


    if (!(saved_vmcs->host_cr0 & CR0_PG_MASK)) {
        printf("PG disabled\n");
    }
    else{
    	if (saved_vmcs->host_cr4 & CR4_PAE_MASK) {
	        if (saved_vmcs->host_ia32_efer & (1 << 10)) {
	            if (saved_vmcs->host_cr0 & CR4_LA57_MASK) {
	            	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "mem_info_la57");
	            	abort();
	                //mem_info_la57(mon, env);
	            } else {
	            	QEMU_PT_PRINTF(NESTED_VM_PREFIX, " ==== L1 Page Tables ====");
	            	print_48_paging(saved_vmcs->host_cr3);

	            	if(saved_vmcs->ept_pointer){
		            	QEMU_PT_PRINTF(NESTED_VM_PREFIX, " ==== L2 Page Tables ====");
		            	print_48_paging(saved_vmcs->ept_pointer);
		            }
	                //mem_info_la48(mon, env);
	            }
	        } 
	        else{
	        	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "mem_info_pae32");
	        	abort();
	            //mem_info_pae32(mon, env);
	        }
	    } 
	    else {
	    	QEMU_PT_PRINTF(NESTED_VM_PREFIX, "mem_info_32");
	    	abort();
	        //mem_info_32(mon, env);
	    }
    }
}

#define AREA_DESC_LEN                   256
#define MAGIC_NUMBER                    0x41584548U

typedef struct {
        uint32_t base;
        uint32_t size;
				uint32_t virtual_base;
        char desc[AREA_DESC_LEN];
}area_t_export_t;

typedef struct {
        uint32_t magic;
        uint8_t num_mmio_areas;
        uint8_t num_io_areas;
        uint8_t num_alloc_areas;
        uint8_t padding;
}config_t;

void print_configuration(FILE *stream, void* configuration, size_t size){
//void print_configuration(void* configuration, size_t size){

	fprintf(stream, "%s: size: %lx\n", __func__, size);
	assert((size-sizeof(config_t))%sizeof(area_t_export_t) == 0);

	assert(((config_t*)configuration)->magic == MAGIC_NUMBER);

	fprintf(stream, "%s: num_mmio_areas: %x\n", __func__, ((config_t*)configuration)->num_mmio_areas);
	fprintf(stream, "%s: num_io_areas: %x\n", __func__, ((config_t*)configuration)->num_io_areas);
	fprintf(stream, "%s: num_alloc_areas: %x\n", __func__, ((config_t*)configuration)->num_alloc_areas);


	for(int i = 0; i < ((config_t*)configuration)->num_mmio_areas; i++){
	fprintf(stream, "\t-> MMIO: 0x%x (V: 0x%x) [0x%x]\t%s\n",       ((area_t_export_t*)(configuration+sizeof(config_t)))[i].base,
																													((area_t_export_t*)(configuration+sizeof(config_t)))[i].virtual_base,
																													((area_t_export_t*)(configuration+sizeof(config_t)))[i].size,
																													((area_t_export_t*)(configuration+sizeof(config_t)))[i].desc );
	}

	for(int i = ((config_t*)configuration)->num_mmio_areas; i < (((config_t*)configuration)->num_mmio_areas+((config_t*)configuration)->num_io_areas); i++){
	fprintf(stream, "\t->   IO: 0x%x [0x%x]\t%s\n",       ((area_t_export_t*)(configuration+sizeof(config_t)))[i].base,
																													((area_t_export_t*)(configuration+sizeof(config_t)))[i].size,
																													((area_t_export_t*)(configuration+sizeof(config_t)))[i].desc );
	}
}