
#include <assert.h>
#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "cpu.h"
#include "qemu/main-loop.h"
#include "nyx/snapshot/devices/vm_change_state_handlers.h"


VMChangeStateHandler* change_kvm_clock_handler = NULL;
VMChangeStateHandler* change_kvm_pit_handler = NULL;
VMChangeStateHandler* change_cpu_handler = NULL;
void* change_kvm_clock_opaque = NULL;
void* change_kvm_pit_opaque = NULL;
void* change_cpu_opaque = NULL;

VMChangeStateHandler* change_ide_core_handler = NULL;
uint8_t change_ide_core_opaque_num = 0;
void* change_ide_core_opaque[32] = {NULL};

void call_fast_change_handlers(void){
    assert(change_kvm_clock_handler && change_kvm_pit_handler && change_cpu_handler);

    change_kvm_clock_handler(change_kvm_clock_opaque, 1, RUN_STATE_RUNNING);
    change_kvm_pit_handler(change_kvm_pit_opaque, 1, RUN_STATE_RUNNING);
    change_cpu_handler(change_cpu_opaque, 1, RUN_STATE_RUNNING);

    return;
    /* check if necessary */
    if(change_ide_core_handler){
        for(uint8_t i = 0; i < change_ide_core_opaque_num; i++){
            change_ide_core_handler(change_ide_core_opaque[i], 1, RUN_STATE_RUNNING);
        }
    }
}

void add_fast_reload_change_handler(VMChangeStateHandler *cb, void *opaque, int id){
    switch(id){
        case RELOAD_HANDLER_KVM_CLOCK:
            change_kvm_clock_handler = cb;
            change_kvm_clock_opaque = opaque;
            return;
        case RELOAD_HANDLER_KVM_PIT:
            change_kvm_pit_handler = cb;
            change_kvm_pit_opaque = opaque;
            return;
        case RELOAD_HANDLER_KVM_CPU:
            change_cpu_handler = cb;
            change_cpu_opaque = opaque;
            return;
        case RELOAD_HANDLER_IDE_CORE:
            change_ide_core_handler = cb;
            change_ide_core_opaque[change_ide_core_opaque_num] = opaque;
            change_ide_core_opaque_num++;
            return;
        default:
            abort();
    }
}
