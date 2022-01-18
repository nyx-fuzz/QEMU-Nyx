#include "qemu/osdep.h"
#include "qapi/error.h"
#include "fast_vm_reload_sync.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "qapi/qapi-types-run-state.h"
#include "qemu-common.h"
#include "exec/memory.h"
#include "qemu/main-loop.h"
#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "sysemu/runstate.h"
#include "nyx/state/state.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/debug.h"
#include "nyx/kvm_nested.h"

extern int save_snapshot(const char *name, Error **errp);
extern int load_snapshot(const char *name, Error **errp);

static void adjust_rip(CPUX86State *env, fast_reload_t* snapshot){
  switch(fast_reload_get_mode(snapshot)){
    case RELOAD_MEMORY_MODE_DEBUG: 				
	  case RELOAD_MEMORY_MODE_DEBUG_QUIET:
      env->eip -= 1;  /* out */
      break;
    case RELOAD_MEMORY_MODE_FDL:
    case RELOAD_MEMORY_MODE_FDL_DEBUG:
      env->eip -= 3;  /* vmcall */
      break;
    case RELOAD_MEMORY_MODE_DIRTY_RING:
    case RELOAD_MEMORY_MODE_DIRTY_RING_DEBUG:
      env->eip -= 1;  /* out */
      break;
  }
}

fast_vm_reload_sync_t* init_fast_vm_reload_sync(void){
  fast_vm_reload_sync_t* self = malloc(sizeof(fast_vm_reload_sync_t));
  memset(self, 0, sizeof(fast_vm_reload_sync_t));

  self->request_exists = false;
  self->request_exists_pre = false;
  self->current_request = REQUEST_VOID;
  self->debug_mode = false;

  /* TODO: only RELOAD_MODE_NO_BLOCK is supported for actual fuzzing */
  self->mode = RELOAD_MODE_NO_BLOCK;

  return self;
}

bool fast_snapshot_exists(fast_vm_reload_sync_t* self, FastReloadRequest type){

  assert(self->mode != RELOAD_MODE_DEBUG);

  switch(type){
    case REQUEST_PRE_EXISTS:
      abort();
    case REQUEST_ROOT_EXISTS:
      return fast_reload_root_created(get_fast_reload_snapshot());
    case REQUEST_TMP_EXISTS:
      return fast_reload_tmp_created(get_fast_reload_snapshot());
    default:
      abort();
  }
}



static inline void perform_task_debug_mode(fast_vm_reload_sync_t* self, FastReloadRequest request){
  struct Error* errp = NULL;

  switch(request){
    case REQUEST_SAVE_SNAPSHOT_PRE_FIX_RIP:
      abort();
    case REQUEST_SAVE_SNAPSHOT_PRE:
      vm_stop(RUN_STATE_SAVE_VM);
      save_snapshot("pre_root", &errp);
      qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
      return; /* return here to skip the vm_start call */
    case REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP:
      abort();
    case REQUEST_SAVE_SNAPSHOT_ROOT:
      vm_stop(RUN_STATE_SAVE_VM);
      save_snapshot("root", &errp);
      break;
    case REQUEST_SAVE_SNAPSHOT_TMP_FIX_RIP:
      abort();
    case REQUEST_SAVE_SNAPSHOT_TMP:
      vm_stop(RUN_STATE_SAVE_VM);
      save_snapshot("tmp", &errp);
      break;
    case REQUEST_LOAD_SNAPSHOT_PRE:
      /* probably never called */
      abort();
      break;
    case REQUEST_LOAD_SNAPSHOT_ROOT:
      vm_stop(RUN_STATE_RESTORE_VM);
      load_snapshot("root", &errp);
      break;
    case REQUEST_LOAD_SNAPSHOT_TMP:
      vm_stop(RUN_STATE_RESTORE_VM);
      load_snapshot("tmp", &errp);
      break;

    default:
      abort();
  }
  if (errp) {
    error_reportf_err(errp, "Error: ");
    errp = NULL;
    abort();
  }
  vm_start();
}

static inline void create_root_snapshot(void){
  if (GET_GLOBAL_STATE()->fast_reload_enabled){
		debug_printf("===> GET_GLOBAL_STATE()->fast_reload_enabled: TRUE\n");
		if (GET_GLOBAL_STATE()->fast_reload_mode){
			debug_printf("===> GET_GLOBAL_STATE()->fast_reload_mode: TRUE\n");
      /* we've loaded an external snapshot folder - so do nothing and don't create any new snapshot files */
		}
		else{
			debug_printf("===> GET_GLOBAL_STATE()->fast_reload_mode: FALSE\n");
      /* store the current state as a snapshot folder */
      fast_reload_create_in_memory(get_fast_reload_snapshot());
      fast_reload_serialize_to_file(get_fast_reload_snapshot(), GET_GLOBAL_STATE()->fast_reload_path, false);
    }
	}
	else{
		debug_printf("===> GET_GLOBAL_STATE()->fast_reload_enabled: FALSE\n");
    /* so we haven't set a path for our snapshot files - just store everything in memory */
		fast_reload_create_in_memory(get_fast_reload_snapshot());
	}
}

static inline void perform_task_no_block_mode(fast_vm_reload_sync_t* self, FastReloadRequest request){
  CPUState* cpu = qemu_get_cpu(0);
  X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;
  
  qemu_mutex_lock_iothread();

  switch(request){
    case REQUEST_SAVE_SNAPSHOT_PRE:
      vm_stop(RUN_STATE_SAVE_VM);
      //fast_reload_create_to_file(get_fast_reload_snapshot(), GET_GLOBAL_STATE()->fast_reload_pre_path, true);
      fast_reload_create_in_memory(get_fast_reload_snapshot());
      fast_reload_serialize_to_file(get_fast_reload_snapshot(), GET_GLOBAL_STATE()->fast_reload_pre_path, true);

      qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
      qemu_mutex_unlock_iothread();
      return; /* return here to skip the vm_start call */
    case REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP:
      adjust_rip(env, get_fast_reload_snapshot());
		  kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
    case REQUEST_SAVE_SNAPSHOT_ROOT:

      kvm_arch_get_registers(cpu);
      vm_stop(RUN_STATE_SAVE_VM);
      create_root_snapshot();

      fast_reload_restore(get_fast_reload_snapshot());
      //call_fast_change_handlers();
      break;

    case REQUEST_SAVE_SNAPSHOT_TMP_FIX_RIP:
      adjust_rip(env, get_fast_reload_snapshot());
		  kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
    case REQUEST_SAVE_SNAPSHOT_TMP:
      fast_reload_create_tmp_snapshot(get_fast_reload_snapshot());
      fast_reload_restore(get_fast_reload_snapshot());

      break;
    case REQUEST_LOAD_SNAPSHOT_PRE:
      abort();
      break;
    case REQUEST_LOAD_SNAPSHOT_ROOT:
    case REQUEST_LOAD_SNAPSHOT_TMP:

      //vm_stop(RUN_STATE_RESTORE_VM);
      fast_reload_restore(get_fast_reload_snapshot());
      //call_fast_change_handlers();
      break;

    case REQUEST_SAVE_SNAPSHOT_ROOT_NESTED_FIX_RIP:
      kvm_arch_get_registers(cpu);

      adjust_rip(env, get_fast_reload_snapshot());
      set_nested_rip(cpu, env->eip);
		  kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);

    //case REQUEST_SAVE_SNAPSHOT_ROOT_NESTED:
      kvm_arch_get_registers(cpu);
      vm_stop(RUN_STATE_SAVE_VM);
      create_root_snapshot();

      fast_reload_restore(get_fast_reload_snapshot());
      break;

    default:
      abort();
  }

  vm_start();
  //call_fast_change_handlers();
  cpu_resume(cpu);
  qemu_mutex_unlock_iothread();
}

static inline void perform_task_block_mode(fast_vm_reload_sync_t* self, FastReloadRequest request){
  switch(request){
    case REQUEST_SAVE_SNAPSHOT_PRE_FIX_RIP:
    case REQUEST_SAVE_SNAPSHOT_PRE:
      vm_stop(RUN_STATE_SAVE_VM);
      //fast_reload_create_to_file(get_fast_reload_snapshot(), GET_GLOBAL_STATE()->fast_reload_pre_path, true);
      fast_reload_create_in_memory(get_fast_reload_snapshot());
      fast_reload_serialize_to_file(get_fast_reload_snapshot(), GET_GLOBAL_STATE()->fast_reload_pre_path, true);
      qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
      return; /* return here to skip the vm_start call */
    case REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP:
    case REQUEST_SAVE_SNAPSHOT_ROOT:
      /* TODO: fix this */
      vm_stop(RUN_STATE_SAVE_VM);
      create_root_snapshot();   /* TODO: Fix this -> fucky in ahci mode */
      //fast_reload_create_in_memory(get_fast_reload_snapshot());
      break;
    case REQUEST_SAVE_SNAPSHOT_TMP_FIX_RIP:
    case REQUEST_SAVE_SNAPSHOT_TMP:
      vm_stop(RUN_STATE_SAVE_VM);
      fast_reload_create_tmp_snapshot(get_fast_reload_snapshot());
      break;
    case REQUEST_LOAD_SNAPSHOT_PRE:
      abort();
      break;
    case REQUEST_LOAD_SNAPSHOT_ROOT:
    case REQUEST_LOAD_SNAPSHOT_TMP:
      vm_stop(RUN_STATE_RESTORE_VM);
      fast_reload_restore(get_fast_reload_snapshot());
      break;

    default:
      abort();
  }
  vm_start();
}

static inline void perform_task(fast_vm_reload_sync_t* self, FastReloadRequest request){
  switch(self->mode){
    case RELOAD_MODE_DEBUG:
      abort();
      perform_task_debug_mode(self, request);
      break;
    case RELOAD_MODE_NO_BLOCK:
      perform_task_no_block_mode(self, request);
      break;
    case RELOAD_MODE_BLOCK:
      perform_task_block_mode(self, request);
      break;
  }
}

void request_fast_vm_reload(fast_vm_reload_sync_t* self, FastReloadRequest request){
  assert(!self->request_exists);
  assert(self->current_request == REQUEST_VOID);

  if(self->mode == RELOAD_MODE_NO_BLOCK){
    CPUState* cpu = qemu_get_cpu(0);
    kvm_arch_get_registers(cpu);
    //perform_task(self, request);
    perform_task_no_block_mode(self, request);
  }
  else{
    self->current_request = request;
    self->request_exists = true;
    self->request_exists_pre = true;
  }
}

bool reload_request_exists(fast_vm_reload_sync_t* self){
  return self->request_exists_pre;
}

void reload_request_discard_tmp(fast_vm_reload_sync_t* self){
	fast_reload_discard_tmp_snapshot(get_fast_reload_snapshot());
}

bool check_if_relood_request_exists_pre(fast_vm_reload_sync_t* self){
  if(self->request_exists_pre){
    self->request_exists_pre = false;
    abort();

/*
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, false);
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL_RT, false);
    qemu_clock_enable(QEMU_CLOCK_HOST, false);
*/

    //printf("%s: task found: %d\n", __func__, self->current_request);

    CPUState* cpu = qemu_get_cpu(0);
    X86CPU *x86_cpu = X86_CPU(cpu);
	  CPUX86State *env = &x86_cpu->env;

    kvm_arch_get_registers(cpu);

    switch(self->current_request){
      case REQUEST_VOID:
        fprintf(stderr, "%s: REQUEST_VOID requested!\n", __func__);
        abort();

      case REQUEST_SAVE_SNAPSHOT_PRE_FIX_RIP:
      case REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP:
      case REQUEST_SAVE_SNAPSHOT_TMP_FIX_RIP:
        adjust_rip(env, get_fast_reload_snapshot());
		    kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
        qemu_system_vmstop_request(RUN_STATE_SAVE_VM);
        break;

      case REQUEST_SAVE_SNAPSHOT_PRE:
      case REQUEST_SAVE_SNAPSHOT_ROOT:
      case REQUEST_SAVE_SNAPSHOT_TMP:
        qemu_system_vmstop_request(RUN_STATE_SAVE_VM);
        break;

      case REQUEST_SAVE_SNAPSHOT_ROOT_NESTED_FIX_RIP:
      case REQUEST_SAVE_SNAPSHOT_TMP_NESTED_FIX_RIP:
        adjust_rip(env, get_fast_reload_snapshot());
        set_nested_rip(cpu, env->eip);
        kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
        qemu_system_vmstop_request(RUN_STATE_SAVE_VM);

      case REQUEST_LOAD_SNAPSHOT_PRE:
      case REQUEST_LOAD_SNAPSHOT_ROOT:
      case REQUEST_LOAD_SNAPSHOT_TMP:
        qemu_system_vmstop_request(RUN_STATE_RESTORE_VM);
        break;

      default:
        fprintf(stderr, "%s: Unkown request: %d\n", __func__, self->current_request);
        abort();
    }
    return true;
  }
  return false;
}

bool check_if_relood_request_exists_post(fast_vm_reload_sync_t* self){
  if(self->request_exists){
    FastReloadRequest request = self->current_request;
    self->request_exists = false;

    assert(self->current_request != REQUEST_VOID);
    self->current_request = REQUEST_VOID;
    perform_task(self, request);

/*
    qemu_clock_enable(QEMU_CLOCK_HOST, true);
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL_RT, true);
    qemu_clock_enable(QEMU_CLOCK_VIRTUAL, true);
*/

    return true;
  }
  return false;
}
