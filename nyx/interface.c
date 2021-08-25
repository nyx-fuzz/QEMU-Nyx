/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (Nyx).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "hw/qdev-properties.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qom/object_interfaces.h"
#include "chardev/char-fe.h"
#include "sysemu/hostmem.h"
#include "sysemu/qtest.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include "pt.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/interface.h"
#include "nyx/debug.h"
#include "nyx/synchronization.h"
#include "nyx/snapshot/devices/state_reallocation.h"
#include "nyx/memory_access.h"
#include <sys/ioctl.h>
#include "nyx/state/state.h"
#include "nyx/sharedir.h"
#include "nyx/helpers.h"
#include "nyx/trace_dump.h"

#include <time.h>

#include "redqueen.h"

#define CONVERT_UINT64(x) (uint64_t)(strtoull(x, NULL, 16))

#define TYPE_NYX_MEM "nyx"
#define NYX_MEM(obj) \
		OBJECT_CHECK(nyx_interface_state, (obj), TYPE_NYX_MEM)

static void nyx_realize(DeviceState *dev, Error **errp);

typedef struct nyx_interface_state {
	DeviceState parent_obj;

	Chardev *nyx_chr_drv_state;
	CharBackend chr;

	char* sharedir;

	char* workdir; 
	uint32_t worker_id;
	uint64_t cow_primary_size;
	
	char* redqueen_workdir;
	char* data_bar_fd_0;
	char* data_bar_fd_1;
	char* data_bar_fd_2;
	char* bitmap_file;

	char* filter_bitmap[4];
	char* ip_filter[4][2];

	uint32_t bitmap_size;
	uint32_t input_buffer_size;

	bool dump_pt_trace;
	bool edge_cb_trace;

	bool redqueen;
	
} nyx_interface_state;

static void nyx_interface_event(void *opaque, int event){
}

static void send_char(char val, void* tmp_s){
	nyx_interface_state *s = tmp_s;

	assert(val == NYX_INTERFACE_PING);
	__sync_synchronize();

	qemu_chr_fe_write(&s->chr, (const uint8_t *) &val, 1);
}

static int nyx_interface_can_receive(void * opaque){
	return sizeof(int64_t);
}

static nyx_interface_state* state = NULL;

static void init_send_char(nyx_interface_state* s){
	state = s;
}

bool interface_send_char(char val){

	if(state){
		send_char(val, state);
		return true;
	}
	return false;
}

static void nyx_interface_receive(void *opaque, const uint8_t * buf, int size){
	int i;				
	for(i = 0; i < size; i++){
		switch(buf[i]){
			case NYX_INTERFACE_PING:
				synchronization_unlock();
				break;
			case '\n':
				break;
			case 'E':
				exit(0);
			default:
				break;
				assert(false);
		}
	}
}

static int nyx_create_payload_buffer(nyx_interface_state *s, uint64_t buffer_size, const char* file, Error **errp){
	void * ptr;
	int fd;
	struct stat st;

	fd = open(file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, buffer_size) == 0);
	stat(file, &st);
	QEMU_PT_PRINTF(INTERFACE_PREFIX, "new shm file: (max size: %lx) %lx", buffer_size, st.st_size);
	
	assert(buffer_size == st.st_size);
	ptr = mmap(0, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (ptr == MAP_FAILED) {
		error_setg_errno(errp, errno, "Failed to mmap memory");
		return -1;
	}

	GET_GLOBAL_STATE()->shared_payload_buffer_fd = fd;
	GET_GLOBAL_STATE()->shared_payload_buffer_size = buffer_size;

	init_send_char(s);

	return 0;
}

static void nyx_guest_setup_bitmap(nyx_interface_state *s, char* filename, uint32_t bitmap_size){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(filename, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bitmap_size) == 0);
	stat(filename, &st);
	assert(bitmap_size == st.st_size);
	ptr = mmap(0, bitmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	GET_GLOBAL_STATE()->shared_bitmap_ptr = (void*)ptr;
	GET_GLOBAL_STATE()->shared_bitmap_fd = fd;
	GET_GLOBAL_STATE()->shared_bitmap_size = bitmap_size;
	GET_GLOBAL_STATE()->shared_bitmap_real_size = bitmap_size;
}


static void nyx_guest_setup_ijon_buffer(nyx_interface_state *s, char* filename){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(filename, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, DEFAULT_NYX_IJON_BITMAP_SIZE) == 0);
	stat(filename, &st);
	assert(DEFAULT_NYX_IJON_BITMAP_SIZE == st.st_size);
	ptr = mmap(0, DEFAULT_NYX_IJON_BITMAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	
	GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr = (void*)ptr;
	GET_GLOBAL_STATE()->shared_ijon_bitmap_fd = fd;
	GET_GLOBAL_STATE()->shared_ijon_bitmap_size = DEFAULT_NYX_IJON_BITMAP_SIZE;
}

static bool verify_workdir_state(nyx_interface_state *s, Error **errp){

	char* workdir = s->workdir;
	uint32_t id = s->worker_id;
	char* tmp;

	if (!folder_exits(workdir)){
		fprintf(stderr, "%s does not exist...\n", workdir);
		return false;
	}

	set_workdir_path(workdir);

	assert(asprintf(&tmp, "%s/dump/", workdir) != -1);
	if (!folder_exits(tmp)){
		mkdir(tmp, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/interface_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/payload_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	else {
		nyx_create_payload_buffer(s, s->input_buffer_size, tmp, errp);
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/bitmap_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	} else {
		nyx_guest_setup_bitmap(s, tmp, s->bitmap_size);
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/ijon_%d", workdir, id) != -1);
	if (!file_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	} else {
		nyx_guest_setup_ijon_buffer(s, tmp);
	}
	free(tmp);

	assert(asprintf(&tmp, "%s/page_cache", workdir) != -1);
	init_page_cache(tmp);

	assert(asprintf(&tmp, "%s/redqueen_workdir_%d/", workdir, id) != -1);
	if (!folder_exits(tmp)){
		fprintf(stderr,  "%s does not exist...\n", tmp);
		free(tmp);
		return false;
	}
	else {
		setup_redqueen_workdir(tmp);
	}
	free(tmp);

	init_redqueen_state();

  if(s->dump_pt_trace){
	assert(asprintf(&tmp, "%s/pt_trace_dump_%d", workdir, id) != -1);
	pt_trace_dump_init(tmp);
	free(tmp);
  }

  if(s->edge_cb_trace){
	redqueen_trace_init();
  }


	assert(asprintf(&tmp, "%s/aux_buffer_%d", workdir, id) != -1);
	/*
	if (file_exits(tmp)){
		QEMU_PT_PRINTF(INTERFACE_PREFIX, "%s does not already exists...", tmp);
		free(tmp);
		return false;
	}
	else {
		init_aux_buffer(tmp);
	}
	*/
	init_aux_buffer(tmp);
	free(tmp);


	return true;
}

#define KVM_VMX_PT_GET_ADDRN				_IO(KVMIO,	0xe9)

static void check_ipt_range(uint8_t i){
	int ret = 0;
	int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	ret = ioctl(kvm, KVM_VMX_PT_GET_ADDRN, NULL);

	if(ret == -1){
		fprintf(stderr, "[QEMU-Nyx] Error: Multi range tracing is not supported!\n");
		exit(1);
	}

	if(ret < (i+1)){
		fprintf(stderr, "[QEMU-Nyx] Error: CPU supports only %d IP filters!\n", ret);
		exit(1);
	}
	close(kvm);
}

static void check_available_ipt_ranges(nyx_interface_state* s){
	uint64_t addr_a, addr_b;

	int kvm_fd = qemu_open("/dev/kvm", O_RDWR);
	if (kvm_fd == -1) {
	    fprintf(stderr, "[QEMU-Nyx] Error: could not access KVM kernel module: %m\n");
		exit(1);
	}

	if (ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_NYX_PT) == 1 && ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_NYX_FDL) == 1) {
		for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
			if(s->ip_filter[i][0] && s->ip_filter[i][1]){
				if(i >= 1){
					check_ipt_range(i);
				}
				addr_a = CONVERT_UINT64(s->ip_filter[i][0]);
				addr_b = CONVERT_UINT64(s->ip_filter[i][1]);
				if (addr_a < addr_b){
					pt_setup_ip_filters(i, addr_a, addr_b);
				}
			}
		}
	}
	close(kvm_fd);
}

static bool verify_sharedir_state(nyx_interface_state *s, Error **errp){

	char* sharedir = s->sharedir;

	if (!folder_exits(sharedir)){
		QEMU_PT_PRINTF(INTERFACE_PREFIX, "%s does not exist...", sharedir);
		return false;
	}
	return true;
}


static void nyx_realize(DeviceState *dev, Error **errp){
	nyx_interface_state *s = NYX_MEM(dev);

	if(s->bitmap_size <= 0){
		s->bitmap_size = DEFAULT_NYX_BITMAP_SIZE;
	}


	if(s->worker_id == 0xFFFF){
		fprintf(stderr, "[QEMU-Nyx] Error: Invalid worker id...\n");
		exit(1);
	}

	if(s->cow_primary_size){
		set_global_cow_cache_primary_size(s->cow_primary_size);
	}
	GET_GLOBAL_STATE()->worker_id = s->worker_id;

	if (!s->workdir || !verify_workdir_state(s, errp)){
		fprintf(stderr, "[QEMU-Nyx] Error:  work dir...\n");
		exit(1);
	}

	if (!s->sharedir || !verify_sharedir_state(s, errp)){
		fprintf(stderr,  "Invalid sharedir...\n");
		//abort();
	}
	else{
		sharedir_set_dir(GET_GLOBAL_STATE()->sharedir, s->sharedir);
	}

	if(&s->chr){
		qemu_chr_fe_set_handlers(&s->chr, nyx_interface_can_receive, nyx_interface_receive, nyx_interface_event, NULL, s, NULL, true);
	}

	check_available_ipt_ranges(s);

	pt_setup_enable_hypercalls();
	init_crash_handler();
}

static Property nyx_interface_properties[] = {
	DEFINE_PROP_CHR("chardev", nyx_interface_state, chr),

	DEFINE_PROP_STRING("sharedir", nyx_interface_state, sharedir),


	DEFINE_PROP_STRING("workdir", nyx_interface_state, workdir),
	DEFINE_PROP_UINT32("worker_id", nyx_interface_state, worker_id, 0xFFFF),

	DEFINE_PROP_UINT64("cow_primary_size", nyx_interface_state, cow_primary_size, 0),
	/* 
	 * Since DEFINE_PROP_UINT64 is somehow broken (signed/unsigned madness),
	 * let's use DEFINE_PROP_STRING and post-process all values by strtol...
	 */
	DEFINE_PROP_STRING("ip0_a", nyx_interface_state, ip_filter[0][0]),
	DEFINE_PROP_STRING("ip0_b", nyx_interface_state, ip_filter[0][1]),
	DEFINE_PROP_STRING("ip1_a", nyx_interface_state, ip_filter[1][0]),
	DEFINE_PROP_STRING("ip1_b", nyx_interface_state, ip_filter[1][1]),
	DEFINE_PROP_STRING("ip2_a", nyx_interface_state, ip_filter[2][0]),
	DEFINE_PROP_STRING("ip2_b", nyx_interface_state, ip_filter[2][1]),
	DEFINE_PROP_STRING("ip3_a", nyx_interface_state, ip_filter[3][0]),
	DEFINE_PROP_STRING("ip3_b", nyx_interface_state, ip_filter[3][1]),


	DEFINE_PROP_UINT32("bitmap_size", nyx_interface_state, bitmap_size, DEFAULT_NYX_BITMAP_SIZE),
	DEFINE_PROP_UINT32("input_buffer_size", nyx_interface_state, input_buffer_size, DEFAULT_NYX_BITMAP_SIZE),
	DEFINE_PROP_BOOL("dump_pt_trace", nyx_interface_state, dump_pt_trace, false),
	DEFINE_PROP_BOOL("edge_cb_trace", nyx_interface_state, edge_cb_trace, false),


	DEFINE_PROP_END_OF_LIST(),
};

static void nyx_interface_class_init(ObjectClass *klass, void *data){
	DeviceClass *dc = DEVICE_CLASS(klass);
	//PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
	dc->realize = nyx_realize;
	//k->class_id = PCI_CLASS_MEMORY_RAM;
	dc->props = nyx_interface_properties;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
	dc->desc = "Nyx Interface";
}

static void nyx_interface_init(Object *obj){
}

static const TypeInfo nyx_interface_info = {
	.name          = TYPE_NYX_MEM,
	.parent        = TYPE_DEVICE,
	.instance_size = sizeof(nyx_interface_state),
	.instance_init = nyx_interface_init,
	.class_init    = nyx_interface_class_init,
};

static void nyx_interface_register_types(void){
	type_register_static(&nyx_interface_info);
}

type_init(nyx_interface_register_types)
