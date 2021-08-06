#ifndef _GNU_SOURCE
#define _GNU_SOURCE  
#endif
#include <errno.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <sys/file.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include "page_cache.h"
#include "debug.h"
#ifndef STANDALONE_DECODER
#include "cpu.h"
#include "memory_access.h"
#include "fast_vm_reload.h"
#include "kvm_nested.h"
#include "nyx/state/state.h"
#endif


#define PAGE_CACHE_ADDR_LINE_SIZE sizeof(uint64_t)

#define UNMAPPED_PAGE 0xFFFFFFFFFFFFFFFFULL

static void page_cache_unlock(page_cache_t* self);
static void page_cache_lock(page_cache_t* self);

#ifndef STANDALONE_DECODER
static bool reload_addresses(page_cache_t* self){
#else
bool reload_addresses(page_cache_t* self){
#endif
	khiter_t k;
	int ret;
	uint64_t addr, offset;
	uint64_t value = 0;

	size_t self_offset = lseek(self->fd_address_file, 0, SEEK_END);

	if(self_offset != self->num_pages*PAGE_CACHE_ADDR_LINE_SIZE){
		//fprintf(stderr, "Reloading files ...\n");

		page_cache_lock(self); // don't read while someone else is writing?

		lseek(self->fd_address_file, self->num_pages*PAGE_CACHE_ADDR_LINE_SIZE, SEEK_SET);
		offset = self->num_pages;
		while(read(self->fd_address_file, &value, PAGE_CACHE_ADDR_LINE_SIZE)){
			addr = value & 0xFFFFFFFFFFFFF000ULL; 
			offset++;

			/* put new addresses and offsets into the hash map */
			k = kh_get(PC_CACHE, self->lookup, addr); 
			if(k == kh_end(self->lookup)){

				if(value & 0xFFF){
					fprintf(stderr, "Load page: %lx (UMAPPED)\n", addr);
					//k = kh_put(PC_CACHE, self->lookup, addr, &ret); 
					//kh_value(self->lookup, k) = UNMAPPED_PAGE;
				}
				else{
					//fprintf(stderr, "Load page: %lx\n", addr);
					k = kh_put(PC_CACHE, self->lookup, addr, &ret); 
					kh_value(self->lookup, k) = (offset-1)*PAGE_SIZE;
				}

				/*
				k = kh_put(PC_CACHE, self->lookup, addr, &ret); 
				kh_value(self->lookup, k) = (offset-1)*PAGE_SIZE;
				*/
			}
			else{
				fprintf(stderr, "----------> Page duplicate found ...skipping! %lx\n", addr);
				/* should not be possible ... */
				//abort();
			}
		}

		//fprintf(stderr, "Old Value: %d - New Value: %ld\n", self->num_pages, (uint32_t)self_offset/PAGE_CACHE_ADDR_LINE_SIZE);

		/* reload page dump file */
		munmap(self->page_data, self->num_pages*PAGE_SIZE);
		self->num_pages = self_offset/PAGE_CACHE_ADDR_LINE_SIZE;
		self->page_data = mmap(NULL, (self->num_pages)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
				
		page_cache_unlock(self);

		return true;
	}

	return false;
}

#ifndef STANDALONE_DECODER
static bool append_page(page_cache_t* self, uint64_t page, uint64_t cr3){
	bool success = true;
	if(!self->num_pages){
		assert(!ftruncate(self->fd_page_file, (self->num_pages+1)*PAGE_SIZE));
		self->page_data = mmap(NULL, (self->num_pages+1)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
	}
	else{
		munmap(self->page_data, self->num_pages*PAGE_SIZE);
		assert(!ftruncate(self->fd_page_file, (self->num_pages+1)*PAGE_SIZE));
		self->page_data = mmap(NULL, (self->num_pages+1)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
	}

	
	//if(!dump_page_cr3_snapshot(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->pt_c3_filter)){
	//	if(!dump_page_cr3_snapshot(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->parent_cr3)){
	if(!dump_page_cr3_ht(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->pt_c3_filter)){
		if(!dump_page_cr3_ht(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->parent_cr3)){
			if(!dump_page_cr3_snapshot(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->parent_cr3)){

				//fprintf(stderr, "FAILED DUMP PROCESS of PAGE %lx\n", page);
				//memset(self->page_data+(PAGE_SIZE*self->num_pages), 0xff, PAGE_SIZE);

				munmap(self->page_data, (self->num_pages+1)*PAGE_SIZE);
				assert(!ftruncate(self->fd_page_file, (self->num_pages)*PAGE_SIZE));
				self->page_data = mmap(NULL, (self->num_pages)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);

				//qemu_backtrace();
				success = false;
				return success;
				//assert(false);
			}
		}
	}
	//}

/*
	if(!dump_page_cr3_ht(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->parent_cr3)){
			fprintf(stderr, "FAILED DUMP PROCESS of PAGE %lx\n", page);
			assert(false);
		}
*/

	/*
	//fast_loadvm();
	if(cr3){
		dump_page_cr3_ht(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->parent_cr3); //self->cpu->parent_cr3);
		//assert(dump_page_cr3_snapshot(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu, GET_GLOBAL_STATE()->parent_cr3)); //self->cpu->parent_cr3);

		//read_virtual_memory_cr3(page, self->page_data+(PAGE_SIZE*self->num_pages), PAGE_SIZE, self->cpu, self->cpu->parent_cr3);
	}
	else{
		dump_page_ht(page, self->page_data+(PAGE_SIZE*self->num_pages), self->cpu);
		//read_virtual_memory(page, self->page_data+(PAGE_SIZE*self->num_pages), PAGE_SIZE, self->cpu);
	}
	*/
	fsync(self->fd_page_file);
	self->num_pages++;
	return success;
}
#else
bool append_page(page_cache_t* self, uint64_t page, uint8_t* ptr){
	self->last_page = 0xFFFFFFFFFFFFFFFF;
	self->last_addr = 0xFFFFFFFFFFFFFFFF;
	page &= 0xFFFFFFFFFFFFF000ULL;
	bool success = true;
	if(!self->num_pages){
		assert(!ftruncate(self->fd_page_file, (self->num_pages+1)*PAGE_SIZE));
		self->page_data = mmap(NULL, (self->num_pages+1)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
	}
	else{
		munmap(self->page_data, self->num_pages*PAGE_SIZE);
		assert(!ftruncate(self->fd_page_file, (self->num_pages+1)*PAGE_SIZE));
		self->page_data = mmap(NULL, (self->num_pages+1)*PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, self->fd_page_file, 0);
	}

	memcpy(self->page_data+(PAGE_SIZE*self->num_pages), ptr, PAGE_SIZE);

	fsync(self->fd_page_file);

	int ret;
	khiter_t k;
	k = kh_put(PC_CACHE, self->lookup, page, &ret); 
	kh_value(self->lookup, k) = self->num_pages*PAGE_SIZE;
	assert(write(self->fd_address_file, &page, PAGE_CACHE_ADDR_LINE_SIZE) == PAGE_CACHE_ADDR_LINE_SIZE);

	self->num_pages++;

	return success;
}
#endif

static void page_cache_lock(page_cache_t* self){
#ifndef STANDALONE_DECODER
	int ret = 0;
	while (true){
		ret = flock(self->fd_lock, LOCK_EX);
		if (ret == 0){
			return;
		}
		else if (ret == EINTR){ 
			/* try again if acquiring this lock has failed */
			fprintf(stderr, "%s: interrupted by signal...\n", __func__);
		}
		else{
			assert(false);
		}
	}
#endif
}

static void page_cache_unlock(page_cache_t* self){
#ifndef STANDALONE_DECODER
	int ret = 0;
	while (true){
		ret = flock(self->fd_lock, LOCK_UN);
		if (ret == 0){
			return;
		}
		else if (ret == EINTR){ 
			/* try again if releasing this lock has failed */
			fprintf(stderr, "%s: interrupted by signal...\n", __func__);
		}
		else{
			assert(false);
		}
	}
#endif
}

static bool update_page_cache(page_cache_t* self, uint64_t page, khiter_t* k){

	//#define DEBUG_PAGE_CACHE_LOCK

	page_cache_lock(self);
#ifdef DEBUG_PAGE_CACHE_LOCK
	fprintf(stderr, "%d: LOCKING PAGE CACHE\n", getpid());
#endif

	if(reload_addresses(self)){
		*k = kh_get(PC_CACHE, self->lookup, page); 
	}


	if(*k == kh_end(self->lookup)){
#ifndef STANDALONE_DECODER
		int ret;

		uint64_t cr3 = GET_GLOBAL_STATE()->parent_cr3; //self->cpu->parent_cr3;
		if(!is_addr_mapped_cr3_snapshot(page, self->cpu, GET_GLOBAL_STATE()->parent_cr3) && !is_addr_mapped_cr3_snapshot(page, self->cpu, GET_GLOBAL_STATE()->pt_c3_filter)){ //self->cpu->parent_cr3)){
			//fprintf(stderr, "PAGE NOT FOUND in SNAPSHOT %lx\n", page);
			//assert(false);
		}

		*k = kh_get(PC_CACHE, self->lookup, page); 

		if(*k == kh_end(self->lookup) && reload_addresses(self)){
			/* reload sucessful */
			*k = kh_get(PC_CACHE, self->lookup, page); 
		}
		else{
			

			if(append_page(self, page, cr3)){
				*k = kh_put(PC_CACHE, self->lookup, page, &ret); 
				assert(write(self->fd_address_file, &page, PAGE_CACHE_ADDR_LINE_SIZE) == PAGE_CACHE_ADDR_LINE_SIZE);
				kh_value(self->lookup, *k) = (self->num_pages-1)*PAGE_SIZE;
			}
			else{
				//fprintf(stderr, "Fail!!!!\n");
				page_cache_unlock(self);
				return false;
				/*
				uint64_t new_page = page | 0xFFF;
				assert(write(self->fd_address_file, &new_page, PAGE_CACHE_ADDR_LINE_SIZE) == PAGE_CACHE_ADDR_LINE_SIZE);
				kh_value(self->lookup, *k) = UNMAPPED_PAGE;
				fprintf(stderr, "APPEND UNMAPPED PAGE %lx!\n", page);
				*/
			}

			*k = kh_get(PC_CACHE, self->lookup, page); 
		}
#else
		//printf("PAGE NOT FOUND: %lx! ABORTING\n", page);
		page_cache_unlock(self);
		return false;
		abort();
#endif
	}
	
#ifdef DEBUG_PAGE_CACHE_LOCK
	fprintf(stderr, "%d: UNLOCKING PAGE CACHE\n", getpid());
#endif

	page_cache_unlock(self);
	return true;
}

uint64_t page_cache_fetch(page_cache_t* self, uint64_t page, bool* success, bool test_mode){	
	page &= 0xFFFFFFFFFFFFF000ULL;

	/*
	if(test_mode){
		*success = false;
		return 0;
	}
	*/

	//if(page == 0x7ffca45b5000)
	//	return UNMAPPED_PAGE;
	//printf("%s %lx\n", __func__, page);

	//if (page == 0x0434000)
	//	return 0;

	if (self->last_page == page){
		*success = true;
		return self->last_addr;
	}

	//QEMU_PT_PRINTF(PAGE_CACHE_PREFIX, "page_cache_fetch %lx", page);
	
	khiter_t k;
	k = kh_get(PC_CACHE, self->lookup, page); 
	if(k == kh_end(self->lookup)){
		if(test_mode || update_page_cache(self, page, &k) == false){
			//fprintf(stderr, "%s: fail!\n", __func__);
			*success = false;
			//abort();
			return 0;
		}
	}

	self->last_page = page;
	//fprintf(stderr, "[%d]\tkh_n_buckets: %d %d\n", getpid(), kh_n_buckets(self->lookup), k);

	if(kh_value(self->lookup, k) == UNMAPPED_PAGE){
		self->last_addr = UNMAPPED_PAGE;
	}
	else{
		self->last_addr = (uint64_t)self->page_data+kh_value(self->lookup, k);
	}



	//fprintf(stderr, "try to unlock flock!\n");
	//fprintf(stderr, "flock unlocked!\n");

	*success = true;
	return self->last_addr;
}

/* fix this */
uint64_t page_cache_fetch2(page_cache_t* self, uint64_t page, bool* success){	
	return page_cache_fetch(self, page, success, false);
}

#ifndef STANDALONE_DECODER
page_cache_t* page_cache_new(CPUState *cpu, const char* cache_file){
#else
page_cache_t* page_cache_new(const char* cache_file, uint8_t disassembler_word_width){
#endif
	page_cache_t* self = malloc(sizeof(page_cache_t));

	char* tmp1;
	char* tmp2;
	char* tmp3;
	assert(asprintf(&tmp1, "%s.dump", cache_file) != -1);
	assert(asprintf(&tmp2, "%s.addr", cache_file) != -1);
	assert(asprintf(&tmp3, "%s.lock", cache_file) != -1);


	self->lookup = kh_init(PC_CACHE);
	self->fd_page_file = open(tmp1, O_CLOEXEC | O_CREAT | O_RDWR, 0644);
	self->fd_address_file = open(tmp2, O_CLOEXEC | O_CREAT | O_RDWR, 0644);

#ifndef STANDALONE_DECODER
	self->cpu = cpu;
	self->fd_lock = open(tmp3, O_CLOEXEC | O_CREAT, 0644);
	assert(self->fd_lock > 0);
#else
	if(self->fd_page_file == -1 || self->fd_address_file == -1){
		printf("[ ] Page cache files not found...\n");
		exit(1);
	}
#endif

	memset(self->disassemble_cache, 0x0, 16);

	self->page_data = NULL;
	self->num_pages = 0;

	self->last_page = 0xFFFFFFFFFFFFFFFF;
	self->last_addr = 0xFFFFFFFFFFFFFFFF;

#ifndef STANDALONE_DECODER
	QEMU_PT_PRINTF(PAGE_CACHE_PREFIX, "%s (%s - %s)", __func__, tmp1, tmp2);
#else
	QEMU_PT_PRINTF(PAGE_CACHE_PREFIX, "%s (%s - %s) WORD_WIDTH: %d", __func__, tmp1, tmp2, disassembler_word_width);
#endif

	free(tmp3);
	free(tmp2);
	free(tmp1);

	if (cs_open(CS_ARCH_X86, CS_MODE_16, &self->handle_16) != CS_ERR_OK)
		assert(false);

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &self->handle_32) != CS_ERR_OK)
		assert(false);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &self->handle_64) != CS_ERR_OK)
		assert(false);

	cs_option(self->handle_16, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(self->handle_32, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(self->handle_64, CS_OPT_DETAIL, CS_OPT_ON);

	return self;
}

#ifdef STANDALONE_DECODER
void page_cache_destroy(page_cache_t* self){
	munmap(self->page_data, self->num_pages * 0x1000);
	kh_destroy(PC_CACHE, self->lookup);

	cs_close(&self->handle_16);
	cs_close(&self->handle_32);
	cs_close(&self->handle_64);
	free(self);
}
#endif


/*
static bool page_cache_load(uint64_t virtual_addr){


	return true;
}
*/

/*

static bool page_cache_load_cr3(uint64_t virtual_addr, uint64_t cr3){
	return true;
}

*/

bool page_cache_disassemble(page_cache_t* self, uint64_t address, cs_insn **insn){
	return true;
}

cs_insn* page_cache_cs_malloc(page_cache_t* self, disassembler_mode_t mode){
	switch(mode){
		case mode_16:
			return cs_malloc(self->handle_16);
		case mode_32:
			return cs_malloc(self->handle_32);
		case mode_64:
			return cs_malloc(self->handle_64);
		default:
			assert(false);
	}
	return NULL;
}

//#define EXPERIMENTAL_PAGE_FETCH

bool page_cache_disassemble_iter(page_cache_t* self, uint64_t* address, cs_insn *insn, uint64_t* failed_page, disassembler_mode_t mode){

	//printf("%s %lx\n", __func__, *address);

	*failed_page = 0xFFFFFFFFFFFFFFFFULL;

	bool success = true;
	size_t code_size = 16;

#if defined(STANDALONE_DECODER) || !defined(EXPERIMENTAL_PAGE_FETCH)
	uint8_t* code = (uint8_t*)page_cache_fetch(self, *address, &success, false);
#else
	uint8_t* code = (uint8_t*)page_cache_fetch(self, *address, &success, true);
#endif
	uint8_t* code_ptr = 0;


	//disassembler_mode_t mode = mode_16;
	csh* current_handle = NULL;

	switch(mode){
		case mode_16:
			current_handle = &self->handle_16;
			break;
		case mode_32:
			current_handle = &self->handle_32;
			break;
		case mode_64:
			current_handle = &self->handle_64;
			break;
		default:
			assert(false);
	}

	if (code == (void*)UNMAPPED_PAGE || success == false){
		*failed_page = *address;// & 0xFFFFFFFFFFFFF000ULL;
		//printf("FAIL???? (0x%lx) %lx %d\n", *address, code, success);
		return false;
	}

	if ((*address & 0xFFF) >= (0x1000-16)){
		//printf("-------------> Disassemble between pages...%lx (%lx %lx %lx)\n", *address, (*address&0xFFF), (0x1000-16), 0xf-(0xfff-(*address&0xfff)));
		memcpy((void*)self->disassemble_cache, (void*)((uint64_t)code+(0x1000-16)), 16);
		code_ptr = self->disassemble_cache + 0xf-(0xfff-(*address&0xfff));

#if defined(STANDALONE_DECODER) || !defined(EXPERIMENTAL_PAGE_FETCH)
		code = (uint8_t*)page_cache_fetch(self, *address+0x1000, &success, false);
#else
		code = (uint8_t*)page_cache_fetch(self, *address+0x1000, &success, true);
#endif

		/* broken AF */
		if(success == true){
			//printf("=> A\n");
			//*failed_page = (*address+0x1000) & 0xFFFFFFFFFFFFF000ULL;
			//return false;
			//printf("=> %lx %lx\n", (0xfff-(*address&0xfff)), *address);
			memcpy((void*)(self->disassemble_cache+16), (void*)code, 16);
			//code_size = 16;
			return cs_disasm_iter(*current_handle, (const uint8_t**) &code_ptr, &code_size, address, insn);
		}
		else{
			//printf("=> B\n");
			code_size = (0xfff-(*address&0xfff));
			//printf("%lx\n", code_size);
			//abort();
			//*failed_page = *address;
			if(!cs_disasm_iter(*current_handle, (const uint8_t**) &code_ptr, &code_size, address, insn)){
				*failed_page = (*address+0x1000) & 0xFFFFFFFFFFFFF000ULL;
				//fprintf(stderr, "%s FAIL: %lx %lx\n", __func__, *address, *failed_page);
				//if(*address != 0x555555554ffe && *address != 0x7ffff7478ffc && *address != 0x7ffff7820ff6 && *address != 0x7ffff7822ffa)
				//	abort();
				return false;
			}
			return true;
			//return cs_disasm_iter(self->handle, (const uint8_t**) &code_ptr, &code_size, address, insn);
		}
	} 
	else {
		//printf("=> C\n");
		code_ptr = code + (*address&0xFFF);

		//printf("Disassemble...(%lx %x)\n", code_ptr, *code_ptr);
		return cs_disasm_iter(*current_handle, (const uint8_t**) &code_ptr, &code_size, address, insn);
	}
}


