#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "redqueen_trace.h"
#include "redqueen.h"
#include "state/state.h"


/* write full trace of edge transitions rather than sorted list? */
//#define KAFL_FULL_TRACES

int trace_fd = 0;
int redqueen_trace_enabled = false;

uint32_t alt_bitmap_size = 0;
uint8_t* alt_bitmap = NULL;

void alt_bitmap_init(void* ptr, uint32_t size)
{
	if (redqueen_trace_enabled) {
		alt_bitmap = (uint8_t*)ptr;
		alt_bitmap_size = size;
	}
}

void alt_bitmap_reset(void)
{
	if (alt_bitmap) {
		memset(alt_bitmap, 0x00, alt_bitmap_size);
	}
}

static inline uint64_t mix_bits(uint64_t v) {
  v ^= (v >> 31);
  v *= 0x7fb5d329728ea185;
  return v;
}

/*
 * quick+dirty bitmap based on libxdc trace callback
 * similar but not itentical to libxdc bitmap.
 */
static void alt_bitmap_add(uint64_t from, uint64_t to)
{
	uint64_t transition_value;

	if (GET_GLOBAL_STATE()->trace_mode) {
		if(alt_bitmap) {
			transition_value = mix_bits(to)^(mix_bits(from)>>1);
			alt_bitmap[transition_value & (alt_bitmap_size-1)]++;
		}
	}
}


static int reset_trace_fd(void) {
	if (trace_fd)
		close(trace_fd);
	trace_fd = open(redqueen_workdir.pt_trace_results, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (trace_fd < 0) {
		fprintf(stderr, "Failed to initiate trace output: %s\n", strerror(errno));
		assert(0);
	}
	return trace_fd;
}

void redqueen_trace_init(void) {
	redqueen_trace_enabled = true;
}

redqueen_trace_t* redqueen_trace_new(void){
	redqueen_trace_t* self = malloc(sizeof(redqueen_trace_t));
	self->lookup = kh_init(RQ_TRACE);
	self->num_ordered_transitions = 0;
	self->max_ordered_transitions = INIT_NUM_OF_STORED_TRANSITIONS;
	self->ordered_transitions = malloc(INIT_NUM_OF_STORED_TRANSITIONS*sizeof(uint128_t));
	return self;
}

void redqueen_trace_free(redqueen_trace_t* self){
	kh_destroy(RQ_TRACE, self->lookup);
	free(self->ordered_transitions);
	free(self);
}

void redqueen_trace_register_transition(redqueen_trace_t* self, disassembler_mode_t mode, uint64_t from, uint64_t to){
	khiter_t k;
	int ret;
	uint64_t exit_ip = 0xffffffffffffffff;

	if (from != exit_ip && to != exit_ip)
		alt_bitmap_add(from, to);
#ifdef KAFL_FULL_TRACES
	assert(trace_fd >= 0);
	dprintf(trace_fd, "%lx,%lx\n", from, to);
	return;
#endif
	uint128_t key = (((uint128_t)from)<<64) | ((uint128_t)to);
	k = kh_get(RQ_TRACE, self->lookup, key); 
	if(k != kh_end(self->lookup)){
		kh_value(self->lookup, k) += 1; 
	} else{
		k = kh_put(RQ_TRACE, self->lookup, key, &ret); 
		kh_value(self->lookup, k) = 1;
		self->ordered_transitions[self->num_ordered_transitions] = key;
		self->num_ordered_transitions++;
		assert(self->num_ordered_transitions < self->max_ordered_transitions);
	}
}	

static void redqueen_trace_write(void){
#ifdef KAFL_FULL_TRACES
	return;
#endif
	redqueen_trace_t *self = GET_GLOBAL_STATE()->redqueen_state->trace_state;
	assert(trace_fd >= 0);
	for(size_t i = 0; i < self->num_ordered_transitions; i++){
		khiter_t k;
		uint128_t key = self->ordered_transitions[i];
		k = kh_get(RQ_TRACE, self->lookup, key); 
		assert(k != kh_end(self->lookup));
		dprintf(trace_fd, "%lx,%lx,%lx\n",  (uint64_t)(key>>64), (uint64_t)key, kh_value(self->lookup, k) );
	}
}

static void redqueen_state_reset(void){
	redqueen_trace_t *self = GET_GLOBAL_STATE()->redqueen_state->trace_state;
	kh_destroy(RQ_TRACE, self->lookup);
	self->lookup = kh_init(RQ_TRACE);
	self->num_ordered_transitions = 0;
}


void redqueen_trace_reset(void){
	if (redqueen_trace_enabled) {
		redqueen_state_reset();
		reset_trace_fd();
	}
}

void redqueen_trace_flush(void){
	if (redqueen_trace_enabled) {
		redqueen_trace_write();
		if (trace_fd)
			fsync(trace_fd);
	}
}

void redqueen_set_trace_mode(void){
	if (redqueen_trace_enabled) {
		libxdc_enable_tracing(GET_GLOBAL_STATE()->decoder);
		libxdc_register_edge_callback(GET_GLOBAL_STATE()->decoder,
				(void (*)(void*, disassembler_mode_t, uint64_t, uint64_t))&redqueen_trace_register_transition,
				GET_GLOBAL_STATE()->redqueen_state->trace_state);
	}
}

void redqueen_unset_trace_mode(void){
	if (redqueen_trace_enabled) {
		libxdc_disable_tracing(GET_GLOBAL_STATE()->decoder);
	}
}

#ifdef DEBUG_MAIN
int main(int argc, char** argv){

	redqueen_trace_t* rq_obj = redqueen_trace_new();

	reset_trace_fd();

	for (uint64_t j = 0; j < 0x5; j++){
		redqueen_trace_register_transition(rq_obj, 0xBADF, 0xC0FFEE);
		redqueen_trace_register_transition(rq_obj, 0xBADBEEF, 0xC0FFEE);
		for (uint64_t i = 0; i < 0x10000; i++){
			redqueen_trace_register_transition(rq_obj, 0xBADBEEF, 0xC0FFEE);
		}
		redqueen_trace_write(rq_obj, STDOUT_FILENO);
		redqueen_trace_reset();
	}

	redqueen_trace_free(rq_obj);
	return 0;
}
#endif
