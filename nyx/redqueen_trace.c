#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include "redqueen_trace.h"

/* write full trace of edge transitions rather than sorted list? */
//#define KAFL_FULL_TRACES

#ifdef KAFL_FULL_TRACES
#include "redqueen.h"
#endif

redqueen_trace_t* redqueen_trace_new(void){
	redqueen_trace_t* self = malloc(sizeof(redqueen_trace_t));
	self->lookup = kh_init(RQ_TRACE);
	self->num_ordered_transitions = 0;
	self->max_ordered_transitions = INIT_NUM_OF_STORED_TRANSITIONS;
	self->ordered_transitions = malloc(INIT_NUM_OF_STORED_TRANSITIONS*sizeof(uint128_t));
	return self;
}

void redqueen_trace_reset(redqueen_trace_t* self){
	kh_destroy(RQ_TRACE, self->lookup);
	self->lookup = kh_init(RQ_TRACE);
	self->num_ordered_transitions = 0;
}

void redqueen_trace_free(redqueen_trace_t* self){
	kh_destroy(RQ_TRACE, self->lookup);
	free(self->ordered_transitions);
	free(self);
}

void redqueen_trace_register_transition(redqueen_trace_t* self, disassembler_mode_t mode, uint64_t from, uint64_t to){
	khiter_t k;
	int ret;
#ifdef KAFL_FULL_TRACES
	extern int trace_fd;
	if (!trace_fd)
		trace_fd = open(redqueen_workdir.pt_trace_results, O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
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

void redqueen_trace_write_file(redqueen_trace_t* self, int fd){
#ifdef KAFL_FULL_TRACES
	return;
#endif
	for(size_t i = 0; i < self->num_ordered_transitions; i++){
		khiter_t k;
		uint128_t key = self->ordered_transitions[i];
		k = kh_get(RQ_TRACE, self->lookup, key); 
		assert(k != kh_end(self->lookup));
		dprintf(fd, "%lx,%lx,%lx\n",  (uint64_t)(key>>64), (uint64_t)key, kh_value(self->lookup, k) );
	}
}


#ifdef DEBUG_MAIN
int main(int argc, char** argv){

	redqueen_trace_t* rq_obj = redqueen_trace_new();

	for (uint64_t j = 0; j < 0x5; j++){
		redqueen_trace_register_transition(rq_obj, 0xBADF, 0xC0FFEE);
		redqueen_trace_register_transition(rq_obj, 0xBADBEEF, 0xC0FFEE);
		for (uint64_t i = 0; i < 0x10000; i++){
			redqueen_trace_register_transition(rq_obj, 0xBADBEEF, 0xC0FFEE);
		}
		redqueen_trace_write_file(rq_obj, STDOUT_FILENO);
		redqueen_trace_reset(rq_obj);
	}

	redqueen_trace_free(rq_obj);
	return 0;
}
#endif
