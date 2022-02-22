#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

#include "state/state.h"
#include "trace_dump.h"

/* dump PT trace as returned from HW */

char *pt_trace_dump_filename;
bool pt_dump_initialized = false;
bool pt_dump_enabled = false;

void pt_trace_dump_enable(bool enable){
	if (pt_dump_initialized)
		pt_dump_enabled = enable;
}

void pt_trace_dump_init(char* filename)
{
	int test_fd;

	//fprintf(stderr, "Enable pt trace dump at %s", filename);
	pt_dump_initialized = true;

	test_fd = open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (test_fd < 0)
		fprintf(stderr, "Error accessing pt_dump output path %s: %s", pt_trace_dump_filename, strerror(errno));
	assert(test_fd >= 0);

	pt_trace_dump_filename = strdup(filename);
	assert(pt_trace_dump_filename);
}

void pt_truncate_pt_dump_file(void) {
	int fd;

	if (!pt_dump_enabled)
		return;

	fd = open(pt_trace_dump_filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd < 0) {
		fprintf(stderr, "Error truncating %s: %s\n", pt_trace_dump_filename, strerror(errno));
		assert(0);
	}
	close(fd);
}

void pt_write_pt_dump_file(uint8_t *data, size_t bytes)
{
	int fd;

	if (!pt_dump_enabled)
		return;

	fd = open(pt_trace_dump_filename, O_APPEND|O_WRONLY, 0644);
	//fd = open(pt_trace_dump_filename, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd < 0) {
		fprintf(stderr, "Error writing pt_trace_dump to %s: %s\n", pt_trace_dump_filename, strerror(errno));
		assert(0);
	}
    assert(bytes == write(fd, data, bytes));
	close(fd);
}

