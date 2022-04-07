#pragma once

void pt_trace_dump_init(char* filename);
void pt_trace_dump_enable(bool enable);
void pt_write_pt_dump_file(uint8_t *data, size_t bytes);
void pt_truncate_pt_dump_file(void);
