#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


// doesn't take ownership of path, num_addrs or addrs
void parse_address_file(char *path, size_t *num_addrs, uint64_t **addrs);

// doesn't take ownership of buf
void write_re_result(char *buf);

// doesn't take ownership of buf
void write_se_result(char *buf);

// doesn' take ownership of buf
void write_debug_result(char *buf);

void delete_redqueen_files(void);

void fsync_redqueen_files(void);
