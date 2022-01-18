#pragma once

#include <stdbool.h>

void serialize_state(const char* filename_prefix, bool is_pre_snapshot);
void deserialize_state(const char* filename_prefix);
