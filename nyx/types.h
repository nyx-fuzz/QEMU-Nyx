#pragma once

enum mem_mode { 
    mm_unkown,
	mm_32_protected,    /* 32 Bit / No MMU */
	mm_32_paging,       /* 32 Bit / L3 Paging */
	mm_32_pae,          /* 32 Bit / PAE Paging */
	mm_64_l4_paging,    /* 64 Bit / L4 Paging */
	mm_64_l5_paging,    /* 32 Bit / L5 Paging */
};

typedef uint8_t mem_mode_t;
