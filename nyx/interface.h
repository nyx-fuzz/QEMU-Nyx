/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

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

#ifndef INTERFACE_H
#define INTERFACE_H

/* 64k bitmap + 4k ijon buffer */
#define DEFAULT_KAFL_IJON_BITMAP_SIZE 0x1000
#define DEFAULT_KAFL_BITMAP_SIZE	0x10000 + DEFAULT_KAFL_IJON_BITMAP_SIZE
#define DEFAULT_EDGE_FILTER_SIZE	0x1000000

#define PROGRAM_SIZE				(128 << 20) /* 128MB Application Data */
#define PAYLOAD_SIZE				(128 << 10)	/* 128KB Payload Data */
#define INFO_SIZE					(128 << 10)	/* 128KB Info Data */
#define HPRINTF_SIZE				0x1000 		/* 4KB hprintf Data */

#define INFO_FILE					"/tmp/kAFL_info.txt"
#define HPRINTF_FILE				"/tmp/kAFL_printf.txt"

#define HPRINTF_LIMIT				512

#define KAFL_PING           'x'

bool interface_send_char(char val);

#endif
