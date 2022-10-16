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
#define DEFAULT_NYX_IJON_BITMAP_SIZE 0x1000  /* fixed size buffer for IJON -> 4k */
#define DEFAULT_NYX_BITMAP_SIZE      0x10000 /* default bitmap size => 64k */

#define NYX_INTERFACE_PING 'x'

bool interface_send_char(char val);

#endif
