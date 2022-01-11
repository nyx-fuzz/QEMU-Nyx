#!/bin/bash
set -e

# Copyright (C) 2021 Sergej Schumilo
# 
# This file is part of NYX.
# 
# QEMU-PT is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
# 
# QEMU-PT is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.


if [ ! -f "/usr/lib/libxdc.so" ] || [ ! -f "/usr/include/libxdc.h" ]; then
  echo "[!] libxdc not found! Installing..."
  if [ -d "capstone_v4/" ]; then
    rm -rf capstone_v4
  fi

  if [ -d "libxdc/" ]; then
    rm -rf libxdc
  fi

  git clone https://github.com/nyx-fuzz/libxdc.git
  git clone https://github.com/aquynh/capstone.git capstone_v4
  cd capstone_v4
  git checkout v4
  make 
  sudo make install 
  cd ..
  cd libxdc
  git checkout 641de7539e99f7faf5c8e8f1c8a4b37a9df52a5f
  sudo make install
  cd ..
fi

./configure --target-list=x86_64-softmmu --enable-gtk --disable-werror --disable-capstone --disable-libssh --enable-nyx --disable-tools
#--enable-sanitizers

if [ -f GNUmakefile ]; then
  rm GNUmakefile 2> /dev/null
fi

make -j

