#!/bin/bash

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

set -e

if [ -z "$BASH_VERSION" ]; then
  exit 0
fi

error()
{
  echo "$0: <option>"
  echo ""
  echo "Available compile options: "
  echo " -  dynamic       dynamically link libxdc and capstone4"
  echo " -  static        statically link libxdc and capstone4"
  echo " -  lto           statically link libxdc and capstone4 and enable LTO (up to 10% better performance)"
  echo " -  debug         enable several debug options"
  echo " -  debug_static  enable several debug options and statically link libxdc and capstone4"
  echo ""
  exit 1
}

compile_libraries()
{
  echo "[!] Compiling capstone4..."
  make -C capstone_v4 -j $(nproc)

  echo "[!] Compiling libxdc..."
  LDFLAGS="-L$PWD/capstone_v4 -L$PWD/libxdc" CFLAGS="-I$PWD/capstone_v4/include/" make -C libxdc -j $(nproc)

  case $1 in
    "dynamic"|"debug")
      echo "[!] Installing capstone4..."
      sudo make -C capstone_v4 install
      echo "[!] Installing libxdc..."
      sudo make -C libxdc install
      ;;
  esac
}

configure_qemu()
{
  QEMU_CONFIGURE="./configure --target-list=x86_64-softmmu --disable-gtk --disable-docs --enable-gtk --disable-werror --disable-capstone --disable-libssh --disable-tools"

  case $1 in
    "debug_static"|"static"|"lto")
      export LIBS="-L$PWD/capstone_v4/ -L$PWD/libxdc/ $LIBS"
      export QEMU_CFLAGS="-I$PWD/capstone_v4/include/ -I$PWD/libxdc/ $QEMU_CFLAGS"
      ;;
    *)
      error
      ;;
  esac

  case $1 in
    "dynamic")
      $QEMU_CONFIGURE --enable-nyx
      ;;
    "debug")
      $QEMU_CONFIGURE --enable-nyx --enable-sanitizers --enable-debug
      ;;
    "debug_static")
      $QEMU_CONFIGURE --enable-nyx --enable-sanitizers --enable-debug --enable-nyx-static
      ;;
    "static")
      $QEMU_CONFIGURE --enable-nyx --enable-nyx-static
      ;;
    "lto")
      $QEMU_CONFIGURE --enable-nyx --enable-nyx-static --enable-nyx-flto
      ;;
    *)
      error
      ;;
  esac
}

compile_qemu()
{
  test -f GNUmakefile && rm GNUmakefile 2> /dev/null
  make -j $(nproc)
}


if [ "$#" -ne 1 ] ; then
  error
fi

git submodule init
git submodule update libxdc
git submodule update capstone_v4

make clean
compile_libraries $1
configure_qemu $1
compile_qemu
