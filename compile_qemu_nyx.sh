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
  echo " -  dynamic        dynamically link libxdc and capstone4"
  echo " -  static         statically link libxdc and capstone4"
  echo " -  full_static    compile a full static QEMU build"
  echo " -  lto            enable static linking and LTO (up to 10% better performance)"
  echo " -  debug          enable debug and ASAN options"
  echo " -  debug_static   enable debug, ASAN and static linking"
  echo ""
  exit 1
}

compile_libraries()
{
  case $1 in
    "debug_static"|"static"|"full_static"|"lto")
      echo "[!] Compiling capstone4..."
      make -C $CAPSTONE_ROOT -j $(nproc)

      echo "[!] Compiling libxdc..."
      set +e
      make -C $LIBXDC_ROOT clean
      LDFLAGS="-L$CAPSTONE_ROOT -L$LIBXDC_ROOT" CFLAGS="-I$CAPSTONE_ROOT/include/" make -C $LIBXDC_ROOT -j $(nproc)
      if [ $? -ne 0 ]; then
          echo "[!] libxdc LTO build failed! Trying to compile in non-LTO mode..."
          make -C $LIBXDC_ROOT clean
          NO_LTO=1 LDFLAGS="-L$CAPSTONE_ROOT -L$LIBXDC_ROOT" CFLAGS="-I$CAPSTONE_ROOT/include/" make -C $LIBXDC_ROOT -j $(nproc)
          if [ $? -ne 0 ]; then
              echo "[ ] libxdc non-LTO build failed again ..."
              exit 1
          fi
      fi
      set -e
    ;;
  esac
}

configure_qemu()
{
  QEMU_CONFIGURE="./configure --target-list=x86_64-softmmu --disable-docs --disable-gtk --disable-werror --disable-capstone --disable-libssh --disable-tools"

  case $1 in
    "debug_static"|"static"|"full_static"|"lto")
      export LIBS="-L$CAPSTONE_ROOT -L$LIBXDC_ROOT/ $LIBS"
      export QEMU_CFLAGS="-I$CAPSTONE_ROOT/include/ -I$LIBXDC_ROOT/ $QEMU_CFLAGS"
      ;;
    *)
      ;;
  esac

  case $1 in
    "dynamic")
      $QEMU_CONFIGURE --enable-nyx
      ;;
    "debug")
      $QEMU_CONFIGURE --enable-nyx --enable-sanitizers --enable-debug --enable-nyx-debug
      ;;
    "debug_static")
      $QEMU_CONFIGURE --enable-nyx --enable-sanitizers --enable-debug --enable-nyx-debug --enable-nyx-static
      ;;
    "static")
      $QEMU_CONFIGURE --enable-nyx --enable-nyx-static
      ;;
    "full_static")
      $QEMU_CONFIGURE --enable-nyx --enable-nyx-static --static --enable-slirp=git --disable-xkbcommon --disable-usb-redir --disable-smartcard --disable-opengl --audio-drv-list= --disable-libusb --disable-rdma --disable-libiscsi
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

case $1 in
    "dynamic"|"debug"|"debug_static"|"static"|"full_static"|"lto")
      ;;
    *)
      error
      ;;
  esac

if [ -z "$LIBXDC_ROOT" -o -z "$CAPSTONE_ROOT" ]; then
	git submodule init
	git submodule update libxdc
	git submodule update capstone_v4
	
	LIBXDC_ROOT="$PWD/libxdc"
	CAPSTONE_ROOT="$PWD/capstone_v4"
fi

make clean
compile_libraries $1
configure_qemu $1
compile_qemu
