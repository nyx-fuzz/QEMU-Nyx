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


if [ -z "$BASH_VERSION" ]; then
  exit 0
fi

error () {
  echo "$0: <option>"
  echo ""
  echo "Available compile options: "
  echo " -  dynamic       dynamically link libxdc and capstone4"
  echo " -  static        statically link libxdc and capstone4"
  echo " -  lto           statically link libxdc and capstone4 and enable LTO (up to 10% better performance)"
  echo " -  debug         enable several debug options"
  echo " -  debug_static  enable several debug options and statically link libxdc and capstone4"
  echo ""
  exit 3
}

compile_libraries (){
  echo "[!] compiling capstone4..."
  cd capstone_v4
  make -j
  cd ..
  echo "[!] capstone4 is ready!"

  echo "[!] compiling libxdc..."
  cd libxdc
  CFLAGS="-I../capstone_v4/include/" V=1 make libxdc.a
  cd ..
  echo "[!] libxdc is ready!"
}

compile_and_install_libraries () {
  if [ ! -f "/usr/lib/libcapstone.so" ] || [ ! -d "/usr/include/capstone/" ]; then
    echo "[!] capstone not found! Installing..."
    cd capstone_v4
    make -j
    echo "[ ] requesting permissions to install capstone4 ..."
    sudo make install
    echo "[!] done ..."
    cd ..
  fi

  if [ ! -f "/usr/lib/libxdc.so" ] || [ ! -f "/usr/include/libxdc.h" ]; then
    echo "[!] libxdc not found! Installing..."
    cd libxdc
    make -j
    echo "[ ] requesting permissions to install libxdc ..."
    sudo make install
    echo "[!] done ..."
    cd ..
  fi
}

compile () {
  if [ -f GNUmakefile ]; then
    rm GNUmakefile 2> /dev/null
  fi

  make -j
  echo "[!] QEMU-Nyx is ready!"
}

git submodule init
git submodule update libxdc
git submodule update capstone_v4

if [ "$#" == 0 ] ; then
  error
fi

if [ "$1" == "dynamic" ]; 
then 

  make clean
  compile_and_install_libraries
  ./configure --target-list=x86_64-softmmu --disable-gtk --disable-docs --enable-gtk --disable-werror --disable-capstone --disable-libssh --enable-nyx --disable-tools
  compile
  exit 0
fi

if [ "$1" == "debug" ]; 
then 

  make clean
  compile_and_install_libraries
  ./configure --target-list=x86_64-softmmu --disable-gtk --disable-docs --enable-gtk --disable-werror --disable-capstone --disable-libssh --enable-nyx --enable-sanitizers --enable-debug --disable-tools
  compile
  exit 0
fi

if [ "$1" == "debug_static" ]; 
then 

  make clean
  compile_libraries
  ./configure --target-list=x86_64-softmmu --disable-gtk --disable-docs --enable-gtk --disable-werror --disable-capstone --disable-libssh --enable-nyx --enable-sanitizers --enable-debug --enable-nyx-static --disable-tools
  compile
  exit 0
fi

if [ "$1" == "static" ]; 
then 

  make clean
  compile_libraries
  ./configure --target-list=x86_64-softmmu --disable-gtk --disable-docs --enable-gtk --disable-werror --disable-capstone --disable-libssh --enable-nyx --enable-nyx-static --disable-tools
  compile
  exit 0
fi

if [ "$1" == "lto" ]; 
then 

  make clean
  compile_libraries
  ./configure --target-list=x86_64-softmmu --disable-gtk --disable-docs --enable-gtk --disable-werror --disable-capstone --disable-libssh --enable-nyx --enable-nyx-static --enable-nyx-flto --disable-tools
  compile
  exit 0
fi

error
exit 1
