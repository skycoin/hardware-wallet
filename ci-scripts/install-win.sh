#!/usr/bin/env bash

set +e
pacman -Sy make gcc protobuf unzip python3-pip

# There are no available packages for MSYS2, listed below
# To make them work under MSYS2, we need to move all files to MSYS2 /usr/
pacman -Sy mingw-w64-x86_64-check
pacman -Sy mingw-w64-x86_64-SDL2
pacman -Sy mingw-w64-x86_64-protobuf-c
set -e && echo "If u got error"

echo "Successfully installed all tools"

cd /c/msys64/mingw64/bin
cp checkmk libcheck-0.dll SDL2.dll sdl2-config libprotobuf-c-1.dll protoc-c.exe protoc-gen-c.exe /usr/bin

cd /c/msys64/mingw64/include
cp check.h check_stdint.h /usr/include
cp -r SDL2 google protobuf-c /usr/include

cd /c/msys64/mingw64/lib
cp libcheck.a libcheck.dll.a libSDL2.a libSDL2.dll.a libSDL2_test.a libSDL2main.a libprotobuf-c.a libprotobuf-c.dll.a /usr/lib
cp pkgconfig/sdl2.pc pkgconfig/check.pc pkgconfig/libprotobuf-c.pc /usr/lib/pkgconfig

cd /c/msys64/mingw64/share
cp licenses/protobuf-c/LICENSE /usr/share/licenses
cp aclocal/check.m4 aclocal/sdl2.m4 /usr/share/aclocal
cp -r doc/check /usr/share/doc
cp ./info/check.info.gz /usr/share/info
cp ./man/man1/checkmk.1.gz /usr/share/man/man1/

echo "Successfully moved all needed tools"
echo "WARNING!!! Don't forget to install Arm-None-Eabi Toolchain and ST-Link Utility"
echo "See README.md for more details"
