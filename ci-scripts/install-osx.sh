#!/usr/bin/env bash

set -x

brew tap skycoin/homebrew-skycoin

# Install libcheck check C testing framework
brew install check

# Install build tools
# TODO: Install tools in Debian's build-essentials ?
brew install md5sha1sum curl unzip python gcc-arm-none-eabi

# Install SDL
brew install  sdl2_image sdl2 mesa mesalib-glw

# Install objconv
if [ ! -d "objconv" ]; then
  wget -c http://www.agner.org/optimize/objconv.zip
  mkdir -p build-objconv
  unzip objconv.zip -d build-objconv

  cd build-objconv
  unzip source.zip -d src
  clang++ -o objconv -O2 src/*.cpp --prefix="$PREFIX"
fi
# brew tap hawkw/homebrew-grub
# brew install objconv

