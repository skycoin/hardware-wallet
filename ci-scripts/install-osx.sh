#!/usr/bin/env bash

set -x

brew tap skycoin/homebrew-skycoin

# Install libcheck check C testing framework
brew install check

# Install build tools
# TODO: Install tools in Debian's build-essentials ?
brew install md5sha1sum curl unzip  gcc-arm-none-eabi
brew install python3
brew unlink python@2

# Install SDL
brew install  sdl2_image sdl2 mesa mesalib-glw
