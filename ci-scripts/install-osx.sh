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

echo 'Available versions (gcc)'
brew list --versions gcc
echo 'Creating gcc@64 formula'
cd "$(brew --repository)/Library/Taps/homebrew/homebrew-core"
git show 42d31bba7772fb01f9ba442d9ee98b33a6e7a055:Formula/gcc\@6.rb | grep -v 'fails_with' > Formula/gcc\@6.rb
echo 'Installing gcc@6 (6.4.0-2)'
brew install gcc\@6 || brew link --overwrite gcc\@6