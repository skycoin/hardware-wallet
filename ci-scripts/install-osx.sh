
brew tap skycoin/homebrew-skycoin

# Install libcheck check C testing framework
brew install check \
  # Install build tools
  # TODO: Install tools in Debian's build-essentials ?
  curl unzip git python gcc-arm-none-eabi \
  # Install SDL
  sdl2_image sdl2 mesa mesalib-glw

# Install protobuf
brew install protobuf --with-python
brew install protobuf-c

