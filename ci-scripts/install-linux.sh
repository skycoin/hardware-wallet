#!/usr/bin/env bash

set -x

sudo apt-get update

# Install libcheck check C testing framework
wget https://github.com/libcheck/check/releases/download/0.12.0/check-0.12.0.tar.gz
tar xvf check-0.12.0.tar.gz
cd check-0.12.0
autoreconf --install
./configure
make
cp src/.libs/*.so* src
cd -

# Install build tools
sudo apt-get install -y build-essential curl unzip git python3 python3-pip python-protobuf gcc-arm-none-eabi

# Install SDL
sudo apt-get install -y libegl1-mesa-dev libgles2-mesa-dev libsdl2-dev libsdl2-image-dev

#Install cccc
sudo apt-get install cccc -y

##INstall cgov
sudo apt-get install lcov -y