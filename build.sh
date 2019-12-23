#!/usr/bin/env bash
git submodule update --init --recursive
make clean
docker build -t skywallet . && \
docker run --rm -it -v $(pwd):/hardware-wallet:Z -w /hardware-wallet skywallet make full-firmware
