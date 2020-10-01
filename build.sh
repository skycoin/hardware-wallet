#!/usr/bin/env bash

REGISTRY="registry.skycoin.com"

docker pull $REGISTRY/skywallet && \
docker run --rm -it -v $(pwd):/hardware-wallet:Z -w /hardware-wallet $REGISTRY/skywallet make full-firmware
