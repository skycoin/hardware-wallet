#!/usr/bin/env bash

ORG="skycoinproject"

docker pull $ORG/skywallet && \
docker run --rm -it -v $(pwd):/hardware-wallet:Z -w /hardware-wallet $ORG/skywallet make full-firmware
