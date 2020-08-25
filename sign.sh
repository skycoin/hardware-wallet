#!/usr/bin/env bash
set -eo pipefail

sudo docker build -t skywallet . && \
docker run --rm -v $(pwd):/hardware-wallet/ -w /hardware-wallet/ -it skywallet
