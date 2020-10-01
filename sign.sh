#!/usr/bin/env bash
set -eo pipefail

REGISTRY="registry.skycoin.com"

docker pull $REGISTRY/skywallet && \
docker run --rm -v $(pwd):/hardware-wallet/ -w /hardware-wallet/ -it $REGISTRY/skywallet
