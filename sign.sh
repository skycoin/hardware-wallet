#!/usr/bin/env bash
set -eo pipefail

ORG="skycoinproject"

docker pull $ORG/skywallet && \
docker run --rm -v $(pwd):/hardware-wallet/ -w /hardware-wallet/ -it $ORG/skywallet
