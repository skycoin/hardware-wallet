#!/usr/bin/env bash
set -eo pipefail

WORK_DIR=$(pwd)

sudo docker build -t hw_docker/dev .
docker run -v $WORK_DIR:/hardware-wallet/ -it hw_docker/dev