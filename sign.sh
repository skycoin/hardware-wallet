#!/usr/bin/env bash

WORK_DIR=$(pwd)

sudo docker build -t hw_docker/dev .
docker run -v $WORK_DIR:/hardware-wallet/ -it hw_docker/dev