#!/usr/bin/env bash

REGISTRY="registry.skycoin.com"

git submodule update --init --recursive
make clean
docker build -t $REGISTRY/skywallet . && \
docker push $REGISTRY/skywallet
