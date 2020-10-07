#!/usr/bin/env bash

ORG="skycoinproject"

git submodule update --init --recursive
make clean
docker build -t $ORG/skywallet . && \
docker push $ORG/skywallet
