#!/usr/bin/env bash
version=$(git describe --tags --exact-match HEAD 2> /dev/null)
if [ $? -ne 0 ]
then
    exit 1
fi
echo $version
