#!/usr/bin/env bash
version=$(./ci-scripts/version/version_from_tag.sh)
if [ $? -ne 0 ]
then
    version=$(git rev-parse --short HEAD  2> /dev/null)
    if [ $? -ne 0 ]
    then
        version=$(cat ./tiny-firmware/VERSION 2> /dev/null)
        if [ $? -ne 0 ]
        then
            version='unknow'
        fi
    fi
fi
echo $version
