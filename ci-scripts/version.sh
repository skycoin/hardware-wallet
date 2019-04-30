#!/usr/bin/env bash
version=$(git describe --tags --exact-match HEAD 2> /dev/null)
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
