#!/bin/bash
version=$(git describe HEAD --exact-match 2> /dev/null)
if [ $? -ne 0 ]
then
    version=$(git rev-parse --short HEAD  2> /dev/null)
    if [ $? -ne 0 ]
    then
        version=$(cat .version 2> /dev/null)
        if [ $? -ne 0 ]
        then
            version='unknow'
        fi
    fi
fi
echo $version
