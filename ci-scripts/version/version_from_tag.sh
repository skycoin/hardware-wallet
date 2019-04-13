#!/usr/bin/env bash
version=$(git describe HEAD --exact-match 2> /dev/null)
if [ $? -ne 0 ]
then
    exit 1
fi
echo $version
