#!/usr/bin/env bash
FULL_VERSION=$(./ci-scripts/version/version_from_tag.sh)
if [ $? -ne 0 ]
then
    exit 1
fi
VERSION_FIRMWARE_MINOR=$(echo $FULL_VERSION | cut -d. -f2)
echo $VERSION_FIRMWARE_MINOR
