#!/usr/bin/env bash

# Get commit hash from submodule
PROTOB_HASH=$(git -C tiny-firmware/protob/ rev-parse HEAD)

# fetch recent 50 commits
# hardware wallet should not get too behind protob repository
commits="$(curl https://api.github.com/repos/skycoin/hardware-wallet-protob/commits\?per_page\=50\&sha\=master)"

if echo "$commits" | egrep "\"sha\": \"$PROTOB_HASH\"" > /dev/null
then
    echo "success"
else
    echo "commit hash not present in recent 50 master commits"
    exit 1
fi
