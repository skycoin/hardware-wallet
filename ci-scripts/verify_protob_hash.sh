#!/usr/bin/env bash

# Get commit hash from submodule
PROTOB_HASH=$(git -C tiny-firmware/protob/ rev-parse HEAD)

# clone protob repository
mkdir -p tmp/hardware-wallet-protob
git clone --depth=50 --single-branch --branch master https://github.com/skycoin/hardware-wallet-protob.git tmp/hardware-wallet-protob

# fetch recent 50 commits
# hardware wallet should not get too behind protob repository
PROTOB_REMOTE_HASH=$(git log --pretty=oneline | head -50 | cut -c 1-40)
rm -rf tmp/hardware-wallet-protob

if ! echo "$PROTOB_REMOTE_HASH" | grep -q "$PROTOB_HASH"; then
   exit 1
fi

exit 0
