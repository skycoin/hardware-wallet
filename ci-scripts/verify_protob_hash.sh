#!/usr/bin/env bash

# Get commit hash from submodule
cd tiny-firmware/protob/
PROTOB_HASH=$(git log --pretty=oneline | head -1 | cut -c 1-40)

# clone protob repository from git
mkdir -p tmp/hardware-wallet-protob
git clone --depth=50 --single-branch --branch master https://github.com/skycoin/hardware-wallet-protob.git tmp/hardware-wallet-protob

# fetch recent 50 commits
# hardware wallet should not get too behind protob repository
PROTOB_REMOTE_HASH=$(git log --pretty=oneline | head -50 | cut -c 1-40)
if ! echo "$PROTOB_REMOTE_HASH" | grep -q "$PROTOB_HASH"; then
   exit 1
fi
rm -rf tmp/hardware-wallet-protob
