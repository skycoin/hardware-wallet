#!/usr/bin/env bash

# Get commit hash from submodule
PROTOB_HASH=$(git -C tiny-firmware/protob/ rev-parse HEAD)

# make sure submodule has correct origin url
SUBMODULE_ORIGIN_URL=$(git -C tiny-firmware/protob remote get-url origin)
if ! echo "$SUBMODULE_ORIGIN_URL" | grep -q "http://github.com/skycoin/hardware-wallet-protob.git"; then
    echo "invalid repository $SUBMODULE_ORIGIN_URL"
    exit 1
fi

# fetch recent 50 commits
# hardware wallet should not get too behind protob repository
git -C tiny-firmware/protob/ fetch origin
PROTOB_REMOTE_HASH=$(git -C tiny-firmware/protob log remotes/origin/develop --pretty=oneline | head -50 | cut -c 1-40)

if ! echo "$PROTOB_REMOTE_HASH" | grep -q "$PROTOB_HASH"; then
    echo "commit hash $PROTOB_HASH not present in recent 50 master commits"
    exit 1
fi

echo "success"
