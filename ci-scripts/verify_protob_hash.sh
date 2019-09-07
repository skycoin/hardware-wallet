#!/usr/bin/env bash

# Get commit hash from submodule
PROTOB_HASH=$(git -C tiny-firmware/protob/ rev-parse HEAD)

# make sure submodule has correct origin url
SUBMODULE_ORIGIN_URL=$(git -C tiny-firmware/protob remote get-url origin)
if ! echo "$SUBMODULE_ORIGIN_URL" | grep -q "http://github.com/skycoin/hardware-wallet-protob.git"; then
    echo "invalid repository $SUBMODULE_ORIGIN_URL"
    exit 1
fi

# TODO: if PR then determine base branch and do checks below
if "$TRAVIS_PULL_REQUEST" != "false" ; then
    echo "Merging changes into $TRAVIS_PULL_REQUEST_BRANCH"
    # fetch recent 50 commits
    # hardware wallet should not get too behind protob repository
    git -C tiny-firmware/protob/ fetch origin $TRAVIS_PULL_REQUEST_BRANCH
    PROTOB_REMOTE_HASH=$(git -C tiny-firmware/protob log remotes/origin/$TRAVIS_PULL_REQUEST_BRANCH --pretty=oneline | head -50 | cut -c 1-40)

    if ! echo "$PROTOB_REMOTE_HASH" | grep -q "$PROTOB_HASH"; then
        echo "commit hash $PROTOB_HASH not present in recent 50 '$TRAVIS_PULL_REQUEST_BRANCH' commits"
        exit 1
    fi
fi

echo "success"
