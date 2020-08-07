#!/bin/bash

cd /root && mkdir bin
cd /home/user/ && mkdir Skycoin & cd ./Skycoin
git clone https://github.com/SkycoinProject/hardware-wallet.git
cd ./hardware-wallet
git submodule update --init --recursive
