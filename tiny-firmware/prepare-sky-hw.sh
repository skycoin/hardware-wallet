#!/bin/bash

set -e -o pipefail

cat <<EOF >/etc/udev/rules.d/99-dev-kit.rules
## 0483:df11 STMicroelectronics STM Device in DFU Mode
SUBSYSTEM=="usb", ATTR{idVendor}=="0483", ATTR{idProduct}=="df11", MODE="0666"
## 0483:3748 STMicroelectronics ST-LINK/V2
SUBSYSTEM=="usb", ATTR{idVendor}=="0483", ATTR{idProduct}=="3748", MODE="0666"
## 0483:374b STMicroelectronics ST-LINK/V2.1 (Nucleo-F103RB)
SUBSYSTEM=="usb", ATTR{idVendor}=="0483", ATTR{idProduct}=="374b", MODE="0666"
## 313a:0001
SUBSYSTEM=="usb", ATTR{idVendor}=="313a", ATTR{idProduct}=="0001", MODE="0666"
KERNEL=="hidraw*", ATTRS{idVendor}=="313a", ATTRS{idProduct}=="0001", MODE="0666"
EOF

udevadm control --reload-rules
udevadm trigger
