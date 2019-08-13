#!/usr/bin/env python
from __future__ import print_function
import platform

print(platform.system())

if platform.system().split('_')[0] == "MSYS":
    with open('bl.bin', 'rb') as f1:
        bl = f1.read()

    with open('fw.bin', 'rb') as f2:
        fw = f2.read()

    combined = bl + fw[:256] + (32768-256)*'\x00'.encode('utf-8') + fw[256:]

    open('combined.bin', 'wb').write(combined)
else:
    bl = open('bl.bin').read()
    fw = open('fw.bin').read()

    combined = bl + fw[:256] + (32768-256)*'\x00' + fw[256:]

    open('combined.bin', 'w').write(combined)

print('bootloader : %d bytes' % len(bl))
print('firmware   : %d bytes' % len(fw))
print('combined   : %d bytes' % len(combined))
