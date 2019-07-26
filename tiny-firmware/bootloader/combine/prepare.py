#!/usr/bin/env python
from __future__ import print_function

if platform.system().split("_")[0] == 'MSYS':
    with open("bl.bin", 'rb') as f1:
        bl = f1.read().decode('utf8', 'ignore')
    with open("fw.bin", 'rb') as f2:
        fw = f2.read().decode('utf8', 'ignore')

bl = open('bl.bin').read()
fw = open('fw.bin').read()
combined = bl + fw[:256] + (32768-256)*'\x00' + fw[256:]

open('combined.bin', 'w').write(combined)

print('bootloader : %d bytes' % len(bl))
print('firmware   : %d bytes' % len(fw))
print('combined   : %d bytes' % len(combined))
