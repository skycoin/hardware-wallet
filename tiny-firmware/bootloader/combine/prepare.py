#!/usr/bin/env python

bl = open('bl.bin', "rb").read()
fw = open('fw.bin', "rb").read()
combined = bl + fw[:256] + (32768-256)*b'\x00' + fw[256:]

open('combined.bin', 'wb').write(combined)

print('bootloader : %d bytes' % len(bl))
print('firmware   : %d bytes' % len(fw))
print('combined   : %d bytes' % len(combined))

