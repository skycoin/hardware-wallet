#!/usr/bin/env python
import argparse
from compute_hash import calculate_binary_hash

parser = argparse.ArgumentParser(description="Commandline tool for combining bootloader and firmware")
parser.add_argument("-b", "--bootloader", dest='bl_path', help="Path to bootloader", required=True)
parser.add_argument("-f", "--firmware", dest='fw_path', help="Path to firmware", required=True)
parser.add_argument("-d", "--dest", dest='dest', help="Path to save combined", required=True)

args = parser.parse_args()

bl = open(args.bl_path, 'rb').read()
fw = open(args.fw_path, 'rb').read()
combined = bl + fw[:256] + (32768 - 256) * '\x00'.encode('utf-8') + fw[256:]
open(args.dest, 'wb').write(combined)

print()
print("Bootloader's location   : %s" % args.bl_path)
print("Firmware's location     : %s" % args.fw_path)
print("Full-firmware's location: %s" % args.dest)
print()
print('bootloader : %d bytes' % len(bl))
print('firmware   : %d bytes' % len(fw))
print('combined   : %d bytes' % len(combined))
print()
print("bootloader's SHA256: %s " % calculate_binary_hash(args.bl_path))
print("firmware's SHA256  : %s " % calculate_binary_hash(args.fw_path))
