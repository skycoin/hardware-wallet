#!/usr/bin/python
from __future__ import print_function
import argparse
import hashlib
import struct
import binascii
import skycoin_crypto
import random
import sys

try:
    raw_input
except:
    raw_input = input

SLOTS = 3

INDEXES_START = len('SKY1') + struct.calcsize('<I')
SIG_START = INDEXES_START + SLOTS + 1 + 52

def parse_args():
    parser = argparse.ArgumentParser(description='Commandline tool for signing Skycoin firmware.')
    parser.add_argument('-f', '--file', dest='path', help="Firmware file to modify", required=True)
    parser.add_argument('-s', '--sign', dest='sign', action='store_true', help="Add signature to firmware slot")
    parser.add_argument('-sk', '--secret-key', dest='sec_key', help="Secret key in hexadecimal")
    parser.add_argument('-pk', '--pub-keys', dest='pub_keys', nargs='+', help="Public key in exadecimal", required=True)

    return parser.parse_args()

def prepare(data):
    # Takes raw OR signed firmware and clean out metadata structure
    # This produces 'clean' data for signing

    meta = b'SKY1'  # magic
    if data[:4] == b'SKY1':
        meta += data[4:4 + struct.calcsize('<I')]
    else:
        meta += struct.pack('<I', len(data))  # length of the code
    meta += b'\x00' * SLOTS  # signature index #1-#3
    meta += b'\x01'       # flags
    meta += b'\x00' * 52  # reserved
    meta += b'\x00' * 65 * SLOTS  # signature #1-#3

    if data[:4] == b'SKY1':
        # Replace existing header
        out = meta + data[len(meta):]
    else:
        # create data from meta + code
        out = meta + data

    return out

def check_signatures(data, pubkeys):
    # Analyses given firmware and prints out
    # status of included signatures. Return True on success False on failed.
    try:
        indexes = [ ord(x) for x in data[INDEXES_START:INDEXES_START + SLOTS] ]
    except:
        indexes = [ x for x in data[INDEXES_START:INDEXES_START + SLOTS] ]

    to_sign = prepare(data)[256:] # without meta
    fingerprint = hashlib.sha256(to_sign).hexdigest()
    print("Firmware fingerprint:", fingerprint)

    used = []
    for x in range(SLOTS):
        signature = data[SIG_START + 65 * x:SIG_START + 65 * x + 65]

        if indexes[x] == 0:
            print("Slot #%d" % (x + 1), 'is empty')
        else:
            pk = pubkeys[indexes[x]]

            skycoin = skycoin_crypto.SkycoinCrypto()
            ret, pubkey = skycoin.SkycoinEcdsaVerifyDigestRecover(signature, binascii.unhexlify(fingerprint))
            if ret != 0:
                return False
            pubkey = binascii.hexlify(pubkey)

            if (pubkey == pk):
                if indexes[x] in used:
                    print("Slot #%d signature: DUPLICATE" % (x + 1), binascii.hexlify(signature))
                else:
                    used.append(indexes[x])
                    print("Slot #%d signature: VALID" % (x + 1), binascii.hexlify(signature))
            else:
                print("Slot #%d signature: INVALID" % (x + 1), binascii.hexlify(signature))
                return False
    return True


def modify(data, slot, index, signature):
    # Replace signature in data

    # Put index to data
    data = data[:INDEXES_START + slot - 1 ] + chr(index) + data[INDEXES_START + slot:]

    # Put signature to data
    data = data[:SIG_START + 65 * (slot - 1) ] + signature + data[SIG_START + 65 * slot:]

    return data

def sign(data, pubkeys, secexp, slot):
    if slot < 1 or slot > SLOTS:
        raise Exception("Invalid slot")
    if secexp.strip() == '':
        # Blank key, let's remove existing signature from slot
        return modify(data, slot, 0, '\x00' * 65)
    seckey = binascii.unhexlify(secexp)
    skycoin = skycoin_crypto.SkycoinCrypto()
    pubkey = skycoin.SkycoinPubkeyFromSeckey(seckey)
    pubkey = binascii.hexlify(pubkey.value)

    to_sign = prepare(data)[256:] # without meta
    fingerprint = hashlib.sha256(to_sign).hexdigest()
    print("Firmware fingerprint:", fingerprint)

    # Locate proper index of current signing key
    # pubkey = b'04' + binascii.hexlify(key.get_verifying_key().to_string())
    index = None
    for i, pk in pubkeys.items():
        if pk == pubkey:
            index = i
            break

    if index == None:
        raise Exception("Unable to find private key index. Unknown private key?")

    ret, signature = skycoin.SkycoinEcdsaSignDigest(seckey, binascii.unhexlify(fingerprint))
    if ret != 0:
        raise Exeption("Error signing message digest")

    if len(signature) != 65:
        raise Exception("Signature length {} is not 65 bytes".format(len(signature)))

    print("Skycoin signature:", binascii.hexlify(signature))

    return modify(data, slot, index, str(signature))

def main(args):
    pubkeys = {}
    for idx, pub_key in enumerate(args.pub_keys):
        pubkeys[idx + 1] = pub_key
    fp = open(args.path, 'rb')
    data = fp.read()
    fp.close()
    assert len(data) % 4 == 0

    if data[:4] != b'SKY1':
        print("Metadata has been added...")
        data = prepare(data)

    if data[:4] != b'SKY1':
        raise Exception("Firmware header expected")

    print("Firmware size %d bytes" % len(data))
    if args.sign:
        # Ask for index and private key and signs the firmware
        slot = int(raw_input('Enter signature slot (1-%d): ' % SLOTS))
        if not args.sec_key:
            print("Paste SECEXP (in hex) and press Enter:")
            print("(blank private key removes the signature on given index)")
            secexp = raw_input()
        else:
            secexp = args.sec_key
        data = sign(data, pubkeys, secexp, slot)
        if not check_signatures(data, pubkeys):
            raise Exception("Invalid signature, hard fail")
    else:
        if not check_signatures(data, pubkeys):
            raise Exception("Invalid signature")
    fp = open(args.path, 'wb')
    fp.write(data)
    fp.close()

if __name__ == '__main__':
    args = parse_args()
    main(args)
