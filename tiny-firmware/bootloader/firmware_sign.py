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

pubkeys = {
    1: '024291e2425a2fc7ec7bd75c8128726ca8cfb7ce9c04ae8186b66c3516f0f80cd2',
    2: '03e592cb31c3c2cc9b3810e5c78298280b0cc785cd7f28e36e135aa8a0fc74d081',
    3: '03b155df34b4c0879fdd6bde2acb9c7a45e93aa0bd0c697f6292dc3d1cb4c596d6',
    4: '026d1d2e1c4af5a2c89e8e4c8bf724034d0252eb8b9179fc6eec9ceb8bb1734997',
    5: '033bdf377502789d27a1d534775392af97a93333181b9736395b3db687ceffc473',
}

INDEXES_START = len('SKY1') + struct.calcsize('<I')
SIG_START = INDEXES_START + SLOTS + 1 + 52

def parse_args():
    parser = argparse.ArgumentParser(description='Commandline tool for signing Skycoin firmware.')
    parser.add_argument('-f', '--file', dest='path', help="Firmware file to modify")
    parser.add_argument('-s', '--sign', dest='sign', action='store_true', help="Add signature to firmware slot")
    parser.add_argument('-sk', '--secret-key', dest='secret_key', help="Secret key in hexadecimal")
    parser.add_argument('-pk', '--public-key', dest='public_key', help="Public key in exadecimal")

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

def check_signatures(data, pk=None):
    # Analyses given firmware and prints out
    # status of included signatures. Return True on success False on failed.

    to_sign = prepare(data)[256:] # without meta
    fingerprint = hashlib.sha256(to_sign).hexdigest()
    print("Firmware fingerprint:", fingerprint)
    if not pk is None:
        skycoin = skycoin_crypto.SkycoinCrypto()
        pubkey = skycoin.RecoverPubkeyFromSignature(binascii.unhexlify(fingerprint), signature)
        pubkey = binascii.hexlify(pubkey)
        return pubkey == pk

    try:
        indexes = [ ord(x) for x in data[INDEXES_START:INDEXES_START + SLOTS] ]
    except:
        indexes = [ x for x in data[INDEXES_START:INDEXES_START + SLOTS] ]
    used = []
    for x in range(SLOTS):
        signature = data[SIG_START + 65 * x:SIG_START + 65 * x + 65]

        if indexes[x] == 0:
            print("Slot #%d" % (x + 1), 'is empty')
        else:
            pk = pubkeys[indexes[x]]

            skycoin = skycoin_crypto.SkycoinCrypto()
            pubkey = skycoin.SkycoinEcdsaVerifyDigestRecover(signature, binascii.unhexlify(fingerprint))
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

def sign(data, secexp=None):
    # Ask for index and private key and signs the firmware

    slot = int(raw_input('Enter signature slot (1-%d): ' % SLOTS))
    if slot < 1 or slot > SLOTS:
        raise Exception("Invalid slot")

    if not secexp:
        print("Paste SECEXP (in hex) and press Enter:")
        print("(blank private key removes the signature on given index)")
        secexp = raw_input()
        if secexp.strip() == '':
        # Blank key, let's remove existing signature from slot
        return modify(data, slot, 0, '\x00' * 65)
    skycoin = skycoin_crypto.SkycoinCrypto()
    seckey = binascii.unhexlify(secexp)
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

    signature = skycoin.SkycoinEcdsaSignDigest(seckey, binascii.unhexlify(fingerprint))

    if len(signature.value) != 65:
        raise Exception("Signature length {} is not 65 bytes".format(len(signature.value)))

    print("Skycoin signature:", binascii.hexlify(signature.value))

    return modify(data, slot, index, str(signature.value))

def main(args):

    if not args.path:
        raise Exception("-f/--file is required")

    data = open(args.path, 'rb').read()
    assert len(data) % 4 == 0

    if data[:4] != b'SKY1':
        print("Metadata has been added...")
        data = prepare(data)

    if data[:4] != b'SKY1':
        raise Exception("Firmware header expected")

    print("Firmware size %d bytes" % len(data))

    match = check_signatures(data, None if not args.public_key else args.public_key)
    if not match:
        fp.close()
        sys.exit(-1)

    if args.sign:
        data = sign(data, None if not args.secret_key else args.secret_key)
        match  = check_signatures(data, None if not args.public_key else args.public_key)
        if not match:
            fp.close()
            sys.exit(-1)

    fp = open(args.path, 'wb')
    fp.write(data)
    fp.close()

if __name__ == '__main__':
    args = parse_args()
    main(args)
