#!/usr/bin/env python
# -*- coding: utf-8 -*-

import binascii
import unittest
import firmware_sign
import skycoin_crypto

class TestSignFirmware(unittest.TestCase):
    def test_sign_firmware_ok(self):
        skycoin = skycoin_crypto.SkycoinCrypto()
        sec_key, pub_key = skycoin.KeyPair()
        pubkeys = {
            1: binascii.hexlify(pub_key).decode('utf-8')
        }
        slot = 1
        data = firmware_sign.get_data('/tmp/skyfirmware.bin')
        data = firmware_sign.sign(data, pubkeys, binascii.hexlify(sec_key), slot)
        self.assertTrue(firmware_sign.check_signatures(data, pubkeys), 'Signature should be checked')

    def test_sign_firmware_fail_as_expected_for_invalid_pub_key(self):
        skycoin = skycoin_crypto.SkycoinCrypto()
        sec_key, pub_key = skycoin.KeyPair()
        pubkeys = {
            1: binascii.hexlify(pub_key).decode('utf-8')
        }
        slot = 1
        data = firmware_sign.get_data('/tmp/skyfirmware.bin')
        data = firmware_sign.sign(data, pubkeys, binascii.hexlify(sec_key), slot)
        mutable_str = list(pubkeys[1])
        # NOTE hack pub key
        mutable_str[1], mutable_str[10] = mutable_str[10], mutable_str[1]
        pubkeys[1] = ''.join(mutable_str)
        self.assertRaises(Exception, firmware_sign.check_signatures(data, pubkeys), 'Undetected hacked pub key')

    def test_sign_firmware_fail_as_expected_for_hacked_data(self):
        skycoin = skycoin_crypto.SkycoinCrypto()
        sec_key, pub_key = skycoin.KeyPair()
        pubkeys = {
            1: binascii.hexlify(pub_key).decode('utf-8')
        }
        slot = 1
        data = firmware_sign.get_data('/tmp/skyfirmware.bin')
        data = firmware_sign.sign(data, pubkeys, binascii.hexlify(sec_key), slot)
        signed = data
        mutable_data = bytearray(signed)
        # NOTE hack data
        mutable_data[1], mutable_data[10] = mutable_data[10], mutable_data[1]
        data = bytes(mutable_data)
        self.assertFalse(firmware_sign.check_signatures(data, pubkeys))
        mutable_data = bytearray(signed)
        # NOTE hack data
        mutable_data[300], mutable_data[301] = mutable_data[301], mutable_data[300]
        data = bytes(mutable_data)
        self.assertFalse(firmware_sign.check_signatures(data, pubkeys))

def test_main():
    pubkeys = {
        1: '03d13e79407ea2a4fb6d85ae5c79477c120e809b2d49e9b2f66555e1f64647f27f'
    }
    secexp = '6bc231f5f85406d0dc6ffd461fcfc9714816ceff1ffa8aa09abf8e0e35f13930'
    slot = 1
    data = firmware_sign.get_data('/tmp/skyfirmware.bin')
    data = firmware_sign.sign(data, pubkeys, secexp, slot)
    pubkeys = {
        1: '33d13e79407ea2a4fb6d85ae5c79477c120e809b2d49e9b2f66555e1f64647f27f',
        2: '028a3db28a39235ca1e15a605f4c1ff3136480a653e7efcd12ce848e1b1beee3ad',
        3: '02fca7fb7bc3a1bd44f27b0942989be564019f51c6fbd16058e9465b0f705a0c81',
        4: '0385dc702567a1038c7a173a5feee45768202a108f96ea13881317f594300ecf50'
    }
    if not firmware_sign.check_signatures(data, pubkeys):
        raise Exception("Invalid signature, hard fail")

if __name__ == '__main__':
    unittest.main()
