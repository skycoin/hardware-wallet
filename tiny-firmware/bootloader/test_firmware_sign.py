#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import unittest
import firmware_sign
import skycoin_crypto

import os

dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, '../skyfirmware.bin')


class TestSignFirmware(unittest.TestCase):
    def setUp(self):
        self.skycoin = skycoin_crypto.SkycoinCrypto()
        self.sec_key, self.pub_key = self.skycoin.KeyPair()
        self.pubkeys = {
            1: binascii.hexlify(self.pub_key).decode('utf-8')
        }
        slot = 1
        data = firmware_sign.get_data(filename)
        self.data = firmware_sign.sign(data, self.pubkeys, binascii.hexlify(self.sec_key).decode('utf-8'), slot)

    def test_sign_firmware_ok(self):
        self.assertTrue(firmware_sign.check_signatures(self.data, self.pubkeys), 'Signature should be checked')

    def test_sign_firmware_fail_as_expected_for_invalid_pub_key(self):
        mutable_str = list(self.pubkeys[1])
        # NOTE hack pub key
        mutable_str[1], mutable_str[10] = mutable_str[10], mutable_str[1]
        pubkeys = self.pubkeys
        pubkeys[1] = ''.join(mutable_str)
        self.assertRaises(Exception, firmware_sign.check_signatures(self.data, pubkeys), 'Undetected hacked pub key')

    def test_sign_firmware_fail_as_expected_for_hacked_data(self):
        signed = self.data
        mutable_data = bytearray(signed)
        # NOTE hack data
        mutable_data[1], mutable_data[10] = mutable_data[10], mutable_data[1]
        data = bytes(mutable_data)
        self.assertFalse(firmware_sign.check_signatures(data, self.pubkeys))
        mutable_data = bytearray(signed)
        # NOTE hack data
        mutable_data[300], mutable_data[301] = mutable_data[301], mutable_data[300]
        data = bytes(mutable_data)
        self.assertFalse(firmware_sign.check_signatures(data, self.pubkeys))


if __name__ == '__main__':
    unittest.main()
