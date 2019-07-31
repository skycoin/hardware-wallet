from ctypes import cdll, c_char_p, c_uint32, c_size_t, byref, addressof, create_string_buffer
import binascii
import os

dir_path = os.path.dirname(os.path.abspath(__file__))

class SkycoinCryptoException(Exception):
    pass

class SkycoinCrypto(object):
    def __init__(self):
        self.lib = cdll.LoadLibrary(dir_path + '/libskycoin-crypto.so')

    def SkycoinEcdsaSignDigest(self, seckey, digest):
        if len(seckey) != 32:
            raise ValueError('seckey must be 32 bytes')
        if len(digest) != 32:
            raise ValueError('digest must be 32 bytes')

        signature = create_string_buffer(65)
        ret = self.lib.skycoin_ecdsa_sign_digest(seckey, digest, signature)
        if ret:
            raise SkycoinCryptoException('skycoin_ecdsa_sign_digest failed with error code {}'.format(ret))
        if len(signature.raw) != 65:
            raise SkycoinCryptoException("signature length {} is not 65 bytes".format(len(signature.raw)))
        return signature.raw

    def KeyPair(self):
        seed = os.urandom(32)
        sec_key = create_string_buffer(32)
        pub_key = create_string_buffer(33)
        self.lib.deterministic_key_pair_iterator(seed, 32, seed, sec_key, pub_key)
        return sec_key, pub_key

    def SkycoinPubkeyFromSeckey(self, seckey):
        if len(seckey) != 32:
            raise ValueError('seckey must be 32 bytes')

        pubkey = create_string_buffer(33)
        self.lib.skycoin_pubkey_from_seckey(seckey, pubkey)
        return pubkey.raw

    def SkycoinAddressFromPubkey(self, pubkey):
        if len(pubkey) != 33:
            raise ValueError('pubkey must be 33 bytes')

        address = create_string_buffer(36)
        address_size = c_size_t(36)
        ok = self.lib.skycoin_address_from_pubkey(pubkey, address, byref(address_size))
        if not ok:
            raise SkycoinCryptoException('skycoin_address_from_pubkey failed')
        return address.value # .value treats it as a NUL terminated string

    def SkycoinEcdsaVerifyDigestRecover(self, signature, digest):
        if len(signature) != 65:
            raise ValueError('signature must be 65 bytes')
        if len(digest) != 32:
            raise ValueError('digest must be 32 bytes')

        pubkey = create_string_buffer(33)
        ret = self.lib.skycoin_ecdsa_verify_digest_recover(signature, digest, pubkey)
        if ret:
            raise SkycoinCryptoException('skycoin_ecdsa_verify_digest_recover failed with error code {}'.format(ret))

        pk = bytearray(pubkey.raw)
        if len(pk) != 33:
            raise SkycoinCryptoException('recovered pubkey length {} is not 33 bytes'.format(len(pk)))
        return pk
