from ctypes import cdll, c_char_p, c_uint32, c_size_t, byref, addressof, create_string_buffer
import binascii
import os

dir_path = os.path.dirname(os.path.realpath(__file__))

class SkycoinCrypto(object):
    def __init__(self):
        self.lib = cdll.LoadLibrary(dir_path + '/libskycoin-crypto.so')

    def SkycoinEcdsaSignDigest(self, seckey, digest):
         signature = create_string_buffer(65)
         ret = self.lib.skycoin_ecdsa_sign_digest(seckey, digest, signature)
         return ret, signature

    def ComputeSha256Sum(self, seed):
        digest = create_string_buffer(32)
        self.lib.sha256sum(seed, digest, self.lib.strlen(seed))
        return digest

    def KeyPair(self):
        seed = os.urandom(32)
        sec_key = create_string_buffer(32)
        pub_key = create_string_buffer(33)
        self.lib.deterministic_key_pair_iterator(seed, 32, seed, sec_key, pub_key)
        return sec_key, pub_key

    def SkycoinPubkeyFromSeckey(self, seckey):
        pubkey = create_string_buffer(33)
        self.lib.skycoin_pubkey_from_seckey(seckey, pubkey)
        return pubkey

    def SkycoinAddressFromPubkey(self, pubkey):
        address = create_string_buffer(36)
        address_size = c_size_t(36)
        self.lib.skycoin_address_from_pubkey(pubkey, address, byref(address_size))
        return address

    def SkycoinEcdsaVerifyDigestRecover(self, signature, digest):
        pubkey = create_string_buffer(33)
        ret = self.lib.skycoin_ecdsa_verify_digest_recover(signature, digest, pubkey)
        return ret, pubkey
