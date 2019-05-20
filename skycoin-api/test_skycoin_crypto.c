/*
 * This file is part of the Skycoin project, https://skycoin.net/ 
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */
#include <stdio.h>
#include <string.h>

#include <check.h>

#include "check_digest.h"
#include "skycoin_check_signature.h"
#include "skycoin_crypto.h"
#include "tools/base58.h"
#include "tools/ecdsa.h"
#include "tools/secp256k1.h"
#include "tools/sha2.h" //SHA256_DIGEST_LENGTH

#define FROMHEX_MAXLEN 512

const uint8_t* fromhex(const char* str)
{
    static uint8_t buf[FROMHEX_MAXLEN];
    size_t len = strlen(str) / 2;
    if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
        if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
        if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
        buf[i] = c;
    }
    return buf;
}

START_TEST(test_base58_decode)
{
    uint8_t addrhex[25] = {0};
    uint8_t signhex[65] = {0};
    char address[36] = "2EVNa4CK9SKosT4j1GEn8SuuUUEAXaHAMbM";
    char signature[90] = "GA82nXSwVEPV5soMjCiQkJb4oLEAo6FMK8CAE2n2YBTm7xjhAknUxtZrhs3RPVMfQsEoLwkJCEgvGj8a2vzthBQ1M";

    size_t sz = sizeof(signhex);
    b58tobin(signhex, &sz, signature);
    ck_assert_int_eq(sz, 65);
    ck_assert_mem_eq(signhex, fromhex("abc30130e2d9561fa8eb9871b75b13100689937dfc41c98d611b985ca25258c960be25c0b45874e1255f053863f6e175300d7e788d8b93d6dcfa9377120e4d3500"), sz);

    sz = sizeof(addrhex);
    b58tobin(addrhex, &sz, address);
    ck_assert_int_eq(sz, 25);
    ck_assert_mem_eq(addrhex, fromhex("b1aa8dd3e68d1d9b130c67ea1339ac9250b7d845002437a5a0"), sz);
}
END_TEST

START_TEST(test_generate_public_key_from_seckey)
{
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};

    memcpy(seckey, fromhex("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04"), sizeof(seckey));
    generate_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("0244350faa76799fec03de2f324acd077fd1b686c3a89babc0ef47096ccc5a13fa"), SHA256_DIGEST_LENGTH);

    memcpy(seckey, fromhex("c89b70a1f7b960c08068de9f2d3b32287833b26372935aa5042f7cc1dc985335"), sizeof(seckey));
    generate_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("03b17c7b7c564385be66f9c1b9da6a0b5aea56f0cb70548e6528a2f4f7b27245d8"), SHA256_DIGEST_LENGTH);
}
END_TEST

START_TEST(test_generate_key_pair_from_seed)
{
    char seed[256] = "seed";
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    compute_sha256sum((const uint8_t*)seed, digest, strlen(seed));
    generate_deterministic_key_pair(digest, SHA256_DIGEST_LENGTH, seckey, pubkey);
    ck_assert_mem_eq(seckey, fromhex("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04"), SHA256_DIGEST_LENGTH);
    ck_assert_mem_eq(pubkey, fromhex("0244350faa76799fec03de2f324acd077fd1b686c3a89babc0ef47096ccc5a13fa"), SHA256_DIGEST_LENGTH);
}
END_TEST

START_TEST(test_secp256k1Hash)
{
    char seed[256] = "seed";
    uint8_t secp256k1Hash_digest[SHA256_DIGEST_LENGTH] = {0};
    secp256k1Hash((const uint8_t*)seed, strlen(seed), secp256k1Hash_digest);
    ck_assert_mem_eq(secp256k1Hash_digest, fromhex("c79454cf362b3f55e5effce09f664311650a44b9c189b3c8eed1ae9bd696cd9e"), SHA256_DIGEST_LENGTH);

    strcpy(seed, "random_seed");
    memset(secp256k1Hash_digest, 0, SHA256_DIGEST_LENGTH);
    secp256k1Hash((const uint8_t*)seed, strlen(seed), secp256k1Hash_digest);
    ck_assert_mem_eq(secp256k1Hash_digest, fromhex("5e81d46f56767496bc05ed177c5237cd4fe5013e617c726af43e1cba884f17d1"), SHA256_DIGEST_LENGTH);

    strcpy(seed, "random_seed");
    memset(secp256k1Hash_digest, 0, SHA256_DIGEST_LENGTH);
    secp256k1Hash((const uint8_t*)seed, strlen(seed), secp256k1Hash_digest);
    ck_assert_mem_eq(secp256k1Hash_digest, fromhex("5e81d46f56767496bc05ed177c5237cd4fe5013e617c726af43e1cba884f17d1"), SHA256_DIGEST_LENGTH);
}
END_TEST

START_TEST(test_generate_deterministic_key_pair_iterator)
{
    char seed[256] = "seed";
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    uint8_t nextSeed[SHA256_DIGEST_LENGTH] = {0};
    generate_deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), nextSeed, seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);
    ck_assert_mem_eq(seckey, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), 32);
    ck_assert_mem_eq(nextSeed, fromhex("c79454cf362b3f55e5effce09f664311650a44b9c189b3c8eed1ae9bd696cd9e"), 32);

    strcpy(seed, "random_seed");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    generate_deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), nextSeed, seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73"), 33);
    ck_assert_mem_eq(seckey, fromhex("ff671860c58aad3f765d8add25046412dabf641186472e1553435e6e3c4a6fb0"), 32);
    ck_assert_mem_eq(nextSeed, fromhex("5e81d46f56767496bc05ed177c5237cd4fe5013e617c726af43e1cba884f17d1"), 32);

    strcpy(seed, "hello seed");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    generate_deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), nextSeed, seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0"), 33);
    ck_assert_mem_eq(seckey, fromhex("84fdc649964bf299a787cb78cd975910e197dbddd7db776ece544f41c44b3056"), 32);
    ck_assert_mem_eq(nextSeed, fromhex("70d382540812d4abc969dcc2adc66e805db96f7e1dcbe1ae6bbf2878211cbcf6"), 32);

    strcpy(seed, "skycoin5");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    generate_deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), nextSeed, seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("03b17c7b7c564385be66f9c1b9da6a0b5aea56f0cb70548e6528a2f4f7b27245d8"), 33);
    ck_assert_mem_eq(seckey, fromhex("c89b70a1f7b960c08068de9f2d3b32287833b26372935aa5042f7cc1dc985335"), 32);
}
END_TEST

START_TEST(test_base58_address_from_pubkey)
{
    uint8_t pubkey[33] = {0};
    char address[256] = {0};
    size_t size_address = sizeof(address);
    memcpy(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);
    generate_base58_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_str_eq(address, "2EVNa4CK9SKosT4j1GEn8SuuUUEAXaHAMbM");

    memcpy(pubkey, fromhex("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73"), 33);
    generate_base58_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_str_eq(address, "2EKq1QXRmfe7jsWzNdYsmyoz8q3VkwkLsDJ");

    memcpy(pubkey, fromhex("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0"), 33);
    generate_base58_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_str_eq(address, "5UgkXRHrf5XRk41BFq1DVyeFZHTQXirhUu");
}
END_TEST


START_TEST(test_bitcoin_address_from_pubkey)
{
    uint8_t pubkey[33] = {0};
    char address[256] = {0};
    size_t size_address = sizeof(address);
    memcpy(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);
    generate_bitcoin_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_str_eq(address, "1CN7JTzTTpmh1dsHeUSosXmNL2GLTwt78g");

    memcpy(pubkey, fromhex("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73"), 33);
    generate_bitcoin_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_str_eq(address, "1DkKGd1YV9nhBKHWT9Aa2JzbEus98y6oU9");

    memcpy(pubkey, fromhex("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0"), 33);
    generate_bitcoin_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_str_eq(address, "1Ba2hpHH2o6H1NSrFpJTz5AbxdB2BdK5L2");
}
END_TEST


START_TEST(test_bitcoin_private_address_from_seckey)
{
    uint8_t seckey[32] = {0};
    char address[256] = {0};
    size_t size_address = sizeof(address);
    memcpy(seckey, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), 32);
    generate_bitcoin_private_address_from_seckey(seckey, address, &size_address);
    ck_assert_str_eq(address, "KwDuvkABDqb4WQiwc92DpXtBBiEywuKv46ZUvz5Gi5Xyn9gbcTJt");

    memcpy(seckey, fromhex("ff671860c58aad3f765d8add25046412dabf641186472e1553435e6e3c4a6fb0"), 32);
    generate_bitcoin_private_address_from_seckey(seckey, address, &size_address);
    ck_assert_str_eq(address, "L5nBR59QkW6kyXFvyqNbncWo2jPMoBXSH9fGUkh3n2RQn5Mj3vfY");

    memcpy(seckey, fromhex("84fdc649964bf299a787cb78cd975910e197dbddd7db776ece544f41c44b3056"), 32);
    generate_bitcoin_private_address_from_seckey(seckey, address, &size_address);
    ck_assert_str_eq(address, "L1gEDGuLTpMjybHnsJ24bUHhueocDrrKVdM3rj1rqXFHfyM2WtwD");
}
END_TEST

START_TEST(test_compute_sha256sum)
{
    char seed[256] = "seed";
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    compute_sha256sum((const uint8_t*)seed, digest, strlen(seed));

    ck_assert_mem_eq(digest, fromhex("19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b"), SHA256_DIGEST_LENGTH);

    strcpy(seed, "random_seed");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    compute_sha256sum((const uint8_t*)seed, digest, strlen(seed));

    ck_assert_mem_eq(digest, fromhex("7b491face15c5be43df3affe42e6e4aab48522a3b564043de464e8de50184a5d"), SHA256_DIGEST_LENGTH);


    strcpy(seed, "024f7fd15da6c7fc7d0410d184073ef702104f82452da9b3e3792db01a8b7907c3");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    compute_sha256sum((const uint8_t*)seed, digest, strlen(seed));

    ck_assert_mem_eq(digest, fromhex("a5daa8c9d03a9ec500088bdf0123a9d865725b03895b1291f25500737298e0a9"), SHA256_DIGEST_LENGTH);
}
END_TEST

START_TEST(test_compute_ecdh)
{
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    uint8_t remote_pubkey[33];
    uint8_t my_seckey[32];

    memcpy(my_seckey, fromhex("8f609a12bdfc8572590c66763bb05ce609cc0fdcd0c563067e91c06bfd5f1027"), sizeof(my_seckey));
    memcpy(remote_pubkey, fromhex("03008fa0a5668a567cb28ab45e4b6747f5592690c1d519c860f748f6762fa13103"), sizeof(remote_pubkey));
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ecdh_shared_secret(my_seckey, remote_pubkey, digest);
    ck_assert_mem_eq(digest, fromhex("907d3c524abb561a80644cdb0cf48e6c71ce33ed6a2d5eed40a771bcf86bd081"), SHA256_DIGEST_LENGTH);

    memcpy(my_seckey, fromhex("ec4c3702ae8dc5d3aaabc230d362f1ccc1ad2222353d006a057969bf2cc749c1"), sizeof(my_seckey));
    memcpy(remote_pubkey, fromhex("03b5d8432d20e55590b3e1e74a86f4689a5c1f5e25cc58840741fe1ac044d5e65c"), sizeof(remote_pubkey));
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ecdh_shared_secret(my_seckey, remote_pubkey, digest);
    ck_assert_mem_eq(digest, fromhex("c59b456353d0fbceadc06d7794c42ebf413ab952b29ecf6052d30c7c1a50acda"), SHA256_DIGEST_LENGTH);

    memcpy(my_seckey, fromhex("19adca686f1ca7befc30af65765597a4d033ac7479850e79cef3ce5cb5b95da4"), sizeof(my_seckey));
    memcpy(remote_pubkey, fromhex("0328bd053c69d9c3dd1e864098e503de9839e990c63c48d8a4d6011c423658c4a9"), sizeof(remote_pubkey));
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ecdh_shared_secret(my_seckey, remote_pubkey, digest);
    ck_assert_mem_eq(digest, fromhex("1fd2c655bcf19202ee004a3e0ae8f5c64ad1c0ce3b69f32ba18da188bb4d1eea"), SHA256_DIGEST_LENGTH);

    memcpy(my_seckey, fromhex("085d62c27a37889e02a183ee29962d5f4377831b4a70834ccea24a209e201404"), sizeof(my_seckey));
    memcpy(remote_pubkey, fromhex("030684d74471053ac6395ef74a86f88daa25f501329734c837c8c79c600423b220"), sizeof(remote_pubkey));
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ecdh_shared_secret(my_seckey, remote_pubkey, digest);
    ck_assert_mem_eq(digest, fromhex("4225281b8498f05e0eaac02be79ce72471c2ddd8c127908b1f717bf64177b287"), SHA256_DIGEST_LENGTH);

    memcpy(my_seckey, fromhex("3c4289a9d884f74bd05c352fa1c08ce0d65955b59b24a572f46e02807dd42e62"), sizeof(my_seckey));
    memcpy(remote_pubkey, fromhex("0223496e9caa207e0f8cc283e970b85f2831732d5e0be2bcf9fa366f7e064a25dd"), sizeof(remote_pubkey));
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ecdh_shared_secret(my_seckey, remote_pubkey, digest);
    ck_assert_mem_eq(digest, fromhex("70e5d568b31ed601fcb7f3144888d0633938817ae85417de1fbd0d52e29b5d7c"), SHA256_DIGEST_LENGTH);

    memcpy(my_seckey, fromhex("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04"), sizeof(my_seckey));
    memcpy(remote_pubkey, fromhex("02683e90daa5b0dd195b69e01386390284d3b3723121ce213771d9a0815d12b86c"), sizeof(remote_pubkey));
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ecdh_shared_secret(my_seckey, remote_pubkey, digest);
    ck_assert_mem_eq(digest, fromhex("9ab65c0e99605712aac66be1eccccb6dacb867ebaf2b1ebf96d3d92524f247fd"), SHA256_DIGEST_LENGTH);
}
END_TEST


START_TEST(test_recover_pubkey_from_signed_message)
{
    int res;
    // uint8_t message[32];
    char message[256] = "Hello World!";
    uint8_t signature[65];
    uint8_t pubkey[33];
    // memcpy(message, fromhex("5dfbea13c81c48f7261994c148a7a39b9b51107d22b57bfd4613dce02dee46ee"), 32);
    memcpy(signature, fromhex("abc30130e2d9561fa8eb9871b75b13100689937dfc41c98d611b985ca25258c960be25c0b45874e1255f053863f6e175300d7e788d8b93d6dcfa9377120e4d3500"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);

    sprintf(message, "Hello World, it's me!");
    memcpy(signature, fromhex("54d7572cf5066225f349d89ad6d19e19e64d14711083f6607258b37407e5f0d26c6328d7c3ecb31eb4132f6b983f8ec33cdf3664c1df617526bbac140cdac75b01"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);

    memcpy(signature, fromhex("00b0dbb50c8b8f6c5be2bdee786a658a0ea22872ce90b21fbc0eb4f1d1018a043f93216a6af467acfb44aef9ab07e0a65621128504f3a61dfa0014b1cdd6d9c701"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);

    // sign with a different key pair
    // the seed for key pair generation was 'different'
    memcpy(signature, fromhex("5feef64dd9b9465e0f66ac21c5078cee4504f15ad407093b58908b69bc717d1c456901b4dbf9dde3eb170bd7aaf4e7a62f260e6194cc9884037affbfda250f3501"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    sprintf(message, "The seed was 'different'");
    memcpy(signature, fromhex("b8a91946af3cfe42139c853f09d1bc087db3bea0ab8bb20ab13790f4ba08aa4c327a4f614c61b2c532c2bab3852817ecd17b1c607f52f52c9c561ddbb2e4418e01"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    memcpy(signature, fromhex("f2e863beed0c026d0c631712dbe5ecb7ed95166275586271b77181ee3e68502b24c7a5c32b26ca5424fadfd8488285ad6e3ff3b86ed6c5449102d3198712f57b00"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    sprintf(message, "This msg has 24 letters.");
    memcpy(signature, fromhex("eff089c10e4c8d3c7244a8bc75d5657153ec7b42ed6d01bcc75cd08271a4aa7c19d1bd3b60330c909600238c1f18d99f06d2573c27cb4f2dfb0f65666a5a523200"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    sprintf(message, "This msg has 31 characters: ok!");
    memcpy(signature, fromhex("3dc77d17eeed0d3fd3d34ca05e8a9e84fbf73529b96bde7548080ac35d81470a60d5b8b37f2bb2500cf6a9745cd1c6edb81ebb5419e4f4fda9271794c8daf54200"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    // testing message maximal length
    sprintf(message, "This msg has 32 characters: max.");
    memcpy(signature, fromhex("e092ce21dda29349bd1e4e8b7a26d701542ac972b4e319a60bd887b6e51853622300e4e847f01a9aff4f51caa969759f717a6e5439b6bc4a5305b10bab9b5cb201"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    sprintf(message, "This msg has 32 characters: max..");
    memcpy(signature, fromhex("e092ce21dda29349bd1e4e8b7a26d701542ac972b4e319a60bd887b6e51853622300e4e847f01a9aff4f51caa969759f717a6e5439b6bc4a5305b10bab9b5cb201"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    sprintf(message, "This msg has 32 characters: max... What ever I write here is ignored.");
    memcpy(signature, fromhex("e092ce21dda29349bd1e4e8b7a26d701542ac972b4e319a60bd887b6e51853622300e4e847f01a9aff4f51caa969759f717a6e5439b6bc4a5305b10bab9b5cb201"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), 32);
    memcpy(signature, fromhex("864c6abf85214be99fed3dc37591a74282f566fb52fb56ab21dabc0d120f29b848ffeb52a7843a49c411753c0edc12c0dedf6313266722bee982a0d3b384b62600"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("03b17c7b7c564385be66f9c1b9da6a0b5aea56f0cb70548e6528a2f4f7b27245d8"), 33);

    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), 32);
    memcpy(signature, fromhex("631182b9722489eedd1a9eab36bf776c3e679aa2b1bd3fb346db0f776b982be25bdd33d4e893aca619eff3013e087307d22ca30644c96ea0fbdef06396d1bf9600"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("039f12c93645e35e5274dc38f191be0b6d1321ec35d2d2a3ddf7d13ed12f6da85b"), 33);

    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), 32);
    memcpy(signature, fromhex("d2a8ec2b29ce3cf3e6048296188adff4b5dfcb337c1d1157f28654e445bb940b4e47d6b0c7ba43d072bf8618775f123a435e8d1a150cb39bbb1aa80da8c57ea100"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("03338ffc0ff42df07d27b0b4131cd96ffdfa4685b5566aafc7aa71ed10fd1cbd6f"), 33);
}
END_TEST

START_TEST(test_signature)
{
    int res;
    uint8_t digest[32];
    uint8_t my_seckey[32];
    uint8_t signature[65];
    uint8_t pubkey[33];
    char* message = (char*)digest;
    memcpy(my_seckey, fromhex("597e27368656cab3c82bfcf2fb074cefd8b6101781a27709ba1b326b738d2c5a"), sizeof(my_seckey));
    memcpy(digest, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), 32);

    res = ecdsa_skycoin_sign(1, my_seckey, digest, signature);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), 32);
    ck_assert_mem_eq(&signature[32], fromhex("04641a7472bb90647fa60b4d30aef8c7279e4b68226f7b2713dab712ef122f8b01"), 32);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    res = ecdsa_skycoin_sign(0xfe25, my_seckey, digest, signature);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("ee38f27be5f3c4b8db875c0ffbc0232e93f622d16ede888508a4920ab51c3c99"), 32);
    ck_assert_mem_eq(&signature[32], fromhex("06ea7426c5e251e4bea76f06f554fa7798a49b7968b400fa981c51531a5748d801"), 32);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    res = ecdsa_skycoin_sign(0xfe250100, my_seckey, digest, signature);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("d4d869ad39cb3a64fa1980b47d1f19bd568430d3f929e01c00f1e5b7c6840ba8"), 32);
    ck_assert_mem_eq(&signature[32], fromhex("5e08d5781986ee72d1e8ebd4dd050386a64eee0256005626d2acbe3aefee9e2500"), 32);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), 33);

    // try of another key pair
    memcpy(my_seckey, fromhex("67a331669081d22624f16512ea61e1d44cb3f26af3333973d17e0e8d03733b78"), sizeof(my_seckey));

    res = ecdsa_skycoin_sign(0x1e2501ac, my_seckey, digest, signature);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("eeee743d79b40aaa52d9eeb48791b0ae81a2f425bf99cdbc84180e8ed429300d457e8d669dbff1716b123552baf6f6f0ef67f16c1d9ccd44e6785d424002212601"), 65);
    res = recover_pubkey_from_signed_message(message, signature, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("0270b763664593c5f84dfb20d23ef79530fc317e5ee2ece0d9c50f432f62426ff9"), 33);
}
END_TEST


START_TEST(test_checkdigest)
{
    ck_assert(is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132"));
    ck_assert(!is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761"));    //too short
    ck_assert(!is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761256")); //too long
    ck_assert(!is_digest("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761r"));   //non hex digits
}
END_TEST


START_TEST(test_addtransactioninput)
{
    // init transaction
    uint8_t addressIn[32];
    uint8_t digest[32];
    Transaction transaction;
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("99a1a50ffa21ab48ee7c31d01e7e14451f9834f5294468bd17e87c5018900b81"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("99a1a50ffa21ab48ee7c31d01e7e14451f9834f5294468bd17e87c5018900b81"), 32);
    // add output
    transaction_addOutput(&transaction, 125000000, 4, "d1hMF1XCCvFXVa2u7NbuWo9dmfNbdpoFLJ");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 125000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 4);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("597f682bf9d6302fc070eb0cee7c1c6a27653f21"), 20);
    // add one more output
    transaction_addOutput(&transaction, 2000000, 3, "2kVVoMkH7aTVXsiGwZEALpkHZ6sUyumL8hH");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 2);
    ck_assert_int_eq(transaction.outAddress[0].coin, 125000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 4);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("597f682bf9d6302fc070eb0cee7c1c6a27653f21"), 20);
    ck_assert_int_eq(transaction.outAddress[1].coin, 2000000);
    ck_assert_int_eq(transaction.outAddress[1].hour, 3);
    ck_assert_mem_eq(transaction.outAddress[1].address, fromhex("fc3a66b52bb478be3a62bf8a698a64fa2ffbdedc"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("0dcbbaf454e158cc87330900080315b9f288b5ceb2d1047299fabc4c407c1a18"), 32);


    // -- SAMPLE 1
    // -- in hash: 181bd5656115172fe81451fae4fb56498a97744d89702e73da75ba91ed5200f9
    // -- out address: K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot - coins: 100000 - hours: 2
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("181bd5656115172fe81451fae4fb56498a97744d89702e73da75ba91ed5200f9"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("181bd5656115172fe81451fae4fb56498a97744d89702e73da75ba91ed5200f9"), 32);
    // add output
    transaction_addOutput(&transaction, 100000, 2, "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 100000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 2);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("2d18bf01abe4e295f907101316f980c0cb25de4b002a7fb54b"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("3992834f0cf7deb087c606d3935358da3760d04c00b484258d1be65cbbd00f4b"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("d11c62b1e0e9abf629b1f5f4699cef9fbc504b45ceedf0047ead686979498218"), 32);


    // -- SAMPLE 2
    // -- in hash: 01a9ef6c25271229ef9760e1536c3dc5ccf0ead7de93a64c12a01340670d87e9
    // -- in hash: 8c2c97bfd34e0f0f9833b789ce03c2e80ac0b94b9d0b99cee6ea76fb662e8e1c
    // -- out address: K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot - coins: 20800000 - hours: 255
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("01a9ef6c25271229ef9760e1536c3dc5ccf0ead7de93a64c12a01340670d87e9"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("01a9ef6c25271229ef9760e1536c3dc5ccf0ead7de93a64c12a01340670d87e9"), 32);
    // add input
    memcpy(addressIn, fromhex("8c2c97bfd34e0f0f9833b789ce03c2e80ac0b94b9d0b99cee6ea76fb662e8e1c"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 2);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[1], fromhex("8c2c97bfd34e0f0f9833b789ce03c2e80ac0b94b9d0b99cee6ea76fb662e8e1c"), 32);
    // add output
    transaction_addOutput(&transaction, 20800000, 255, "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot");
    ck_assert_int_eq(transaction.nbIn, 2);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 20800000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 255);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("2d18bf01abe4e295f907101316f980c0cb25de4b002a7fb54b"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("1b190d3eb4981c221204e7d303efcf04661bb575c59b26f09c45d422a92a6453"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("9bbde062d665a8b11ae15aee6d4f32f0f3d61af55160c142060795a219378a54"), 32);
    transaction_msgToSign(&transaction, 1, digest);
    ck_assert_mem_eq(digest, fromhex("f947b0352b19672f7b7d04dc2f1fdc47bc5355878f3c47a43d4d4cfbae07d026"), 32);


    // -- SAMPLE 3
    // -- in hash: da3b5e29250289ad78dc42dcf007ab8f61126198e71e8306ff8c11696a0c40f7
    // -- in hash: 33e826d62489932905dd936d3edbb74f37211d68d4657689ed4b8027edcad0fb
    // -- in hash: 668f4c144ad2a4458eaef89a38f10e5307b4f0e8fce2ade96fb2cc2409fa6592
    // -- out address: K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot - coins: 111000000 - hours: 6464556
    // -- out address: 2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8 - coins: 1900000 - hours: 1
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("da3b5e29250289ad78dc42dcf007ab8f61126198e71e8306ff8c11696a0c40f7"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("da3b5e29250289ad78dc42dcf007ab8f61126198e71e8306ff8c11696a0c40f7"), 32);
    // add input
    memcpy(addressIn, fromhex("33e826d62489932905dd936d3edbb74f37211d68d4657689ed4b8027edcad0fb"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 2);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[1], fromhex("33e826d62489932905dd936d3edbb74f37211d68d4657689ed4b8027edcad0fb"), 32);
    // add input
    memcpy(addressIn, fromhex("668f4c144ad2a4458eaef89a38f10e5307b4f0e8fce2ade96fb2cc2409fa6592"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 3);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[2], fromhex("668f4c144ad2a4458eaef89a38f10e5307b4f0e8fce2ade96fb2cc2409fa6592"), 32);
    // add output
    transaction_addOutput(&transaction, 111000000, 6464556, "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot");
    ck_assert_int_eq(transaction.nbIn, 3);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 111000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 6464556);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("2d18bf01abe4e295f907101316f980c0cb25de4b002a7fb54b"), 20);
    // add output
    transaction_addOutput(&transaction, 1900000, 1, "2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8");
    ck_assert_int_eq(transaction.nbIn, 3);
    ck_assert_int_eq(transaction.nbOut, 2);
    ck_assert_int_eq(transaction.outAddress[1].coin, 1900000);
    ck_assert_int_eq(transaction.outAddress[1].hour, 1);
    ck_assert_mem_eq(transaction.outAddress[1].address, fromhex("f6f3e048062dff0ccc237d7de1345a6dcabaded200458dead1"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("ab8b7d61fb330c446366e804e1586c62fd14bbb850eea83e880539f09fe5d336"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("ff383c647551a3ba0387f8334b3f397e45f9fc7b3b5c3b18ab9f2b9737bce039"), 32);
    transaction_msgToSign(&transaction, 1, digest);
    ck_assert_mem_eq(digest, fromhex("c918d83d8d3b1ee85c1d2af6885a0067bacc636d2ebb77655150f86e80bf4417"), 32);
    transaction_msgToSign(&transaction, 2, digest);
    ck_assert_mem_eq(digest, fromhex("0e827c5d16bab0c3451850cc6deeaa332cbcb88322deea4ea939424b072e9b97"), 32);


    // -- SAMPLE 4
    // -- in hash: b99f62c5b42aec6be97f2ca74bb1a846be9248e8e19771943c501e0b48a43d82
    // -- in hash: cd13f705d9c1ce4ac602e4c4347e986deab8e742eae8996b34c429874799ebb2
    // -- out address: 22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF - coins: 23100000 - hours: 0
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("b99f62c5b42aec6be97f2ca74bb1a846be9248e8e19771943c501e0b48a43d82"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("b99f62c5b42aec6be97f2ca74bb1a846be9248e8e19771943c501e0b48a43d82"), 32);
    // add input
    memcpy(addressIn, fromhex("cd13f705d9c1ce4ac602e4c4347e986deab8e742eae8996b34c429874799ebb2"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 2);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[1], fromhex("cd13f705d9c1ce4ac602e4c4347e986deab8e742eae8996b34c429874799ebb2"), 32);
    // add output
    transaction_addOutput(&transaction, 23100000, 0, "22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF");
    ck_assert_int_eq(transaction.nbIn, 2);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 23100000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 0);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("93b472a9a187bb70cfdc78151c7cc5c7ab5cba580094398734"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("4317dfb226f2ff72fc8206ac26e9e8817a0036f2baada722f3fd02a74dee5088"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("42a26380399172f2024067a17704fceda607283a0f17cb0024ab7a96fc6e4ac6"), 32);
    transaction_msgToSign(&transaction, 1, digest);
    ck_assert_mem_eq(digest, fromhex("5e0a5a8c7ea4a2a500c24e3a4bfd83ef9f74f3c2ff4bdc01240b66a41e34ebbf"), 32);


    // -- SAMPLE 5
    // -- in hash: 4c12fdd28bd580989892b0518f51de3add96b5efb0f54f0cd6115054c682e1f1
    // -- out address: 2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8 - coins: 1000000 - hours: 0
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("4c12fdd28bd580989892b0518f51de3add96b5efb0f54f0cd6115054c682e1f1"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("4c12fdd28bd580989892b0518f51de3add96b5efb0f54f0cd6115054c682e1f1"), 32);
    // add output
    transaction_addOutput(&transaction, 1000000, 0, "2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 1000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 0);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("f6f3e048062dff0ccc237d7de1345a6dcabaded200458dead1"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("17f7533b71f194b95f4174c205ec16f0041ff8c97487ab0cdffd5dca168c64f9"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("c40e110f5e460532bfb03a5a0e50262d92d8913a89c87869adb5a443463dea69"), 32);


    // -- SAMPLE 6
    // -- in hash: c5467f398fc3b9d7255d417d9ca208c0a1dfa0ee573974a5fdeb654e1735fc59
    // -- out address: K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot - coins: 10000000 - hours: 1
    // -- out address: VNz8LR9JTSoz5o7qPHm3QHj4EiJB6LV18L - coins: 5500000 - hours: 0
    // -- out address: 22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF - coins: 4500000 - hours: 1
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("c5467f398fc3b9d7255d417d9ca208c0a1dfa0ee573974a5fdeb654e1735fc59"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("c5467f398fc3b9d7255d417d9ca208c0a1dfa0ee573974a5fdeb654e1735fc59"), 32);
    // add output
    transaction_addOutput(&transaction, 10000000, 1, "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 10000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 1);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("2d18bf01abe4e295f907101316f980c0cb25de4b002a7fb54b"), 20);
    // add output
    transaction_addOutput(&transaction, 5500000, 0, "VNz8LR9JTSoz5o7qPHm3QHj4EiJB6LV18L");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 2);
    ck_assert_int_eq(transaction.outAddress[1].coin, 5500000);
    ck_assert_int_eq(transaction.outAddress[1].hour, 0);
    ck_assert_mem_eq(transaction.outAddress[1].address, fromhex("468734bf340ea7e21a407c5d7c4274cc11a8d9320002f76a59"), 20);
    // add output
    transaction_addOutput(&transaction, 4500000, 1, "22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 3);
    ck_assert_int_eq(transaction.outAddress[2].coin, 4500000);
    ck_assert_int_eq(transaction.outAddress[2].hour, 1);
    ck_assert_mem_eq(transaction.outAddress[2].address, fromhex("93b472a9a187bb70cfdc78151c7cc5c7ab5cba580094398734"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("60f308a2038c59027b7ff8fdb257ed48907639d57806c6f57799ccf38d4c910d"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("7edea77354eca0999b1b023014eb04638b05313d40711707dd03a9935696ccd1"), 32);


    // -- SAMPLE 7
    // -- in hash: 7b65023cf64a56052cdea25ce4fa88943c8bc96d1ab34ad64e2a8b4c5055087e
    // -- in hash: 0c0696698cba98047bc042739e14839c09bbb8bb5719b735bff88636360238ad
    // -- in hash: ae3e0b476b61734e590b934acb635d4ad26647bc05867cb01abd1d24f7f2ce50
    // -- out address: 22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF - coins: 25000000 - hours: 33
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("7b65023cf64a56052cdea25ce4fa88943c8bc96d1ab34ad64e2a8b4c5055087e"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("7b65023cf64a56052cdea25ce4fa88943c8bc96d1ab34ad64e2a8b4c5055087e"), 32);
    // add input
    memcpy(addressIn, fromhex("0c0696698cba98047bc042739e14839c09bbb8bb5719b735bff88636360238ad"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 2);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[1], fromhex("0c0696698cba98047bc042739e14839c09bbb8bb5719b735bff88636360238ad"), 32);
    // add input
    memcpy(addressIn, fromhex("ae3e0b476b61734e590b934acb635d4ad26647bc05867cb01abd1d24f7f2ce50"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 3);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[2], fromhex("ae3e0b476b61734e590b934acb635d4ad26647bc05867cb01abd1d24f7f2ce50"), 32);
    // add output
    transaction_addOutput(&transaction, 25000000, 33, "22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF");
    ck_assert_int_eq(transaction.nbIn, 3);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 25000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 33);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("93b472a9a187bb70cfdc78151c7cc5c7ab5cba580094398734"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("25107eb9547cc6602b650294beaaf0bdd40fd2dc38f21d15d4534ba84a6b2c33"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("ec9053ab9988feb0cfb3fcce96f02c7d146ff7a164865c4434d1dbef42a24e91"), 32);
    transaction_msgToSign(&transaction, 1, digest);
    ck_assert_mem_eq(digest, fromhex("332534f92c27b31f5b73d8d0c7dde4527b540024f8daa965fe9140e97f3c2b06"), 32);
    transaction_msgToSign(&transaction, 2, digest);
    ck_assert_mem_eq(digest, fromhex("63f955205ceb159415268bad68acaae6ac8be0a9f33ef998a84d1c09a8b52798"), 32);


    // -- SAMPLE 8
    // -- in hash: ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da
    // -- out address: 3pXt9MSQJkwgPXLNePLQkjKq8tsRnFZGQA - coins: 1000000 - hours: 1000
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da"), 32);
    // add output
    transaction_addOutput(&transaction, 1000000, 1000, "3pXt9MSQJkwgPXLNePLQkjKq8tsRnFZGQA");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 1000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 1000);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("0701d3acaa76ec13a3ccda5fdcb58c2bc7fac4150098698f5b"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("d533d8643af5e5d9dcdef6a96e4548c2c035803bd2b84e6a7120de8483f45abf"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("47bfa37c79f7960df8e8a421250922c5165167f4c91ecca5682c1106f9010a7f"), 32);


    // -- SAMPLE 9
    // -- in hash: ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da
    // -- out address: 3pXt9MSQJkwgPXLNePLQkjKq8tsRnFZGQA - coins: 300000 - hours: 500
    // -- out address: S6Dnv6gRTgsHCmZQxjN7cX5aRjJvDvqwp9 - coins: 700000 - hours: 500
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da"), 32);
    // add output
    transaction_addOutput(&transaction, 300000, 500, "3pXt9MSQJkwgPXLNePLQkjKq8tsRnFZGQA");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 300000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 500);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("0701d3acaa76ec13a3ccda5fdcb58c2bc7fac4150098698f5b"), 20);
    // add output
    transaction_addOutput(&transaction, 700000, 500, "S6Dnv6gRTgsHCmZQxjN7cX5aRjJvDvqwp9");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 2);
    ck_assert_int_eq(transaction.outAddress[1].coin, 700000);
    ck_assert_int_eq(transaction.outAddress[1].hour, 500);
    ck_assert_mem_eq(transaction.outAddress[1].address, fromhex("3e5aaa55d30d389a651e8fbd4d6b0c8fbee773750077f2ab56"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("a1697116c1a96a8db60939629f768f4b241c54b89f03a8a1397f45ec9ce7bf2b"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("e0c6e4982b1b8c33c5be55ac115b69be68f209c5d9054954653e14874664b57d"), 32);


    // -- SAMPLE 10
    // -- in hash: ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da
    // -- out address: S6Dnv6gRTgsHCmZQxjN7cX5aRjJvDvqwp9 - coins: 1000000 - hours: 1000
    transaction_initZeroTransaction(&transaction);
    ck_assert_int_eq(transaction.nbIn, 0);
    ck_assert_int_eq(transaction.nbOut, 0);
    // add input
    memcpy(addressIn, fromhex("ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da"), 32);
    transaction_addInput(&transaction, addressIn);
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 0);
    ck_assert_mem_eq(&transaction.inAddress[0], fromhex("ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da"), 32);
    // add output
    transaction_addOutput(&transaction, 1000000, 1000, "S6Dnv6gRTgsHCmZQxjN7cX5aRjJvDvqwp9");
    ck_assert_int_eq(transaction.nbIn, 1);
    ck_assert_int_eq(transaction.nbOut, 1);
    ck_assert_int_eq(transaction.outAddress[0].coin, 1000000);
    ck_assert_int_eq(transaction.outAddress[0].hour, 1000);
    ck_assert_mem_eq(transaction.outAddress[0].address, fromhex("3e5aaa55d30d389a651e8fbd4d6b0c8fbee773750077f2ab56"), 20);

    // compute inner hash
    transaction_innerHash(&transaction);
    ck_assert_mem_eq(transaction.innerHash, fromhex("7b16f31f1cfb7aa0da3c48283560515c7c3f6669efb9cc57e0ef4016516c1c3a"), 32);

    transaction_msgToSign(&transaction, 0, digest);
    ck_assert_mem_eq(digest, fromhex("457648543755580ad40ab461bbef2b0ffe19f2130f2f220cbb2f196b05d436b4"), 32);
}
END_TEST

// define test suite and cases
Suite* test_suite(void)
{
    Suite* s = suite_create("skycoin_crypto");
    TCase* tc;

    tc = tcase_create("checksums");
    tcase_add_test(tc, test_generate_public_key_from_seckey);
    tcase_add_test(tc, test_generate_key_pair_from_seed);
    tcase_add_test(tc, test_secp256k1Hash);
    tcase_add_test(tc, test_generate_deterministic_key_pair_iterator);
    tcase_add_test(tc, test_base58_address_from_pubkey);
    tcase_add_test(tc, test_bitcoin_address_from_pubkey);
    tcase_add_test(tc, test_bitcoin_private_address_from_seckey);
    tcase_add_test(tc, test_compute_sha256sum);
    tcase_add_test(tc, test_compute_ecdh);
    tcase_add_test(tc, test_recover_pubkey_from_signed_message);
    tcase_add_test(tc, test_base58_decode);
    tcase_add_test(tc, test_signature);
    tcase_add_test(tc, test_checkdigest);
    tcase_add_test(tc, test_addtransactioninput);
    suite_add_tcase(s, tc);

    return s;
}


// run suite
int main(void)
{
    int number_failed;
    Suite* s = test_suite();
    SRunner* sr = srunner_create(s);
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (number_failed == 0) {
        printf("PASSED ALL TESTS\n");
    }
    return number_failed;
}
