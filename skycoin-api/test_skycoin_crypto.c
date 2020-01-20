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
#include "tools/curves.h"
#include "skycoin_constants.h"
#include "bitcoin_constants.h"
#include "skycoin_crypto.h"
#include "bitcoin_crypto.h"
#include "skycoin_signature.h"
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

START_TEST(test_skycoin_pubkey_from_seckey)
{
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};

    memcpy(seckey, fromhex("a7e130694166cdb95b1e1bbce3f21e4dbd63f46df42b48c5a1f8295033d57d04"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("0244350faa76799fec03de2f324acd077fd1b686c3a89babc0ef47096ccc5a13fa"), SKYCOIN_PUBKEY_LEN);

    memcpy(seckey, fromhex("c89b70a1f7b960c08068de9f2d3b32287833b26372935aa5042f7cc1dc985335"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("03b17c7b7c564385be66f9c1b9da6a0b5aea56f0cb70548e6528a2f4f7b27245d8"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vectors from TestSigSignRecover
    memcpy(seckey, fromhex("597e27368656cab3c82bfcf2fb074cefd8b6101781a27709ba1b326b738d2c5a"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    memcpy(seckey, fromhex("67a331669081d22624f16512ea61e1d44cb3f26af3333973d17e0e8d03733b78"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("0270b763664593c5f84dfb20d23ef79530fc317e5ee2ece0d9c50f432f62426ff9"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector 1 from TestAbnormalKeys2
    memcpy(seckey, fromhex("08efb79385c9a8b0d1c6f5f6511be0c6f6c2902963d874a3a4bacc18802528d3"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("03c74332d6094b1f603d4902fc6b1aa09fb3ef81f3015a4000cc0077ff70543c16"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector 2 from TestAbnormalKeys2
    memcpy(seckey, fromhex("78298d9ecdc0640c9ae6883201a53f4518055442642024d23c45858f45d0c3e6"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("02fa3e6e0b1fb76e26dffe7b1e01fd02677fedfed23a59000092c706b04214bee3"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector 3 from TestAbnormalKeys2
    memcpy(seckey, fromhex("04e04fe65bfa6ded50a12769a3bd83d7351b2dbff08c9bac14662b23a3294b9e"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("034f25c9400dd0f87a9c420b35b5a157d21caa086ef8fa00015bc3c8ab73a1cc4c"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector 4 from TestAbnormalKeys2
    memcpy(seckey, fromhex("2f5141f1b75747996c5de77c911dae062d16ae48799052c04ead20ccd5afa113"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("03fe58baefc491a9dcf0939ab6252f81f6d9515105bd89c000bb7f2a694e8a8b72"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector from TestPubkeyFromSeckey
    memcpy(seckey, fromhex("f19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4"), sizeof(seckey));
    skycoin_pubkey_from_seckey(seckey, pubkey);
    ck_assert_mem_eq(pubkey, fromhex("03fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef1"), SKYCOIN_PUBKEY_LEN);
}
END_TEST

START_TEST(test_secp256k1Hash)
{
    int ret;
    char seed[256] = "seed";
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("c79454cf362b3f55e5effce09f664311650a44b9c189b3c8eed1ae9bd696cd9e"), SHA256_DIGEST_LENGTH);

    strcpy(seed, "random_seed");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("5e81d46f56767496bc05ed177c5237cd4fe5013e617c726af43e1cba884f17d1"), SHA256_DIGEST_LENGTH);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("5e81d46f56767496bc05ed177c5237cd4fe5013e617c726af43e1cba884f17d1"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector file: integration-test.wlt
    strcpy(seed, "exchange stage green marine palm tobacco decline shadow cereal chapter lamp copy");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("1c0ff9dd77fb5dd079078c3098e61a9d99965e8d55121cc3fb576af61d6d450a"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector file: test1.wlt
    strcpy(seed, "buddy fossil side modify turtle door label grunt baby worth brush master");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("9182b02c0004217ba9a55593f8cf0abecc30d041e094b266dbb5103e1919adaf"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector file: test1.wlt
    strcpy(seed, "buddy fossil side modify turtle door label grunt baby worth brush master");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("9182b02c0004217ba9a55593f8cf0abecc30d041e094b266dbb5103e1919adaf"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector file: test2.wlt
    strcpy(seed, "sample assume enjoy museum behind horror mad reward forward reform valley planet");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("67de80ac3ae025c8742bec541da7018d08fa351983557d2bc753e90e24337d13"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector file: test3.wlt
    strcpy(seed, "acoustic test story tank thrive wine able frequent marriage use swim develop");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, strlen(seed), digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("f3a7942899ed2723999288ea83f4f20908bf9deabc05bc8216339da4d3e02c0b"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 1 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("90c56f5b8d78a46fb4cddf6fd9c6d88d6d2d7b0ec35917c7dac12c03b04e444e"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("a70c36286be722d8111e69e910ce4490005bbf9135b0ce8e7a59f84eee24b88b"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 2 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("a3b08ccf8cbae4955c02f223be1f97d2bb41d92b7f0c516eb8467a17da1e6057"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("e9db072fe5817325504174253a056be7b53b512f1e588f576f1f5a82cdcad302"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 3 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("7048eb8fa93cec992b93dc8e93c5543be34aad05239d4c036cf9e587bbcf7654"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("5e9133e83c4add2b0420d485e1dcda5c00e283c6509388ab8ceb583b0485c13b"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 4 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("6d25375591bbfce7f601fc5eb40e4f3dde2e453dc4bf31595d8ec29e4370cd80"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("8d5579cd702c06c40fb98e1d55121ea0d29f3a6c42f5582b902ac243f29b571a"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 5 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("7214b4c09f584c5ddff971d469df130b9a3c03e0277e92be159279de39462120"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("3a4e8c72921099a0e6a4e7f979df4c8bced63063097835cdfd5ee94548c9c41a"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 6 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("b13e78392d5446ae304b5fc9d45b85f26996982b2c0c86138afdac8d2ea9016e"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("462efa1bf4f639ffaedb170d6fb8ba363efcb1bdf0c5aef0c75afb59806b8053"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 7 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("9403bff4240a5999e17e0ab4a645d6942c3a7147c7834e092e461a4580249e6e"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("68dd702ea7c7352632876e9dc2333142fce857a542726e402bb480cad364f260"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 8 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("2665312a3e3628f4df0b9bc6334f530608a9bcdd4d1eef174ecda99f51a6db94"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("5db72c31d575c332e60f890c7e68d59bd3d0ac53a832e06e821d819476e1f010"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 9 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("6cb37532c80765b7c07698502a49d69351036f57a45a5143e33c57c236d841ca"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("0deb20ec503b4c678213979fd98018c56f24e9c1ec99af3cd84b43c161a9bb5c"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 10 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("8654a32fa120bfdb7ca02c487469070eba4b5a81b03763a2185fdf5afd756f3c"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("36f3ede761aa683813013ffa84e3738b870ce7605e0a958ed4ffb540cd3ea504"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 11 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("66d1945ceb6ef8014b1b6703cb624f058913e722f15d03225be27cb9d8aabe4a"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("6bcb4819a96508efa7e32ee52b0227ccf5fbe5539687aae931677b24f6d0bbbd"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 12 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("22c7623bf0e850538329e3e6d9a6f9b1235350824a3feaad2580b7a853550deb"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("8bb257a1a17fd2233935b33441d216551d5ff1553d02e4013e03f14962615c16"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 13 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("a5eebe3469d68c8922a1a8b5a0a2b55293b7ff424240c16feb9f51727f734516"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("d6b780983a63a3e4bcf643ee68b686421079c835a99eeba6962fe41bb355f8da"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 14 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("479ec3b589b14aa7290b48c2e64072e4e5b15ce395d2072a5a18b0a2cf35f3fd"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("39c5f108e7017e085fe90acfd719420740e57768ac14c94cb020d87e36d06752"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 15 from TestSecp256k1Hash
    memset(seed, 0, 256);
    memcpy(seed, (const char*)fromhex("63952334b731ec91d88c54614925576f82e3610d009657368fc866e7b1efbe73"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("79f654976732106c0e4a97ab3b6d16f343a05ebfcc2e1d679d69d396e6162a77"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 16 from TestSecp256k1Hash
    memcpy(seed, (const char*)fromhex("256472ee754ef6af096340ab1e161f58e85fb0cc7ae6e6866b9359a1657fa6c1"), 32);
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    ret = secp256k1sum((const uint8_t*)seed, 32, digest);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(digest, fromhex("387883b86e2acc153aa334518cea48c0c481b573ccaacf17c575623c392f78b2"), SHA256_DIGEST_LENGTH);
}
END_TEST

START_TEST(test_deterministic_key_pair_iterator)
{
    int ret;
    char seed[256] = {0};
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    uint8_t next_seed[SHA256_DIGEST_LENGTH] = {0};

    strcpy(seed, "seed");
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);
    ck_assert_mem_eq(seckey, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), 32);
    ck_assert_mem_eq(next_seed, fromhex("c79454cf362b3f55e5effce09f664311650a44b9c189b3c8eed1ae9bd696cd9e"), 32);

    strcpy(seed, "random_seed");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73"), 33);
    ck_assert_mem_eq(seckey, fromhex("ff671860c58aad3f765d8add25046412dabf641186472e1553435e6e3c4a6fb0"), 32);
    ck_assert_mem_eq(next_seed, fromhex("5e81d46f56767496bc05ed177c5237cd4fe5013e617c726af43e1cba884f17d1"), 32);

    strcpy(seed, "hello seed");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0"), 33);
    ck_assert_mem_eq(seckey, fromhex("84fdc649964bf299a787cb78cd975910e197dbddd7db776ece544f41c44b3056"), 32);
    ck_assert_mem_eq(next_seed, fromhex("70d382540812d4abc969dcc2adc66e805db96f7e1dcbe1ae6bbf2878211cbcf6"), 32);

    strcpy(seed, "skycoin5");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03b17c7b7c564385be66f9c1b9da6a0b5aea56f0cb70548e6528a2f4f7b27245d8"), 33);
    ck_assert_mem_eq(seckey, fromhex("c89b70a1f7b960c08068de9f2d3b32287833b26372935aa5042f7cc1dc985335"), 32);

    // Skycoin core test vector file: test1.wlt
    strcpy(seed, "buddy fossil side modify turtle door label grunt baby worth brush master");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("028ef95b281f1bd6483f0c5c1ed1144b77c360b92a4eb48f681a6dff67a7c2dab1"), 33);
    ck_assert_mem_eq(seckey, fromhex("1fc5396e91e60b9fc613d004ea5bd2ccea17053a12127301b3857ead76fdb93e"), 32);

    // Skycoin core test vector file: test2.wlt
    strcpy(seed, "sample assume enjoy museum behind horror mad reward forward reform valley planet");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03595cffa8e5906b08be0c6bf907c9b6ad70f422b7c875b1a0da2c11114145c71f"), 33);
    ck_assert_mem_eq(seckey, fromhex("7154a28fc9939a759cd00067130507e118e8e068ed0df595d488c2562ce8c9f0"), 32);

    // Skycoin core test vector file: test3.wlt
    strcpy(seed, "acoustic test story tank thrive wine able frequent marriage use swim develop");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03a179e412d9d27e14ba647177648a871a7311f15a5312064c7abac1d72764081c"), 33);
    ck_assert_mem_eq(seckey, fromhex("7889f1d107dade4369bbb1ab6a55cf74a31d0524601398f03a57c5b0b1f5444b"), 32);

    // Skycoin core test vectors from TestDeterministicKeypairs03
    strcpy(seed, "tQ93w5Aqcunm9SGUfnmF4fJv");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03996e65d79e957ce1eafb57453e55b55906e04c8de556e54961eb06a4836c06df"), 33);
    ck_assert_mem_eq(seckey, fromhex("9b8c3e36adce64dedc80d6dfe51ff1742cc1d755bbad457ac01177c5a18a789f"), 32);

    strcpy(seed, "DC7qdQQtbWSSaekXnFmvQgse");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("0283a86efb1b8d82147c336c83d991f8124f0c4ca62c1019d6af1db46ae34594be"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("d2deaf4a9ff7a5111fe1d429d6976cbde78811fdd075371a2a4449bb0f4d8bf9"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "X8EkuUZC7Td7PAXeS7Duc7vR");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03f1fbd857b8a19de3ae35d616d41f179c0f3de94231e3caabf34eabf4674a1643"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("cad79b6dcf7bd21891cbe20a51c57d59689ae6e3dc482cd6ec22898ac00cd86b"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "tVqPYHHNVPRWyEed62v7f23u");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03ebde2c29e3beadab6f324ceb82a71c23655678e47d97f1d92159c3d7e4b59be4"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("2a386e94e9ffaa409517cbed81b9b2d4e1c5fb4afe3cbd67ce8aba11af0b02fa"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "kCy4R57HDfLqF3pVhBWxuMcg");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03b27bd3ae6b9034a4ffb2173381448c724f649fd0ec14ee0288758aa7812a7338"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("26a7c6d8809c476a56f7455209f58b5ff3f16435fcf208ff2931ece60067f305"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "j8bjv86ZNjKqzafR6mtSUVCE");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("0236b5d52711f8a11da664c57da4378690751016ecf3089eed4ed1833c610046b6"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("ea5c0f8c9f091a70bf38327adb9b2428a9293e7a7a75119920d759ecfa03a995"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "qShryAzVY8EtsuD3dsAc7qnG");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02da2aab09ec94e8a40d7381f72ff6585bf7d87e4a599d1408d2686ce5514692b1"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("331206176509bcae31c881dc51e90a4e82ec33cd7208a5fb4171ed56602017fa"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "5FGG7ZBa8wVMBJkmzpXj5ESX");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02b7d159de0d705c99e24d609b1591b1fac86d46c2c99e2ce6cc20b7402e32215c"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("4ea2ad82e7730d30c0c21d01a328485a0cf5543e095139ba613929be7739b52c"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "f46TZG4xJHXUGWx8ekbNqa9F");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03e709fbdaf4f3b913b8c4ea887d1fea61ed356fcf0178ee7c2b556ce308cfc001"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("dcddd403d3534c4ef5703cc07a771c107ed49b7e0643c6a2985a96149db26108"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "XkZdQJ5LT96wshN8JBH8rvEt");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03a34782043386f068780cc82d0deffcea1703e4e4bbe67537a89bda0fbd3240e0"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("3e276219081f072dff5400ca29a9346421eaaf3c419ff1474ac1c81ad8a9d6e1"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "GFDqXU4zYymhJJ9UGqRgS8ty");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03ad4b4525c6031c2fa3c43722ca6dbde64b30d646b8914b0391096d8964e5d4da"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("95be4163085b571e725edeffa83fff8e7a7db3c1ccab19d0f3c6e105859b5e10"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "tmwZksH2XyvuamnddYxyJ5Lp");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03f127118872ac5cb83b9167e561a28d82f4691d06297051dc71fb97d00b42aa20"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("2666dd54e469df56c02e82dffb4d3ea067daafe72c54dc2b4f08c4fb3a7b7e42"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "EuqZFsbAV5amTzkhgAMgjr7W");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03df10131650e63894e6c43427fc9ad0119a956ef1821c68f0e09e7d90411e6c39"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("40c325c01f2e4087fcc97fcdbea6c35c88a12259ebf1bce0b14a4d77f075abbf"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "TW6j8rMffZfmhyDEt2JUCrLB");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03f9ead3620dfcfcf731d42b0752a2e1549b0190070eed686002e02f58da955731"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("e676e0685c5d1afd43ad823b83db5c6100135c35485146276ee0b0004bd6689e"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "8rvkBnygfhWP8kjX9aXq68CY");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("026ace328af3200b4abe13a29125545bd9d82cc32eed13b782371ef54fb6301d6c"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("21450a646eed0d4aa50a1736e6c9bf99fff006a470aab813a2eff3ee4d460ae4"), SKYCOIN_SECKEY_LEN);

    strcpy(seed, "phyRfPDuf9JMRFaWdGh7NXPX");
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, strlen(seed), next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03fc05f68ef56235b777168c45d46dfb8f665d12e4f92265305b2e66aafe000351"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("ca7bc04196c504d0e815e125f7f1e086c8ae8c10d5e9df984aeab4b41bf9e398"), SKYCOIN_SECKEY_LEN);

    // Skycoin core test vectors from TestDeterministicKeyPairIterator1
    memcpy(seed, fromhex("90c56f5b8d78a46fb4cddf6fd9c6d88d6d2d7b0ec35917c7dac12c03b04e444e"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03eb71274ba23438f4ce6ac125e20bb78cd8123dc9483b5f34ace67cb6972e4ca8"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("94dd1a9de9ffd57b5516b8a7f090da67f142f7d22356fa5d1b894ee4d4fba95b"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("a70c36286be722d8111e69e910ce4490005bbf9135b0ce8e7a59f84eee24b88b"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("a3b08ccf8cbae4955c02f223be1f97d2bb41d92b7f0c516eb8467a17da1e6057"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02be1c44351c2e4295e4e9257667b164e2a0e471ecf499084357c13e1b5119b4c2"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("82fba4cc2bc29eef122f116f45d01d82ff488d7ee713f8a95c162a64097239e0"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("e9db072fe5817325504174253a056be7b53b512f1e588f576f1f5a82cdcad302"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("7048eb8fa93cec992b93dc8e93c5543be34aad05239d4c036cf9e587bbcf7654"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("028868f984547f2febcdd9087a1cc3528929598b1afc9feec0fa62233052bff401"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("44c059496aac871ac168bb6889b9dd3decdb9e1fa082442a95fcbca982643425"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("5e9133e83c4add2b0420d485e1dcda5c00e283c6509388ab8ceb583b0485c13b"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("6d25375591bbfce7f601fc5eb40e4f3dde2e453dc4bf31595d8ec29e4370cd80"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("035f0b2cd081f6dd45178d87be62c88b020599292cf77834d8a4dab7a7aad6b1be"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("d709ceb1a6fb906de506ea091c844ca37c65e52778b8d257d1dd3a942ab367fb"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("8d5579cd702c06c40fb98e1d55121ea0d29f3a6c42f5582b902ac243f29b571a"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("7214b4c09f584c5ddff971d469df130b9a3c03e0277e92be159279de39462120"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("032e039b5885d2d6001b2b5eb4b0af473befa04d2d9fbc4c12ef78f30fe186e487"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("5fe4986fa964773041e119d2b6549acb392b2277a72232af75cbfb62c357c1a7"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("3a4e8c72921099a0e6a4e7f979df4c8bced63063097835cdfd5ee94548c9c41a"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("b13e78392d5446ae304b5fc9d45b85f26996982b2c0c86138afdac8d2ea9016e"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02f32b1960c1e61ccc58bb458b8e6fc74a2c37fcb1deb0708251b35e55ba11795e"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("f784abc2e7f11ee84b4adb72ea4730a6aabe27b09604c8e2b792d8a1a31881ac"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("462efa1bf4f639ffaedb170d6fb8ba363efcb1bdf0c5aef0c75afb59806b8053"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("9403bff4240a5999e17e0ab4a645d6942c3a7147c7834e092e461a4580249e6e"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03f60cefd9bcc6f38487ae082d475c86ee086f0dfed25ff8758c1a9b06862dd0b8"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("d495174b8d3f875226b9b939121ec53f9383bd560d34aa5ca3ac6b257512adf4"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("68dd702ea7c7352632876e9dc2333142fce857a542726e402bb480cad364f260"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("2665312a3e3628f4df0b9bc6334f530608a9bcdd4d1eef174ecda99f51a6db94"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("029a3b04c75549c8a509fb42a2fa4e8d8361bbe543ee93ccecea90411924f5ab5b"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("1fdc9fbfc6991b9416b3a8385c9942e2db59009aeb2d8de349b73d9f1d389374"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("5db72c31d575c332e60f890c7e68d59bd3d0ac53a832e06e821d819476e1f010"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("6cb37532c80765b7c07698502a49d69351036f57a45a5143e33c57c236d841ca"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02b0f062bdf46066a9a7adb9337a6741ffe95ec26c5652d178dfff88ad302c962d"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("c87c85a6f482964db7f8c31720981925b1e357a9fdfcc585bc2164fdef1f54d0"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("0deb20ec503b4c678213979fd98018c56f24e9c1ec99af3cd84b43c161a9bb5c"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("8654a32fa120bfdb7ca02c487469070eba4b5a81b03763a2185fdf5afd756f3c"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03251fa5b85a9ada12787234e0ceb3dcc5bd58a49c15ac0749a4238f3bca6d9a1d"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("e2767d788d1c5620f3ef21d57f2d64559ab203c044f0a5f0730b21984e77019c"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("36f3ede761aa683813013ffa84e3738b870ce7605e0a958ed4ffb540cd3ea504"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("66d1945ceb6ef8014b1b6703cb624f058913e722f15d03225be27cb9d8aabe4a"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03975043476a76b72b093d684b8a0979d8b246c2f99f16f95760d6d3490c2e37a1"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("3fcb80eb1d5b91c491408447ac4e221fcb2254c861adbb5a178337c2750b0846"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("6bcb4819a96508efa7e32ee52b0227ccf5fbe5539687aae931677b24f6d0bbbd"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("22c7623bf0e850538329e3e6d9a6f9b1235350824a3feaad2580b7a853550deb"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("0262e2054c89ad173f741e413d12f511a2cf98783c43f18f8dbb6274bdd584a3dc"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("5577d4be25f1b44487140a626c8aeca2a77507a1fc4fd466dd3a82234abb6785"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("8bb257a1a17fd2233935b33441d216551d5ff1553d02e4013e03f14962615c16"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("a5eebe3469d68c8922a1a8b5a0a2b55293b7ff424240c16feb9f51727f734516"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("03d80474b8e6002793374a99d884605cf022d216573459b7deb19b6ccb110d286a"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("c07275582d0681eb07c7b51f0bca0c48c056d571b7b83d84980ab40ac7d7d720"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("d6b780983a63a3e4bcf643ee68b686421079c835a99eeba6962fe41bb355f8da"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("479ec3b589b14aa7290b48c2e64072e4e5b15ce395d2072a5a18b0a2cf35f3fd"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("0219d5b487ebdf719a994dcde094072e0227fc23e4cdbc4cce3b9d3e4a4ffe0668"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("f10e2b7675dfa557d9e3188469f12d3e953c2d46dce006cd177b6ae7f465cfc0"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("39c5f108e7017e085fe90acfd719420740e57768ac14c94cb020d87e36d06752"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("63952334b731ec91d88c54614925576f82e3610d009657368fc866e7b1efbe73"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02b58d9eb9595c24438a6ae4a4be4a408c0cd7a3017c3780cba253171cc9e62627"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("0bcbebb39d8fe1cb3eab952c6f701656c234e462b945e2f7d4be2c80b8f2d974"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("79f654976732106c0e4a97ab3b6d16f343a05ebfcc2e1d679d69d396e6162a77"), SHA256_DIGEST_LENGTH);

    memcpy(seed, fromhex("256472ee754ef6af096340ab1e161f58e85fb0cc7ae6e6866b9359a1657fa6c1"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02dac6b246a06ac7c38a63f4f10b1344a8cd6f920a8fd74523bd2f5d4a9a3055b2"), SKYCOIN_PUBKEY_LEN);
    ck_assert_mem_eq(seckey, fromhex("88ba6f6c66fc0ef01c938569c2dd1f05475cb56444f4582d06828e77d54ffbe6"), SKYCOIN_SECKEY_LEN);
    ck_assert_mem_eq(next_seed, fromhex("387883b86e2acc153aa334518cea48c0c481b573ccaacf17c575623c392f78b2"), SHA256_DIGEST_LENGTH);

    // Skycoin core test vector 1 from TestDeterministicKeyPairIterator2
    memcpy(seed, fromhex("67c53b28b8c7b06be53b490c28c0a3b77724b5c31c4bf12b71cd44c6bb4586f3"), SHA256_DIGEST_LENGTH);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    ck_assert_mem_eq(pubkey, fromhex("02c32556c48bfe944e4b8f6ecb6c884112c71a468247d338cbbdc9c561ab7c6d3d"), 33);
    ck_assert_mem_eq(seckey, fromhex("68c751a58f48d656e4d3ec31f6c1016e6e36583ac2f63129f576b29e764469b5"), 32);

    // Skycoin core test vector 2 from TestDeterministicKeyPairIterator2
    memcpy(seed, fromhex("38363534613332666131323062666462376361303263343837343639303730656261346235613831623033373633613231383566646635616664373536663363"), 64);
    memset(pubkey, 0, sizeof(pubkey));
    memset(seckey, 0, sizeof(seckey));
    ret = deterministic_key_pair_iterator((const uint8_t*)seed, 64, next_seed, seckey, pubkey);
    ck_assert_int_eq(ret, 0);
    memcpy(seed, next_seed, 32);
    for (int i = 1; i<1024; i++) {
        ret = deterministic_key_pair_iterator((const uint8_t*)seed, 32, next_seed, seckey, pubkey);
        ck_assert_int_eq(ret, 0);
        memcpy(seed, next_seed, 32);
    }
    ck_assert_mem_eq(pubkey, fromhex("0249964ac7e3fe1b2c182a2f10abe031784e374cc0c665a63bc76cc009a05bc7c6"), 33);
    ck_assert_mem_eq(seckey, fromhex("10ba0325f1b8633ca463542950b5cd5f97753a9829ba23477c584e7aee9cfbd5"), 32);
}
END_TEST

START_TEST(test_skycoin_address_from_pubkey)
{
    uint8_t pubkey[33] = {0};
    char address[256] = {0};
    size_t size_address = sizeof(address);
    memcpy(pubkey, fromhex("02e5be89fa161bf6b0bc64ec9ec7fe27311fbb78949c3ef9739d4c73a84920d6e1"), 33);
    int ok = skycoin_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_int_eq(ok, 1);
    ck_assert_str_eq(address, "2EVNa4CK9SKosT4j1GEn8SuuUUEAXaHAMbM");

    memcpy(pubkey, fromhex("030e40dda21c27126d829b6ae57816e1440dcb2cc73e37e860af26eff1ec55ed73"), 33);
    ok = skycoin_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_int_eq(ok, 1);
    ck_assert_str_eq(address, "2EKq1QXRmfe7jsWzNdYsmyoz8q3VkwkLsDJ");

    memcpy(pubkey, fromhex("035843e72258696b391cf1d898fc65f31e66876ea0c9e101f8ddc3ebb4b87dc5b0"), 33);
    ok = skycoin_address_from_pubkey(pubkey, address, &size_address);
    ck_assert_int_eq(ok, 1);
    ck_assert_str_eq(address, "5UgkXRHrf5XRk41BFq1DVyeFZHTQXirhUu");
}
END_TEST

START_TEST(test_bitcoin_address_from_pubkey){
  uint8_t pubkey[33] = {0};
  char address[256] = {0};
  size_t size_address = sizeof(address);
  memcpy(pubkey, fromhex("038aca63fe6fb5eeccba919a5559aecadb8aca54b270c57c4498303b19e9829801"), 33);
  int ok = bitcoin_address_from_pubkey(pubkey, address, &size_address);
  ck_assert_int_eq(ok, 1);
  ck_assert_str_eq(address, "1NnKKCBPyeFvoEmJXDKg8q8RZpGSQXLVEd");

  memcpy(pubkey, fromhex("036e6fddfe21559034c317558c52856369ad42a1617eb39c52f324cd64be193561"), 33);
  ok = bitcoin_address_from_pubkey(pubkey, address, &size_address);
  ck_assert_int_eq(ok, 1);
  ck_assert_str_eq(address, "1PgTd8MbDzFv5CNgQpn2acZEhFk55trNjo");

  memcpy(pubkey, fromhex("037f695fe06102d2ff951bdfe7e9d1e7b6cee08f655b60cfa85c941c455a1e6c31"), 33);
  ok = bitcoin_address_from_pubkey(pubkey, address, &size_address);
  ck_assert_int_eq(ok, 1);
  ck_assert_str_eq(address, "1C6DVX1v1eLsiAbQMSYeS54TZxoVvLVziM");
}
END_TEST

START_TEST(test_compute_sha256sum)
{
    char seed[256] = "seed";
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    sha256sum((const uint8_t*)seed, digest, strlen(seed));

    ck_assert_mem_eq(digest, fromhex("19b25856e1c150ca834cffc8b59b23adbd0ec0389e58eb22b3b64768098d002b"), SHA256_DIGEST_LENGTH);

    strcpy(seed, "random_seed");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    sha256sum((const uint8_t*)seed, digest, strlen(seed));

    ck_assert_mem_eq(digest, fromhex("7b491face15c5be43df3affe42e6e4aab48522a3b564043de464e8de50184a5d"), SHA256_DIGEST_LENGTH);


    strcpy(seed, "024f7fd15da6c7fc7d0410d184073ef702104f82452da9b3e3792db01a8b7907c3");
    memset(digest, 0, SHA256_DIGEST_LENGTH);
    sha256sum((const uint8_t*)seed, digest, strlen(seed));

    ck_assert_mem_eq(digest, fromhex("a5daa8c9d03a9ec500088bdf0123a9d865725b03895b1291f25500737298e0a9"), SHA256_DIGEST_LENGTH);
}
END_TEST


START_TEST(test_skycoin_ecdsa_verify_digest_recover)
{
    int res;
    uint8_t message[SHA256_DIGEST_LENGTH] = "Hello World!";
    uint8_t signature[SKYCOIN_SIG_LEN];
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN];

    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("864c6abf85214be99fed3dc37591a74282f566fb52fb56ab21dabc0d120f29b848ffeb52a7843a49c411753c0edc12c0dedf6313266722bee982a0d3b384b62600"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("03b17c7b7c564385be66f9c1b9da6a0b5aea56f0cb70548e6528a2f4f7b27245d8"), SKYCOIN_PUBKEY_LEN);

    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("631182b9722489eedd1a9eab36bf776c3e679aa2b1bd3fb346db0f776b982be25bdd33d4e893aca619eff3013e087307d22ca30644c96ea0fbdef06396d1bf9600"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("039f12c93645e35e5274dc38f191be0b6d1321ec35d2d2a3ddf7d13ed12f6da85b"), SKYCOIN_PUBKEY_LEN);

    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("d2a8ec2b29ce3cf3e6048296188adff4b5dfcb337c1d1157f28654e445bb940b4e47d6b0c7ba43d072bf8618775f123a435e8d1a150cb39bbb1aa80da8c57ea100"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("03338ffc0ff42df07d27b0b4131cd96ffdfa4685b5566aafc7aa71ed10fd1cbd6f"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector: TestSigRecover2 1
    memcpy(message, fromhex("016b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("d2a8ec2b29ce3cf3e6048296188adff4b5dfcb337c1d1157f28654e445bb940b4e47d6b0c7ba43d072bf8618775f123a435e8d1a150cb39bbb1aa80da8c57ea100"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("03c0b0e24d55255f7aefe3da7a947a63028b573f45356a9c22e9a3c103fd00c3d1"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector: TestSigRecover2 2
    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("d2a8ec2b20ce3cf3e6048296188adff4b5dfcb337c1d1157f28654e445bb940b4e47d6b0c7ba43d072bf8618775f123a435e8d1a150cb39bbb1aa80da8c57ea100"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("03cee91b6d329e00c344ad5d67cfd00d885ec36e8975b5d9097738939cb8c08b31"), SKYCOIN_PUBKEY_LEN);

    // Skycoin core test vector: TestSigRecover2 3
    memcpy(message, fromhex("176b81623cf98f45879f3a48fa34af77dde44b2ffa0ddd2bf9edb386f76ec0ef"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("d201ec2b29ce3cf3e6048296188adff4b5dfcb337c1d1157f28654e445bb940b4e47d6b0c7ba43d072bf8618775f123a435e8d1a150cb39bbb1aa80da8c57ea100"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 1);

    // Skycoin core test vectors from TestSigSignRecover
    memcpy(message, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179804641a7472bb90647fa60b4d30aef8c7279e4b68226f7b2713dab712ef122f8b01"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    memcpy(message, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("ee38f27be5f3c4b8db875c0ffbc0232e93f622d16ede888508a4920ab51c3c9906ea7426c5e251e4bea76f06f554fa7798a49b7968b400fa981c51531a5748d801"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    memcpy(message, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("d4d869ad39cb3a64fa1980b47d1f19bd568430d3f929e01c00f1e5b7c6840ba85e08d5781986ee72d1e8ebd4dd050386a64eee0256005626d2acbe3aefee9e2500"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    memcpy(message, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(signature, fromhex("eeee743d79b40aaa52d9eeb48791b0ae81a2f425bf99cdbc84180e8ed429300d457e8d669dbff1716b123552baf6f6f0ef67f16c1d9ccd44e6785d424002212601"), SKYCOIN_SIG_LEN);
    res = skycoin_ecdsa_verify_digest_recover(signature, message, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("0270b763664593c5f84dfb20d23ef79530fc317e5ee2ece0d9c50f432f62426ff9"), SKYCOIN_PUBKEY_LEN);
}
END_TEST

START_TEST(test_ecdsa_sign_digest_inner)
{
    // Tests ecdsa_sign_digest_inner against known test vectors from skycoin core
    int res;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t nonce[32];
    uint8_t seckey[SKYCOIN_SECKEY_LEN];
    uint8_t signature[SKYCOIN_SIG_LEN];
    bignum256 z, k;
    uint8_t recid;
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

    // Skycoin core test vector: TestSigForceLowS
    memcpy(seckey, fromhex("7A642C99F7719F57D8F4BEB11A303AFCD190243A51CED8782CA6D3DBE014D146"), sizeof(seckey));
    memcpy(digest, fromhex("DD72CBF2203C1A55A411EEC4404AF2AFB2FE942C434B23EFE46E9F04DA8433CA"), sizeof(digest));
    memcpy(nonce, fromhex("9F3CD9AB0F32911BFDE39AD155F527192CE5ED1F51447D63C4F154C118DA598E"), sizeof(nonce));

    bn_read_be(digest, &z);
    bn_read_be(nonce, &k);
    res = ecdsa_sign_digest_inner(curve->params, seckey, &z, &k, signature, &recid, NULL);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("8c20a668be1b5a910205de46095023fe4823a3757f4417114168925f28193bff520ce833da9313d726f2a4d481e3195a5dd8e935a6c7f4dc260ed4c66ebe6da7"), 64);
    ck_assert_int_eq(recid, 0);

    // Skycoin core test vector: TestSigSign
    memcpy(seckey, fromhex("73641C99F7719F57D8F4BEB11A303AFCD190243A51CED8782CA6D3DBE014D146"), sizeof(seckey));
    memcpy(digest, fromhex("D474CBF2203C1A55A411EEC4404AF2AFB2FE942C434B23EFE46E9F04DA8433CA"), sizeof(digest));
    memcpy(nonce, fromhex("9E3CD9AB0F32911BFDE39AD155F527192CE5ED1F51447D63C4F154C118DA598E"), sizeof(nonce));

    bn_read_be(digest, &z);
    bn_read_be(nonce, &k);
    res = ecdsa_sign_digest_inner(curve->params, seckey, &z, &k,  signature, &recid, NULL);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("98f9d784ba6c5c77bb7323d044c0fc9f2b27baa0a5b0718fe88596cc566819801ca662aaefd6cc958ba4604fea999db133a75bf34c13334dabac7124ff0cfcc1"), 64);
    ck_assert_int_eq(recid, 0);

    bignum256 sigr, sigs;
    bn_read_be(signature, &sigr);
    bn_read_be(&signature[32], &sigs);

    bignum256 refr, refs;
    uint8_t refrb[32];
    uint8_t refsb[32];
    memcpy(refrb, fromhex("98f9d784ba6c5c77bb7323d044c0fc9f2b27baa0a5b0718fe88596cc56681980"), sizeof(refrb));
    memcpy(refsb, fromhex("1ca662aaefd6cc958ba4604fea999db133a75bf34c13334dabac7124ff0cfcc1"), sizeof(refsb));
    bn_read_be(refrb, &refr);
    bn_read_be(refsb, &refs);

    res = bn_is_equal(&sigr, &refr);
    ck_assert_int_eq(res, 1);
    res = bn_is_equal(&sigs, &refs);
    ck_assert_int_eq(res, 1);
}
END_TEST

START_TEST(test_sign_recover)
{
    int res;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    uint8_t nonce[32];
    uint8_t seckey[SKYCOIN_SECKEY_LEN];
    uint8_t signature[SKYCOIN_SIG_LEN];
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN];
    bignum256 z, k;
    uint8_t recid = -1;
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

    // Skycoin core test vectors from TestSigSignRecover
    recid = -1;
    memset(nonce, 0, sizeof(nonce));
    memcpy(seckey, fromhex("597e27368656cab3c82bfcf2fb074cefd8b6101781a27709ba1b326b738d2c5a"), sizeof(seckey));
    memcpy(digest, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(nonce, fromhex("0000000000000000000000000000000000000000000000000000000000000001"), 32);

    bn_read_be(digest, &z);
    bn_read_be(nonce, &k);
    res = ecdsa_sign_digest_inner(curve->params, seckey, &z, &k, signature, &recid, NULL);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179804641a7472bb90647fa60b4d30aef8c7279e4b68226f7b2713dab712ef122f8b"), 64);
    ck_assert_int_eq(recid, 1);

    signature[64] = recid;
    res = skycoin_ecdsa_verify_digest_recover(signature, digest, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    recid = -1;
    memset(nonce, 0, sizeof(nonce));
    memcpy(seckey, fromhex("597e27368656cab3c82bfcf2fb074cefd8b6101781a27709ba1b326b738d2c5a"), sizeof(seckey));
    memcpy(digest, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(nonce, fromhex("000000000000000000000000000000000000000000000000000000000000fe25"), 32);
    bn_read_be(digest, &z);
    bn_read_be(nonce, &k);
    res = ecdsa_sign_digest_inner(curve->params, seckey, &z, &k, signature, &recid, NULL);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("ee38f27be5f3c4b8db875c0ffbc0232e93f622d16ede888508a4920ab51c3c9906ea7426c5e251e4bea76f06f554fa7798a49b7968b400fa981c51531a5748d8"), 64);
    ck_assert_int_eq(recid, 1);

    signature[64] = recid;
    res = skycoin_ecdsa_verify_digest_recover(signature, digest, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    recid = -1;
    memset(nonce, 0, sizeof(nonce));
    memcpy(seckey, fromhex("597e27368656cab3c82bfcf2fb074cefd8b6101781a27709ba1b326b738d2c5a"), sizeof(seckey));
    memcpy(digest, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(nonce, fromhex("00000000000000000000000000000000000000000000000000000000fe250100"), 32);
    bn_read_be(digest, &z);
    bn_read_be(nonce, &k);
    res = ecdsa_sign_digest_inner(curve->params, seckey, &z, &k, signature, &recid, NULL);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("d4d869ad39cb3a64fa1980b47d1f19bd568430d3f929e01c00f1e5b7c6840ba85e08d5781986ee72d1e8ebd4dd050386a64eee0256005626d2acbe3aefee9e25"), 64);
    ck_assert_int_eq(recid, 0);

    signature[64] = recid;
    res = skycoin_ecdsa_verify_digest_recover(signature, digest, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132c7"), SKYCOIN_PUBKEY_LEN);

    recid = -1;
    memset(nonce, 0, sizeof(nonce));
    memcpy(seckey, fromhex("67a331669081d22624f16512ea61e1d44cb3f26af3333973d17e0e8d03733b78"), sizeof(seckey));
    memcpy(digest, fromhex("001aa9e416aff5f3a3c7f9ae0811757cf54f393d50df861f5c33747954341aa7"), SHA256_DIGEST_LENGTH);
    memcpy(nonce, fromhex("000000000000000000000000000000000000000000000000000000001e2501ac"), 32);
    bn_read_be(digest, &z);
    bn_read_be(nonce, &k);
    res = ecdsa_sign_digest_inner(curve->params, seckey, &z, &k, signature, &recid, NULL);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(signature, fromhex("eeee743d79b40aaa52d9eeb48791b0ae81a2f425bf99cdbc84180e8ed429300d457e8d669dbff1716b123552baf6f6f0ef67f16c1d9ccd44e6785d4240022126"), 64);
    ck_assert_int_eq(recid, 1);

    signature[64] = recid;
    res = skycoin_ecdsa_verify_digest_recover(signature, digest, pubkey);
    ck_assert_int_eq(res, 0);
    ck_assert_mem_eq(pubkey, fromhex("0270b763664593c5f84dfb20d23ef79530fc317e5ee2ece0d9c50f432f62426ff9"), SKYCOIN_PUBKEY_LEN);
}
END_TEST


START_TEST(test_checkdigest)
{
    ck_assert(is_sha256_digest_hex("02df09821cff4874198a1dbdc462d224bd99728eeed024185879225762376132"));
    ck_assert(!is_sha256_digest_hex("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761"));    // too short
    ck_assert(!is_sha256_digest_hex("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761256")); // too long
    ck_assert(!is_sha256_digest_hex("02df09821cff4874198a1dbdc462d224bd99728eeed0241858792257623761r"));   // non hex digits
}
END_TEST


START_TEST(test_ecdh)
{
    // Skycoin core test vectors from TestAbnormalKeys3
    uint8_t pubkeys[4 * SKYCOIN_PUBKEY_LEN];
    uint8_t seckeys[4 * SKYCOIN_SECKEY_LEN];
    uint8_t ecdhkeys[4 * 4 * SKYCOIN_PUBKEY_LEN];

    // vector 1
    memcpy(seckeys, fromhex("08efb79385c9a8b0d1c6f5f6511be0c6f6c2902963d874a3a4bacc18802528d3"), SKYCOIN_SECKEY_LEN);
    memcpy(pubkeys, fromhex("03c74332d6094b1f603d4902fc6b1aa09fb3ef81f3015a4000cc0077ff70543c16"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 0 + 1), fromhex("02e72655a3adf8308a078ee6fe948cf6baf95ef626b1e1fe6e434c737c7c2fef4e"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 0 + 2), fromhex("03222fe59be5a69c38364dd313bd077b8b1c2216804a4a727e0078b3c77778bc45"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 0 + 3), fromhex("021096aa98231eaa949542be029a1f3a93815e05e243c69e73d7449d719ff5d76d"), SKYCOIN_PUBKEY_LEN);

    // vector 2
    memcpy(seckeys + SKYCOIN_SECKEY_LEN, fromhex("78298d9ecdc0640c9ae6883201a53f4518055442642024d23c45858f45d0c3e6"), SKYCOIN_SECKEY_LEN);
    memcpy(pubkeys + SKYCOIN_PUBKEY_LEN, fromhex("02fa3e6e0b1fb76e26dffe7b1e01fd02677fedfed23a59000092c706b04214bee3"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 1 + 0), fromhex("02e72655a3adf8308a078ee6fe948cf6baf95ef626b1e1fe6e434c737c7c2fef4e"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 1 + 2), fromhex("025617125b44ded369deed72f833535d56a3ed035afc44ff64fb7c65986f6ea2a5"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 1 + 3), fromhex("03849b3f906180cf27c161045e9da551a44476b0d4f7f29d668ba17569953d0a11"), SKYCOIN_PUBKEY_LEN);

    // vector 3
    memcpy(seckeys + SKYCOIN_SECKEY_LEN * 2, fromhex("04e04fe65bfa6ded50a12769a3bd83d7351b2dbff08c9bac14662b23a3294b9e"), SKYCOIN_SECKEY_LEN);
    memcpy(pubkeys + SKYCOIN_PUBKEY_LEN * 2, fromhex("034f25c9400dd0f87a9c420b35b5a157d21caa086ef8fa00015bc3c8ab73a1cc4c"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 2 + 0), fromhex("03222fe59be5a69c38364dd313bd077b8b1c2216804a4a727e0078b3c77778bc45"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 2 + 1), fromhex("025617125b44ded369deed72f833535d56a3ed035afc44ff64fb7c65986f6ea2a5"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 2 + 3), fromhex("03fd41f8d279e2df640f17aef31c258a0a9aa6ddcaf4c4bc80f71dccff576b630c"), SKYCOIN_PUBKEY_LEN);

    // vector 3
    memcpy(seckeys + SKYCOIN_SECKEY_LEN * 3, fromhex("2f5141f1b75747996c5de77c911dae062d16ae48799052c04ead20ccd5afa113"), SKYCOIN_SECKEY_LEN);
    memcpy(pubkeys + SKYCOIN_PUBKEY_LEN * 3, fromhex("03fe58baefc491a9dcf0939ab6252f81f6d9515105bd89c000bb7f2a694e8a8b72"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 3 + 0), fromhex("021096aa98231eaa949542be029a1f3a93815e05e243c69e73d7449d719ff5d76d"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 3 + 1), fromhex("03849b3f906180cf27c161045e9da551a44476b0d4f7f29d668ba17569953d0a11"), SKYCOIN_PUBKEY_LEN);
    memcpy(ecdhkeys + SKYCOIN_PUBKEY_LEN * (4 * 3 + 2), fromhex("03fd41f8d279e2df640f17aef31c258a0a9aa6ddcaf4c4bc80f71dccff576b630c"), SKYCOIN_PUBKEY_LEN);

    int i, j, ret, offset;
    uint8_t pubkeya[SKYCOIN_PUBKEY_LEN];
    uint8_t pubkeyb[SKYCOIN_PUBKEY_LEN];
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            if (i == j) {
                continue;
            }

            memset(pubkeya, 0, SKYCOIN_PUBKEY_LEN);
            memset(pubkeyb, 0, SKYCOIN_PUBKEY_LEN);
            ret = ecdh(pubkeys + SKYCOIN_PUBKEY_LEN * i, seckeys + SKYCOIN_SECKEY_LEN * j, pubkeya);
            ck_assert_int_eq(ret, 0);
            ret = ecdh(pubkeys + SKYCOIN_PUBKEY_LEN * j, seckeys + SKYCOIN_SECKEY_LEN * i, pubkeyb);
            ck_assert_int_eq(ret, 0);
            offset = SKYCOIN_PUBKEY_LEN * ((4 * i) + j);
            ck_assert_mem_eq(ecdhkeys + (offset), pubkeya, SKYCOIN_PUBKEY_LEN);
            ck_assert_mem_eq(pubkeya, pubkeyb, SKYCOIN_PUBKEY_LEN);
        }
    }
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
    tcase_add_test(tc, test_skycoin_pubkey_from_seckey);
    tcase_add_test(tc, test_secp256k1Hash);
    tcase_add_test(tc, test_deterministic_key_pair_iterator);
    tcase_add_test(tc, test_skycoin_address_from_pubkey);
    tcase_add_test(tc, test_bitcoin_address_from_pubkey);
    tcase_add_test(tc, test_compute_sha256sum);
    tcase_add_test(tc, test_skycoin_ecdsa_verify_digest_recover);
    tcase_add_test(tc, test_base58_decode);
    tcase_add_test(tc, test_ecdsa_sign_digest_inner);
    tcase_add_test(tc, test_sign_recover);
    tcase_add_test(tc, test_checkdigest);
    tcase_add_test(tc, test_addtransactioninput);
    tcase_add_test(tc, test_ecdh);
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
