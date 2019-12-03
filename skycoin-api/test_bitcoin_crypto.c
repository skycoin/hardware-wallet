#include <stdio.h>
#include <string.h>

#include <check.h>

#include "check_digest.h"
#include "tools/curves.h"
#include "skycoin_constants.h"
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

Suite* test_suite(void)
{
    Suite* s = suite_create("bitcoin_crypto");
    TCase* tc;

    tc = tcase_create("checksums");
    tcase_add_test(tc, test_bitcoin_address_from_pubkey);
    suite_add_tcase(s, tc);

    return s;
}

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
