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
#include "test_fsm_bitcoin.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <check.h>
#include <pb_decode.h>
#include <pb_encode.h>

#include "skycoin-crypto/tools/base58.h"
#include "skycoin-crypto/tools/bip32.h"
#include "skycoin-crypto/tools/bip39.h"
#include "skycoin-crypto/check_digest.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/firmware/error.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/fsm_bitcoin_impl.h"
#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/gettext.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/memory.h"
#include "tiny-firmware/firmware/messages.h"
#include "tiny-firmware/oled.h"
#include "tiny-firmware/firmware/pinmatrix.h"
#include "tiny-firmware/firmware/protect.h"
#include "messages.pb.h"
#include "bitcoin_messages.pb.h"
#include "skycoin-crypto/tools/rand.h"
#include "tiny-firmware/firmware/recovery.h"
#include "tiny-firmware/firmware/reset.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/setup.h"
#include "skycoin-crypto/skycoin_crypto.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/tests/test_many_address_golden.h"
#include "tiny-firmware/tests/test_fsm.h"
#include "tiny-firmware/usb.h"
#include "tiny-firmware/util.h"
#include <inttypes.h>
#include <stdio.h>

#include "test_pin.h"

static uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void setup_tc_fsm_bitcoin(void)
{
    srand(time(NULL));
    setup();
}

void teardown_tc_fsm_bitcoin(void)
{
}

/**
 * Test cases : SkycoinAddresses
 */

START_TEST(test_msgBitcoinAddressesAll)
        {
                SetMnemonic msgSeed = SetMnemonic_init_zero;
                printf("Starting all address test\n");
        BitcoinAddress msgAddr = SkycoinAddress_init_zero;
        RESP_INIT(ResponseSkycoinAddress);
        printf("Response initialized\n");

        strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
        ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

        msgAddr.address_n = 99;
        msgAddr.has_start_index = false;
        msgAddr.has_confirm_address = false;
        printf("Starting getting addresses\n");
        ck_assert_int_eq(msgBitcoinAddressImpl(&msgAddr, resp), ErrOk);
        ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
        int i;
        char test_msg[256];
        printf("Starting iterating\n");
        for (i = 0; i < resp->addresses_count; ++i) {
            sprintf(test_msg, "Check %d-th address , expected %s got %s", i, TEST_MANY_BTC_ADDRESSES[i], resp->addresses[i]);
            ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_BTC_ADDRESSES[i]) == 0, test_msg);
        }
        printf("Ending tests\n");
        }
END_TEST

START_TEST(test_msgBitcoinAddressesStartIndex)
{
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    BitcoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    msgAddr.has_start_index = true;
    msgAddr.start_index = random32() % 100;
    msgAddr.address_n = random32() % (100 - msgAddr.start_index) + 1;
    ck_assert_uint_ge(msgAddr.address_n, 1);
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgBitcoinAddressImpl(&msgAddr, resp), ErrOk);
    ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
    int i, index;
    char test_msg[256];
    for (i = 0, index = msgAddr.start_index; i < resp->addresses_count; ++i, ++index) {
        sprintf(test_msg, "Check %d-th address , expected %s got %s", index, TEST_MANY_BTC_ADDRESSES[index], resp->addresses[i]);
        ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_BTC_ADDRESSES[index]) == 0, test_msg);
    }
}
END_TEST

void setBitcoinPassphrase(char *passphrase) {
    ApplySettings msg = ApplySettings_init_zero;
    msg.has_use_passphrase = true;
    msg.use_passphrase = true;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    session_cachePassphrase(passphrase);
}

START_TEST(test_msgBitcoinAddressesAllEmptyPassphrase)
        {
                storage_wipe();
        SetMnemonic msgSeed = SetMnemonic_init_zero;
        BitcoinAddress msgAddr = SkycoinAddress_init_zero;
        RESP_INIT(ResponseSkycoinAddress);

        strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
        ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

        setBitcoinPassphrase("");

        msgAddr.address_n = 99;
        msgAddr.has_start_index = false;
        msgAddr.has_confirm_address = false;

        ck_assert_int_eq(msgBitcoinAddressImpl(&msgAddr, resp), ErrOk);
        ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
        int i;
        char test_msg[256];
        for (i = 0; i < resp->addresses_count; ++i) {
            sprintf(test_msg, "Check %d-th address , expected %s got %s", i, TEST_MANY_BTC_ADDRESSES[i], resp->addresses[i]);
            ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_BTC_ADDRESSES[i]) == 0, test_msg);
        }
        }
END_TEST

START_TEST(test_msgBitcoinAddressesStartIndexEmptyPassphrase)
{
    storage_wipe();
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    BitcoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    setBitcoinPassphrase("");

    msgAddr.has_start_index = true;
    msgAddr.start_index = random32() % 99;
    msgAddr.address_n = random32() % (99 - msgAddr.start_index) + 1;
    ck_assert_uint_ge(msgAddr.address_n, 1);
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgBitcoinAddressImpl(&msgAddr, resp), ErrOk);
    ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
    int i, index;
    char test_msg[256];
    for (i = 0, index = msgAddr.start_index; i < resp->addresses_count; ++i, ++index) {
        sprintf(test_msg, "Check %d-th address , expected %s got %s", index, TEST_MANY_BTC_ADDRESSES[index], resp->addresses[i]);
        ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_BTC_ADDRESSES[index]) == 0, test_msg);
    }
}
END_TEST

START_TEST(test_msgBitcoinAddressesTooMany)
{
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    BitcoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    msgAddr.has_start_index = false;
    msgAddr.address_n = 100;
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgBitcoinAddressImpl(&msgAddr, resp), ErrTooManyAddresses);
}
END_TEST

START_TEST(test_msgBitcoinAddressesFailWithoutMnemonic)
{
    BitcoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    storage_wipe();

    msgAddr.has_start_index = true;
    msgAddr.start_index = random32() % 100;
    msgAddr.address_n = random32() % (100 - msgAddr.start_index) + 1;
    ck_assert_uint_ge(msgAddr.address_n, 1);
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgBitcoinAddressImpl(&msgAddr, resp), ErrMnemonicRequired);
}
END_TEST


TCase* add_fsm_bitcoin_tests(TCase* tc)
{
  tcase_add_checked_fixture(tc, setup_tc_fsm_bitcoin, teardown_tc_fsm_bitcoin);
  tcase_add_test(tc, test_msgBitcoinAddressesAll);
  tcase_add_test(tc, test_msgBitcoinAddressesStartIndex);
  tcase_add_test(tc, test_msgBitcoinAddressesAllEmptyPassphrase);
  tcase_add_test(tc, test_msgBitcoinAddressesStartIndexEmptyPassphrase);
  tcase_add_test(tc, test_msgBitcoinAddressesTooMany);
  tcase_add_test(tc, test_msgBitcoinAddressesFailWithoutMnemonic);
  return tc;
}
