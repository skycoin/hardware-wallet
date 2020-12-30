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

/**
 * Test cases : BitcoinAddresses
 */

 static void fill_txids(BitcoinTransactionInput inputs[], char* txids[], int txids_n){
  uint8_t hex_raw_tx[32] = {0};
  for(int iter = 0; iter < txids_n; iter++){
    tobuff(txids[iter], hex_raw_tx, 32);
    memcpy(inputs[iter].prev_hash.bytes, hex_raw_tx, 32);
    memset(hex_raw_tx, 0, 32);
  }
}


START_TEST(test_BitcoinTransactionMoreInputsThanOutputs){
  SetMnemonic mnemonic = SetMnemonic_init_zero;
  char mnemonic_str[] = {"network hurdle trash obvious soccer sunset side merit horn author horn you"};
  memcpy(mnemonic.mnemonic, mnemonic_str, sizeof(mnemonic_str));
  ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

  SignTx sign_tx = SignTx_init_default;
  sign_tx.outputs_count = 2;
  sign_tx.inputs_count = 3;
  sign_tx.has_coin_name = true;
  strcpy((char *) sign_tx.coin_name, "Bitcoin");
  sign_tx.has_version = true;
  sign_tx.version = 1;
  sign_tx.has_lock_time = true;
  sign_tx.lock_time = 0;
  TxRequest response = TxRequest_init_default;
  ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
  ck_assert_int_eq(response.request_type, TxRequest_RequestType_TXINPUT);
  ck_assert_int_eq(response.has_details, true);
  ck_assert_int_eq(response.details.request_index, 1);

  BitcoinTxAck tx_ack = BitcoinTxAck_init_default;

  char *txids[] = {
    "dec6c7e07b66e88053a721dba3e5a379766ba7dd11f654b53dd6b2b28d37c4",
    "dec6c7e07b66e88053a721dba3e5a379766ba7dd11f654b53dd6b2b28d37c4",
    "dec6c7e07b66e88053a721dba3e5a379766ba7dd11f654b53dd6b2b28d37c4"
  };

  BitcoinTransactionInput inputs1[] = {
    {.address_n = 1,
     .index = 1,
     .value = 100000},
    {.address_n = 1,
     .index = 2,
     .value = 100000},
    {.address_n = 1,
     .index = 3,
     .value = 100000}
   };

   fill_txids(inputs1, txids, 3);

  BitcoinTransactionOutput outputs1[] = {
    {
      .address = "mvQrmmzFroQS9Z6vZ8J4YGBjGWuACbiQ72",
      .coin = 80000
    },
    {
      .address = "mhQftxKfYHD22MVFheUyRtoMq3RAjNcXuy",
      .coin = 10000
    }
  };

  memcpy(tx_ack.tx.inputs, inputs1, sizeof(inputs1));
  memcpy(tx_ack.tx.outputs, outputs1, sizeof(outputs1));
  ck_assert_int_eq(msgBitcoinTxAckImpl(&tx_ack, &response), ErrInvalidArg);
}
END_TEST


START_TEST(test_BitcoinTransactionChangeMnemonic){
  SetMnemonic mnemonic = SetMnemonic_init_zero;
  char mnemonic_str[] = {"network hurdle trash obvious soccer sunset side merit horn author horn you"};
  memcpy(mnemonic.mnemonic, mnemonic_str, sizeof(mnemonic_str));
  ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

  SignTx sign_tx = SignTx_init_default;
  sign_tx.outputs_count = 2;
  sign_tx.inputs_count = 1;
  sign_tx.has_coin_name = true;
  strcpy((char *) sign_tx.coin_name, "Bitcoin");
  sign_tx.has_version = true;
  sign_tx.version = 1;
  sign_tx.has_lock_time = true;
  sign_tx.lock_time = 0;
  TxRequest response = TxRequest_init_default;
  ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
  ck_assert_int_eq(response.request_type, TxRequest_RequestType_TXINPUT);
  ck_assert_int_eq(response.has_details, true);
  ck_assert_int_eq(response.details.request_index, 1);

  char nemonic_str[] = {"all all all all all all all all all all all all"};
  memcpy(mnemonic.mnemonic, nemonic_str, sizeof(nemonic_str));
  ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

  BitcoinTxAck tx_ack = BitcoinTxAck_init_default;

  BitcoinTransactionInput inputs1[] = {
    {.address_n = 1,
     .index = 1,
     .value = 31000000}
   };

   uint8_t hex_txid[32] = {0};
   tobuff("e5040e1bc1ae7667ffb9e5248e90b2fb93cd9150234151ce90e14ab2f5933bcd", hex_txid, 32);

   memcpy(inputs1[0].prev_hash.bytes, hex_txid, 32);

   BitcoinTransactionOutput outputs1[] = {
     {
       .address = "msj42CCGruhRsFrGATiUuh25dtxYtnpbTx",
       .coin = 30090000
     },
     {
       .address = "mm6kLYbGEL1tGe4ZA8xacfgRPdW1NLjCbZ",
       .coin = 900000
     }
   };

   memcpy(tx_ack.tx.outputs, outputs1, sizeof(outputs1));
   tx_ack.tx.outputs_cnt = 2;
   tx_ack.tx.inputs_cnt = 0;
   ck_assert_int_eq(msgBitcoinTxAckImpl(&tx_ack, &response), ErrFailed);

}
END_TEST

START_TEST(test_BitcoinTransactionSignNoData){
  SetMnemonic mnemonic = SetMnemonic_init_zero;
  char mnemonic_str[] = {"network hurdle trash obvious soccer sunset side merit horn author horn you"};
  memcpy(mnemonic.mnemonic, mnemonic_str, sizeof(mnemonic_str));
  ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

  SignTx sign_tx = SignTx_init_default;
  sign_tx.outputs_count = 14;
  sign_tx.inputs_count = 14;
  sign_tx.has_coin_name = true;
  strcpy((char *) sign_tx.coin_name, "Bitcoin");
  sign_tx.has_version = true;
  sign_tx.version = 1;
  sign_tx.has_lock_time = true;
  sign_tx.lock_time = 0;
  TxRequest response = TxRequest_init_default;
  ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
  ck_assert_int_eq(response.request_type, TxRequest_RequestType_TXINPUT);
  ck_assert_int_eq(response.has_details, true);
  ck_assert_int_eq(response.details.request_index, 1);

  sign_tx.outputs_count = 14;
  sign_tx.inputs_count = 14;
  sign_tx.has_coin_name = true;
  strcpy(sign_tx.coin_name, "Bitcoin");
  sign_tx.has_version = true;
  sign_tx.version = 1;
  sign_tx.has_lock_time = true;
  sign_tx.lock_time = 3;
  sign_tx.has_tx_hash = false;

  ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrFailed);

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
  tcase_add_test(tc, test_BitcoinTransactionMoreInputsThanOutputs);
  tcase_add_test(tc, test_BitcoinTransactionChangeMnemonic);
  tcase_add_test(tc, test_BitcoinTransactionSignNoData);
  return tc;
}
