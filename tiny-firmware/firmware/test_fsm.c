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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <check.h>
#include <pb_decode.h>
#include <pb_encode.h>

#include "tools/base58.h"
#include "tools/bip32.h"
#include "tools/bip39.h"
#include "check_digest.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/entropy.h"
#include "error.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/gettext.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/memory.h"
#include "tiny-firmware/firmware/messages.h"
#include "tiny-firmware/oled.h"
#include "tiny-firmware/firmware/pinmatrix.h"
#include "tiny-firmware/firmware/protect.h"
#include "messages.pb.h"
#include "tools/rand.h"
#include "tiny-firmware/firmware/recovery.h"
#include "tiny-firmware/firmware/reset.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/setup.h"
#include "skycoin_crypto.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/firmware/test_fsm.h"
#include "tiny-firmware/firmware/test_many_address_golden.h"
#include "tiny-firmware/firmware/usb.h"
#include "tiny-firmware/util.h"
#include <inttypes.h>
#include <stdio.h>

#include "test_pin.h"

static uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));
static uint32_t wcs[] = {MNEMONIC_WORD_COUNT_12, MNEMONIC_WORD_COUNT_24};

void setup_tc_fsm(void)
{
    srand(time(NULL));
    setup();
}

void teardown_tc_fsm(void)
{
}

void forceGenerateMnemonic(uint32_t wc)
{
    storage_wipe();
    GenerateMnemonic msg = GenerateMnemonic_init_zero;
    msg.word_count = wc;
    msg.has_word_count = true;
    ck_assert_int_eq(ErrOk, msgGenerateMnemonicImpl(&msg, &random_buffer));
}

bool is_base16_char(char c)
{
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
        return true;
    }
    return false;
}

/**
 * Test cases : GenerateMnemonic
 */

START_TEST(test_msgGenerateMnemonicImplOk)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        storage_wipe();
        GenerateMnemonic msg = GenerateMnemonic_init_zero;
        msg.word_count = wcs[wi];
        msg.has_word_count = true;
        ErrCode_t ret = msgGenerateMnemonicImpl(&msg, &random_buffer);
        ck_assert_int_eq(ErrOk, ret);
    }
}
END_TEST

START_TEST(test_msgGenerateMnemonicImplShouldFailIfItWasDone)
{
    storage_wipe();
    GenerateMnemonic msg = GenerateMnemonic_init_zero;
    msg.word_count = MNEMONIC_WORD_COUNT_12;
    msg.has_word_count = true;
    msgGenerateMnemonicImpl(&msg, &random_buffer);
    ErrCode_t ret = msgGenerateMnemonicImpl(&msg, &random_buffer);
    ck_assert_int_eq(ErrNotInitialized, ret);
}
END_TEST

START_TEST(test_msgGenerateMnemonicImplShouldFailForWrongSeedCount)
{
    storage_wipe();
    GenerateMnemonic msg = GenerateMnemonic_init_zero;
    msg.has_word_count = true;
    msg.word_count = MNEMONIC_WORD_COUNT_12 + 1;
    ErrCode_t ret = msgGenerateMnemonicImpl(&msg, random_buffer);
    ck_assert_int_eq(ErrInvalidArg, ret);
}
END_TEST

/**
 * Test cases : EntropyAck
 */

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

extern uint8_t int_entropy[INTERNAL_ENTROPY_SIZE];

START_TEST(test_msgEntropyAckChgMixerNotInternal)
{
    EntropyAck eaMsg = EntropyAck_init_zero;

    uint8_t null_entropy[INTERNAL_ENTROPY_SIZE] = {0};

    storage_wipe();
    ck_assert_mem_eq(int_entropy, null_entropy, sizeof(int_entropy));
    eaMsg.has_entropy = true;
    eaMsg.entropy.size = 32;
    random_buffer(eaMsg.entropy.bytes, 32);

    uint8_t entropy_mixer_initial_state[SHA256_DIGEST_LENGTH];
    backup_entropy_pool(entropy_mixer_initial_state);
    ck_assert_int_eq(ErrOk, msgEntropyAckImpl(&eaMsg));
    ck_assert_mem_eq(int_entropy, null_entropy, sizeof(int_entropy));
    uint8_t entropy_mixer_final_state[SHA256_DIGEST_LENGTH];
    backup_entropy_pool(entropy_mixer_final_state);
    ck_assert_mem_ne(entropy_mixer_final_state, entropy_mixer_initial_state, SHA256_DIGEST_LENGTH);
}
END_TEST

START_TEST(test_isSha256DigestHex)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        forceGenerateMnemonic(wcs[wi]);
        char raw_msg_hex[] = {"32018964c1ac8c2a536b59dd830a80b9d4ce3bb1ad6a182c13b36240ebf4ec11"};
        uint8_t raw_msg[sizeof(raw_msg_hex)] = {0};
        tobuff(raw_msg_hex, raw_msg, sizeof(raw_msg));
        char test_msg[256] = {0};

        SkycoinSignMessage msg = SkycoinSignMessage_init_zero;
        strncpy(
            msg.message, (char*)raw_msg,
            sizeof(raw_msg) < sizeof(msg.message)
                    ? sizeof(raw_msg) : sizeof(msg.message));
        RESP_INIT(ResponseSkycoinSignMessage);
        msgSkycoinSignMessageImpl(&msg, resp);
        // NOTE(): ecdsa signature have 65 bytes,
        // 2 for each one in hex = 130
        // TODO(): this kind of "dependency" is not maintainable.
        for (size_t i = 0; i < sizeof(resp->signed_message); ++i) {
            sprintf(test_msg, "Check that %d-th character in %s is in base16 alphabet", (int)i, resp->signed_message);
            ck_assert_msg(is_base16_char(resp->signed_message[i]), test_msg);
        }
    }
}
END_TEST

/**
 * Test cases : SkycoinSignMessage
 */

START_TEST(test_msgSkycoinSignMessageReturnIsInHex)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        forceGenerateMnemonic(wcs[wi]);
        char raw_msg[] = {"32018964c1ac8c2a536b59dd830a80b9d4ce3bb1ad6a182c13b36240ebf4ec11"};
        char test_msg[256];

        SkycoinSignMessage msg = SkycoinSignMessage_init_zero;
        strncpy(msg.message, raw_msg, sizeof(msg.message));
        RESP_INIT(ResponseSkycoinSignMessage);
        ck_assert_int_eq(ErrOk, msgSkycoinSignMessageImpl(&msg, resp));
        // NOTE(): ecdsa signature have 65 bytes,
        // 2 for each one in hex = 130
        // TODO(): this kind of "dependency" is not maintainable.
        for (size_t i = 0; i < sizeof(resp->signed_message); ++i) {
            sprintf(test_msg, "Check that %d-th character in %s is in base16 alphabet", (int)i, resp->signed_message);
            ck_assert_msg(is_base16_char(resp->signed_message[i]), test_msg);
        }
    }
}
END_TEST

START_TEST(test_msgSkycoinSignMessageCheckMaxAddresses)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        forceGenerateMnemonic(wcs[wi]);
        char raw_msg[] = {"32018964c1ac8c2a536b59dd830a80b9d4ce3bb1ad6a182c13b36240ebf4ec11"};
        SkycoinSignMessage msg = SkycoinSignMessage_init_zero;
        msg.address_n = 101;
        strncpy(msg.message, raw_msg, sizeof(msg.message));
        RESP_INIT(ResponseSkycoinSignMessage);
        ck_assert_int_eq(ErrInvalidValue, msgSkycoinSignMessageImpl(&msg, resp));
        msg.address_n = 100;
        ck_assert_int_eq(ErrOk, msgSkycoinSignMessageImpl(&msg, resp));
    }
}
END_TEST

/**
 * Test cases : SkycoinCheckMessage
 */

START_TEST(test_msgSkycoinCheckMessageSignatureOk)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        // NOTE(): Given
        forceGenerateMnemonic(wcs[wi]);
        SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
        msgSkyAddress.address_n = 1;
        uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        ResponseSkycoinAddress* respAddress = (ResponseSkycoinAddress*)(void*)msg_resp_addr;
        ErrCode_t err = msgSkycoinAddressImpl(&msgSkyAddress, respAddress);
        ck_assert_int_eq(ErrOk, err);
        ck_assert_int_eq(respAddress->addresses_count, 1);
        // NOTE(): `raw_msg` hash become from:
        // https://github.com/skycoin/skycoin/blob/develop/src/cipher/testsuite/testdata/input-hashes.golden
        char raw_msg[] = {"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"};
        SkycoinSignMessage msgSign = SkycoinSignMessage_init_zero;
        strncpy(msgSign.message, raw_msg, sizeof(msgSign.message));
        msgSign.address_n = 0;

        // NOTE(): When
        uint8_t msg_resp_sign[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        ResponseSkycoinSignMessage* respSign = (ResponseSkycoinSignMessage*)(void*)msg_resp_sign;
        ck_assert_int_eq(ErrOk, msgSkycoinSignMessageImpl(&msgSign, respSign));
        SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
        memcpy(checkMsg.message, msgSign.message, sizeof(checkMsg.message));
        memcpy(checkMsg.address, respAddress->addresses[0], sizeof(checkMsg.address));
        memcpy(checkMsg.signature, respSign->signed_message, sizeof(checkMsg.signature));
        Success successRespCheck = Success_init_zero;
        Failure failRespCheck = Failure_init_zero;
        err = msgSkycoinCheckMessageSignatureImpl(
                    &checkMsg, &successRespCheck, &failRespCheck);

        // NOTE(): Then
        ck_assert_int_eq(ErrOk, err);
        ck_assert(successRespCheck.has_message);
        int address_diff = strncmp(
                    respAddress->addresses[0],
                successRespCheck.message,
                sizeof(respAddress->addresses[0]));
        if (address_diff) {
            fprintf(stderr, "\nrespAddress->addresses[0]: ");
            for (size_t i = 0; i < sizeof(respAddress->addresses[0]); ++i) {
                fprintf(stderr, "%c", respAddress->addresses[0][i]);
            }
            fprintf(stderr, "\nrespCheck->message: ");
            for (size_t i = 0; i < sizeof(successRespCheck.message); ++i) {
                fprintf(stderr, "%c", successRespCheck.message[i]);
            }
            fprintf(stderr, "\n");
        }
        ck_assert_int_eq(0, address_diff);
    }
}
END_TEST

START_TEST(test_msgSkycoinCheckMessageSignatureCanNotGetPubKey)
{
    // NOTE Given
    SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
    strncpy(checkMsg.message, "msgSign.message", sizeof(checkMsg.message));
    strncpy(checkMsg.address, "respAddress->addresses[0]", sizeof(checkMsg.address));
    strncpy(checkMsg.signature, "respSign->signed_message", sizeof(checkMsg.signature));
    Success successRespCheck = Success_init_zero;
    Failure failRespCheck = Failure_init_zero;

    // NOTE When
    ErrCode_t err = msgSkycoinCheckMessageSignatureImpl(
                &checkMsg, &successRespCheck, &failRespCheck);

    // NOTE Then
    ck_assert_int_eq(ErrInvalidSignature, err);
}
END_TEST

static void swap_char(char* ch1, char* ch2)
{
    char tmp;
    memcpy((void*)&tmp, (void*)ch1, sizeof(tmp));
    memcpy((void*)ch1, (void*)ch2, sizeof(*ch1));
    memcpy((void*)ch2, (void*)&tmp, sizeof(tmp));
}

static void random_shuffle(char* buffer, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        size_t rIndex = (size_t)rand() % len;
        swap_char(&buffer[i], &buffer[rIndex]);
    }
}

START_TEST(test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidSignedMessage)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        // NOTE(): Given
        forceGenerateMnemonic(wcs[wi]);
        SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
        msgSkyAddress.address_n = 1;
        uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        ResponseSkycoinAddress* respAddress = (ResponseSkycoinAddress*)(void*)msg_resp_addr;
        ErrCode_t err = msgSkycoinAddressImpl(&msgSkyAddress, respAddress);
        ck_assert_int_eq(ErrOk, err);
        ck_assert_int_eq(respAddress->addresses_count, 1);
        // NOTE(): `raw_msg` hash become from:
        // https://github.com/skycoin/skycoin/blob/develop/src/cipher/testsuite/testdata/input-hashes.golden
        char raw_msg[] = {"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"};
        SkycoinSignMessage msgSign = SkycoinSignMessage_init_zero;
        strncpy(msgSign.message, raw_msg, sizeof(msgSign.message));
        msgSign.address_n = 0;

        // NOTE(): When
        uint8_t msg_resp_sign[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        ResponseSkycoinSignMessage* respSign = (ResponseSkycoinSignMessage*)(void*)msg_resp_sign;
        ck_assert_int_eq(ErrOk, msgSkycoinSignMessageImpl(&msgSign, respSign));
        // NOTE(denisaostaq@gmail.com): An attacker change our msg signature.
        random_shuffle(respSign->signed_message, sizeof(respSign->signed_message));
        SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
        strncpy(checkMsg.message, msgSign.message, sizeof(checkMsg.message));
        memcpy(checkMsg.address, respAddress->addresses[0], sizeof(checkMsg.address));
        memcpy(checkMsg.signature, respSign->signed_message, sizeof(checkMsg.signature));
        uint8_t msg_success_resp_check[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        uint8_t msg_fail_resp_check[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        Success* successRespCheck = (Success*)(void*)msg_success_resp_check;
        Failure* failRespCheck = (Failure*)(void*)msg_fail_resp_check;
        err = msgSkycoinCheckMessageSignatureImpl(&checkMsg, successRespCheck, failRespCheck);

        // NOTE(): Then
        ck_assert_int_ne(ErrOk, err);
        ck_assert(failRespCheck->has_message);
        int address_diff = strncmp(
                    respAddress->addresses[0],
                successRespCheck->message,
                sizeof(respAddress->addresses[0]));
        ck_assert_int_ne(0, address_diff);
    }
}
END_TEST

START_TEST(test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidMessage)
{
    for (size_t wi = 0; wi < sizeof(wcs)/sizeof(*wcs); ++wi) {
        // NOTE(): Given
        forceGenerateMnemonic(wcs[wi]);
        SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
        msgSkyAddress.address_n = 1;
        uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        ResponseSkycoinAddress* respAddress = (ResponseSkycoinAddress*)(void*)msg_resp_addr;
        ErrCode_t err = msgSkycoinAddressImpl(&msgSkyAddress, respAddress);
        ck_assert_int_eq(ErrOk, err);
        ck_assert_int_eq(respAddress->addresses_count, 1);
        // NOTE(): `raw_msg` hash become from:
        // https://github.com/skycoin/skycoin/blob/develop/src/cipher/testsuite/testdata/input-hashes.golden
        char raw_msg[] = {
            "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"};
        SkycoinSignMessage msgSign = SkycoinSignMessage_init_zero;
        strncpy(msgSign.message, raw_msg, sizeof(msgSign.message));
        msgSign.address_n = 0;

        // NOTE(): When
        uint8_t msg_resp_sign[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        ResponseSkycoinSignMessage* respSign = (ResponseSkycoinSignMessage*)(void*)msg_resp_sign;
        ck_assert_int_eq(ErrOk, msgSkycoinSignMessageImpl(&msgSign, respSign));
        // NOTE(denisaostaq@gmail.com): An attacker change our msg(hash).
        random_shuffle(msgSign.message, sizeof(msgSign.message));
        SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
        strncpy(checkMsg.message, msgSign.message, sizeof(checkMsg.message));
        memcpy(checkMsg.address, respAddress->addresses[0], sizeof(checkMsg.address));
        memcpy(checkMsg.signature, respSign->signed_message, sizeof(checkMsg.signature));
        uint8_t msg_success_resp_check[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        uint8_t msg_fail_resp_check[MSG_OUT_SIZE] __attribute__((aligned)) = {0};
        Success* successRespCheck = (Success*)(void*)msg_success_resp_check;
        Failure* failRespCheck = (Failure*)(void*)msg_fail_resp_check;
        err = msgSkycoinCheckMessageSignatureImpl(&checkMsg, successRespCheck, failRespCheck);

        // NOTE(): Then
        ck_assert_int_ne(ErrOk, err);
        ck_assert(failRespCheck->has_message);
        int address_diff = strncmp(
                    respAddress->addresses[0],
                successRespCheck->message,
                sizeof(respAddress->addresses[0]));
        ck_assert_int_ne(0, address_diff);
    }
}
END_TEST

/**
 * Test cases : ApplySettings
 */

START_TEST(test_msgApplySettingsLabelSuccess)
{
    storage_wipe();
    char raw_label[] = {
        "my custom device label"};
    ApplySettings msg = ApplySettings_init_zero;
    msg.has_label = true;
    strncpy(msg.label, raw_label, sizeof(msg.label));
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    ck_assert_int_eq(storage_hasLabel(), true);
    ck_assert_str_eq(storage_getLabel(), raw_label);
}
END_TEST

START_TEST(test_msgApplySettingsLabelGetFeaturesSuccess)
{
    storage_wipe();
    char raw_label[] = {
        "my custom device label"};
    ApplySettings msg = ApplySettings_init_zero;
    msg.has_label = true;
    strncpy(msg.label, raw_label, sizeof(msg.label));
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    ck_assert_int_eq(storage_hasLabel(), true);
    ck_assert_str_eq(storage_getLabel(), raw_label);
    Features features = Features_init_zero;
    msgGetFeaturesImpl(&features);
    ck_assert_int_eq(features.has_firmware_features, (int)true);
    ck_assert_int_eq(features.firmware_features, 4);
    ck_assert_int_eq((int)features.has_label, (int)true);
    ck_assert_str_eq(features.label, raw_label);
}
END_TEST

START_TEST(test_msgApplySettingsLabelShouldNotBeReset)
{
    storage_wipe();
    char raw_label[] = {
        "my custom device label"};
    ApplySettings msg = ApplySettings_init_zero;
    msg.has_use_passphrase = true;
    msg.use_passphrase = false;
    msg.has_label = true;
    strncpy(msg.label, raw_label, sizeof(msg.label));
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    ck_assert(!storage_hasPassphraseProtection());
    ck_assert_int_eq(storage_hasLabel(), true);
    ck_assert_str_eq(storage_getLabel(), raw_label);
    msg.has_label = false;
    memset(msg.label, 0, sizeof(msg.label));
    msg.has_use_passphrase = true;
    msg.use_passphrase = true;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    ck_assert_str_eq(storage_getLabel(), raw_label);
    ck_assert(storage_hasPassphraseProtection());
}
END_TEST

START_TEST(test_msgApplySettingsLabelSuccessCheck)
{
    storage_wipe();
    char raw_label[] = {
        "my custom device label"};
    ApplySettings msg = ApplySettings_init_zero;
    strncpy(msg.label, raw_label, sizeof(msg.label));
    msg.has_label = true;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    ck_assert_int_eq(storage_hasLabel(), true);
    ck_assert_str_eq(storage_getLabel(), raw_label);
}
END_TEST

START_TEST(test_msgApplySettingsUnsupportedLanguage)
{
    storage_wipe();
    char language[] = {"chinese"};
    ApplySettings msg = ApplySettings_init_zero;
    strncpy(msg.language, language, sizeof(msg.language));
    msg.has_language = true;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrInvalidArg);
}
END_TEST

START_TEST(test_msgApplySettingsNoSettingsFailure)
{
    storage_wipe();

    // No fields set
    ApplySettings msg = ApplySettings_init_zero;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrPreconditionFailed);

    // label value set but all has_* unset
    memset(&msg, 0, sizeof(msg));
    char raw_label[] = {
        "my custom device label"};
    strncpy(msg.label, raw_label, sizeof(msg.label));
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrPreconditionFailed);

    // use_passphrase value set but all has_* unset
    memset(&msg, 0, sizeof(msg));
    msg.use_passphrase = true;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrPreconditionFailed);

    // language value set but all has_* unset
    memset(&msg, 0, sizeof(msg));
    char language[] = {
        "english"};
    strncpy(msg.language, language, sizeof(msg.language));
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrPreconditionFailed);

    // All values set but all has_* unset
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.label, raw_label, sizeof(msg.label));
    strncpy(msg.language, language, sizeof(msg.language));
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrPreconditionFailed);
}
END_TEST

/**
 * Test cases : Features
 */

START_TEST(test_msgFeaturesLabelDefaultsToDeviceId)
{
    storage_wipe();
    const char* label = storage_getLabelOrDeviceId();
    ck_assert_str_eq(storage_uuid_str, label);
}
END_TEST

START_TEST(test_msgGetFeatures)
{
    RESP_INIT(Features);
    msgGetFeaturesImpl(resp);
    ck_assert_int_eq(resp->has_firmware_features, (int)true);
    ck_assert_int_eq(resp->firmware_features, 4);
#if VERSION_IS_SEMANTIC_COMPLIANT == 1
#ifdef VERSION_MAJOR
    ck_assert_int_eq(resp->has_fw_major, 1);
    ck_assert_int_eq(VERSION_MAJOR, resp->fw_major);
#endif // VERSION_MAJOR
#ifdef VERSION_MINOR
    ck_assert_int_eq(resp->has_fw_minor, 1);
    ck_assert_int_eq(VERSION_MINOR, resp->fw_minor);
#endif // VERSION_MINOR
#ifdef VERSION_PATCH
    ck_assert_int_eq(resp->has_fw_patch, 1);
    ck_assert_int_eq(VERSION_PATCH, resp->fw_patch);
#endif // VERSION_PATCH
#else  // VERSION_IS_SEMANTIC_COMPLIANT == 1
#ifdef APPVER
    char fw_version_head[sizeof(resp->fw_version_head)] = {0};
    sprintf(fw_version_head, "%x", APPVER);
    ck_assert_str_eq(fw_version_head, resp->fw_version_head);
    resp->has_fw_version_head = true;
#endif // APPVER
#endif // VERSION_IS_SEMANTIC_COMPLIANT == 1
}
END_TEST

/**
 * Test cases : ChangePin
 */

START_TEST(test_msgChangePinSuccess)
{
    ChangePin msg = ChangePin_init_zero;
    storage_wipe();

    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_ok), ErrOk);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN1);
}
END_TEST

START_TEST(test_msgChangePinEditSuccess)
{
    ChangePin msg = ChangePin_init_zero;
    storage_wipe();

    // Set pin
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_ok), ErrOk);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN1);
    // Edit pin
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_alt), ErrOk);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN2);
    // Edit if remove set to false
    msg.has_remove = true;
    msg.remove = false;
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_ok), ErrOk);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN1);
}
END_TEST

START_TEST(test_msgChangePinRemoveSuccess)
{
    ChangePin msg = ChangePin_init_zero;
    storage_wipe();

    // Set pin
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_ok), ErrOk);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN1);
    // Remove
    msg.has_remove = true;
    msg.remove = true;
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_alt), ErrOk);
    ck_assert_int_eq(storage_hasPin(), false);
}
END_TEST

START_TEST(test_msgChangePinSecondRejected)
{
    ChangePin msg = ChangePin_init_zero;
    storage_wipe();

    // Pin mismatch
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_wrong), ErrPinMismatch);
    ck_assert_int_eq(storage_hasPin(), false);
    // Retry and set it
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_ok), ErrOk);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN1);
    // Do not change pin on mismatch
    ck_assert_int_eq(msgChangePinImpl(&msg, &pin_reader_wrong), ErrPinMismatch);
    ck_assert_int_eq(storage_hasPin(), true);
    ck_assert_str_eq(storage_getPin(), TEST_PIN1);
}
END_TEST

/**
 * Test cases : SkycoinAddresses
 */

START_TEST(test_msgSkycoinAddressesAll)
{
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    SkycoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    msgAddr.address_n = 99;
    msgAddr.has_start_index = false;
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgSkycoinAddressImpl(&msgAddr, resp), ErrOk);
    ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
    int i;
    char test_msg[256];
    for (i = 0; i < resp->addresses_count; ++i) {
        sprintf(test_msg, "Check %d-th address , expected %s got %s", i, TEST_MANY_ADDRESSES[i], resp->addresses[i]);
        ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_ADDRESSES[i]) == 0, test_msg);
    }
}
END_TEST

START_TEST(test_msgSkycoinAddressesStartIndex)
{
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    SkycoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    msgAddr.has_start_index = true;
    msgAddr.start_index = random32() % 100;
    msgAddr.address_n = random32() % (100 - msgAddr.start_index) + 1;
    ck_assert_uint_ge(msgAddr.address_n, 1);
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgSkycoinAddressImpl(&msgAddr, resp), ErrOk);
    ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
    int i, index;
    char test_msg[256];
    for (i = 0, index = msgAddr.start_index; i < resp->addresses_count; ++i, ++index) {
        sprintf(test_msg, "Check %d-th address , expected %s got %s", index, TEST_MANY_ADDRESSES[index], resp->addresses[i]);
        ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_ADDRESSES[index]) == 0, test_msg);
    }
}
END_TEST

void setPassphrase(char *passphrase) {
    ApplySettings msg = ApplySettings_init_zero;
    msg.has_use_passphrase = true;
    msg.use_passphrase = true;
    ck_assert_int_eq(msgApplySettingsImpl(&msg), ErrOk);
    session_cachePassphrase(passphrase);
}

START_TEST(test_msgSkycoinAddressesAllEmptyPassphrase)
{
    storage_wipe();
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    SkycoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    setPassphrase("");

    msgAddr.address_n = 99;
    msgAddr.has_start_index = false;
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgSkycoinAddressImpl(&msgAddr, resp), ErrOk);
    ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
    int i;
    char test_msg[256];
    for (i = 0; i < resp->addresses_count; ++i) {
        sprintf(test_msg, "Check %d-th address , expected %s got %s", i, TEST_MANY_ADDRESSES[i], resp->addresses[i]);
        ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_ADDRESSES[i]) == 0, test_msg);
    }
}
END_TEST

START_TEST(test_msgSkycoinAddressesStartIndexEmptyPassphrase)
{
    storage_wipe();
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    SkycoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    setPassphrase("");

    msgAddr.has_start_index = true;
    msgAddr.start_index = random32() % 100;
    msgAddr.address_n = random32() % (100 - msgAddr.start_index) + 1;
    ck_assert_uint_ge(msgAddr.address_n, 1);
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgSkycoinAddressImpl(&msgAddr, resp), ErrOk);
    ck_assert_int_eq(resp->addresses_count, msgAddr.address_n);
    int i, index;
    char test_msg[256];
    for (i = 0, index = msgAddr.start_index; i < resp->addresses_count; ++i, ++index) {
        sprintf(test_msg, "Check %d-th address , expected %s got %s", index, TEST_MANY_ADDRESSES[index], resp->addresses[i]);
        ck_assert_msg(strcmp(resp->addresses[i], TEST_MANY_ADDRESSES[index]) == 0, test_msg);
    }
}
END_TEST

START_TEST(test_msgSkycoinAddressesTooMany)
{
    SetMnemonic msgSeed = SetMnemonic_init_zero;
    SkycoinAddress msgAddr = SkycoinAddress_init_zero;
    RESP_INIT(ResponseSkycoinAddress);

    strncpy(msgSeed.mnemonic, TEST_MANY_ADDRESS_SEED, sizeof(msgSeed.mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&msgSeed), ErrOk);

    msgAddr.has_start_index = false;
    msgAddr.address_n = 100;
    msgAddr.has_confirm_address = false;

    ck_assert_int_eq(msgSkycoinAddressImpl(&msgAddr, resp), ErrTooManyAddresses);
}
END_TEST

START_TEST(test_msgSkycoinAddressesFailWithoutMnemonic)
{
	SkycoinAddress msgAddr = SkycoinAddress_init_zero;
	RESP_INIT(ResponseSkycoinAddress);

	storage_wipe();

	msgAddr.has_start_index = true;
	msgAddr.start_index = random32() % 100;
	msgAddr.address_n = random32() % (100 - msgAddr.start_index) + 1;
	ck_assert_uint_ge(msgAddr.address_n, 1);
	msgAddr.has_confirm_address = false;

	ck_assert_int_eq(msgSkycoinAddressImpl(&msgAddr, resp), ErrMnemonicRequired);
}
END_TEST

ErrCode_t funcConfirmTxn(char* a, char* b, TransactionSign* sign, uint32_t t)
{
    (void)a;
    (void)b;
    (void)sign;
    (void)t;
    return ErrOk;
}

/**
 * Test cases : TransactionSign
 */

START_TEST(test_msgTransactionSign1)
{
    SkycoinTransactionInput transactionInputs[1] = {
        {.hashIn = "181bd5656115172fe81451fae4fb56498a97744d89702e73da75ba91ed5200f9",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot",
            .coin = 100000,
            .hour = 2}};
    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 1;
    msg.nbOut = 1;
    msg.transactionIn_count = 1;
    msg.transactionOut_count = 1;
    ResponseTransactionSign resp = ResponseTransactionSign_init_zero;
    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "d11c62b1e0e9abf629b1f5f4699cef9fbc504b45ceedf0047ead686979498218"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign2)
{
    SkycoinTransactionInput transactionInputs[2] = {
        {.hashIn = "01a9ef6c25271229ef9760e1536c3dc5ccf0ead7de93a64c12a01340670d87e9",
            .has_index = true,
            .index = 0},
        {.hashIn = "8c2c97bfd34e0f0f9833b789ce03c2e80ac0b94b9d0b99cee6ea76fb662e8e1c",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot",
            .coin = 20800000,
            .hour = 255}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionIn[1] = transactionInputs[1];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 2;
    msg.nbOut = 1;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 2);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "9bbde062d665a8b11ae15aee6d4f32f0f3d61af55160c142060795a219378a54"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);

    SkycoinCheckMessageSignature msg_s2 = SkycoinCheckMessageSignature_init_zero;
    memcpy(msg_s2.address, raw_addr, sizeof(raw_addr));
    char raw_msg2[] = {
        "f947b0352b19672f7b7d04dc2f1fdc47bc5355878f3c47a43d4d4cfbae07d026"};
    memcpy(msg_s2.message, raw_msg2, sizeof(raw_msg2));
    memcpy(msg_s2.signature, resp.signatures[1], sizeof(msg_s2.signature));

    ErrCode_t check_sign2 = msgSkycoinCheckMessageSignatureImpl(
        &msg_s2, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign2, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign3)
{
    SkycoinTransactionInput transactionInputs[3] = {
        {.hashIn = "da3b5e29250289ad78dc42dcf007ab8f61126198e71e8306ff8c11696a0c40f7",
            .has_index = true,
            .index = 0},
        {.hashIn = "33e826d62489932905dd936d3edbb74f37211d68d4657689ed4b8027edcad0fb",
            .has_index = true,
            .index = 0},
        {.hashIn = "668f4c144ad2a4458eaef89a38f10e5307b4f0e8fce2ade96fb2cc2409fa6592",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[2] = {
        {.address = "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot",
            .coin = 111000000,
            .hour = 6464556},
        {.address = "2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8",
            .coin = 1900000,
            .hour = 1}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionIn[1] = transactionInputs[1];
    msg.transactionIn[2] = transactionInputs[2];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.transactionOut[1] = transactionOutputs[1];
    msg.nbIn = 3;
    msg.nbOut = 2;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 3);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "ff383c647551a3ba0387f8334b3f397e45f9fc7b3b5c3b18ab9f2b9737bce039"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);

    SkycoinCheckMessageSignature msg_s2 = SkycoinCheckMessageSignature_init_zero;
    memcpy(msg_s2.address, raw_addr, sizeof(raw_addr));
    char raw_msg2[] = {
        "c918d83d8d3b1ee85c1d2af6885a0067bacc636d2ebb77655150f86e80bf4417"};
    memcpy(msg_s2.message, raw_msg2, sizeof(raw_msg2));
    memcpy(msg_s2.signature, resp.signatures[1], sizeof(msg_s2.signature));

    ErrCode_t check_sign2 = msgSkycoinCheckMessageSignatureImpl(
        &msg_s2, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign2, ErrOk);

    SkycoinCheckMessageSignature msg_s3 = SkycoinCheckMessageSignature_init_zero;
    memcpy(msg_s3.address, raw_addr, sizeof(raw_addr));
    char raw_msg3[] = {
        "0e827c5d16bab0c3451850cc6deeaa332cbcb88322deea4ea939424b072e9b97"};
    memcpy(msg_s3.message, raw_msg3, sizeof(raw_msg3));
    memcpy(msg_s3.signature, resp.signatures[2], sizeof(msg_s3.signature));

    ErrCode_t check_sign3 = msgSkycoinCheckMessageSignatureImpl(
        &msg_s3, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign3, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign4)
{
    SkycoinTransactionInput transactionInputs[2] = {
        {.hashIn = "b99f62c5b42aec6be97f2ca74bb1a846be9248e8e19771943c501e0b48a43d82",
            .has_index = true,
            .index = 0},
        {.hashIn = "cd13f705d9c1ce4ac602e4c4347e986deab8e742eae8996b34c429874799ebb2",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF",
            .coin = 23100000,
            .hour = 0}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionIn[1] = transactionInputs[1];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 2;
    msg.nbOut = 1;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 2);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "42a26380399172f2024067a17704fceda607283a0f17cb0024ab7a96fc6e4ac6"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);

    SkycoinCheckMessageSignature msg_s2 = SkycoinCheckMessageSignature_init_zero;
    memcpy(msg_s2.address, raw_addr, sizeof(raw_addr));
    char raw_msg2[] = {
        "5e0a5a8c7ea4a2a500c24e3a4bfd83ef9f74f3c2ff4bdc01240b66a41e34ebbf"};
    memcpy(msg_s2.message, raw_msg2, sizeof(raw_msg2));
    memcpy(msg_s2.signature, resp.signatures[1], sizeof(msg_s2.signature));

    ErrCode_t check_sign2 = msgSkycoinCheckMessageSignatureImpl(
        &msg_s2, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign2, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign5)
{
    SkycoinTransactionInput transactionInputs[1] = {
        {.hashIn = "4c12fdd28bd580989892b0518f51de3add96b5efb0f54f0cd6115054c682e1f1",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8",
            .coin = 1000000,
            .hour = 0}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 1;
    msg.nbOut = 1;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 1);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "c40e110f5e460532bfb03a5a0e50262d92d8913a89c87869adb5a443463dea69"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign6)
{
    SkycoinTransactionInput transactionInputs[1] = {
        {.hashIn = "c5467f398fc3b9d7255d417d9ca208c0a1dfa0ee573974a5fdeb654e1735fc59",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[3] = {
        {.address = "K9TzLrgqz7uXn3QJHGxmzdRByAzH33J2ot",
            .coin = 10000000,
            .hour = 1},
        {.address = "VNz8LR9JTSoz5o7qPHm3QHj4EiJB6LV18L",
            .coin = 5500000,
            .hour = 0},
        {.address = "22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF",
            .coin = 4500000,
            .hour = 1}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.transactionOut[1] = transactionOutputs[1];
    msg.transactionOut[2] = transactionOutputs[2];
    msg.nbIn = 1;
    msg.nbOut = 3;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 1);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "7edea77354eca0999b1b023014eb04638b05313d40711707dd03a9935696ccd1"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign7)
{
    SkycoinTransactionInput transactionInputs[3] = {
        {.hashIn = "7b65023cf64a56052cdea25ce4fa88943c8bc96d1ab34ad64e2a8b4c5055087e",
            .has_index = true,
            .index = 0},
        {.hashIn = "0c0696698cba98047bc042739e14839c09bbb8bb5719b735bff88636360238ad",
            .has_index = true,
            .index = 0},
        {.hashIn = "ae3e0b476b61734e590b934acb635d4ad26647bc05867cb01abd1d24f7f2ce50",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "22S8njPeKUNJBijQjNCzaasXVyf22rWv7gF",
            .coin = 25000000,
            .hour = 33}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionIn[1] = transactionInputs[1];
    msg.transactionIn[2] = transactionInputs[2];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 3;
    msg.nbOut = 1;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 3);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "ec9053ab9988feb0cfb3fcce96f02c7d146ff7a164865c4434d1dbef42a24e91"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);

    SkycoinCheckMessageSignature msg_s2 = SkycoinCheckMessageSignature_init_zero;
    memcpy(msg_s2.address, raw_addr, sizeof(raw_addr));
    char raw_msg2[] = {
        "332534f92c27b31f5b73d8d0c7dde4527b540024f8daa965fe9140e97f3c2b06"};
    memcpy(msg_s2.message, raw_msg2, sizeof(raw_msg2));
    memcpy(msg_s2.signature, resp.signatures[1], sizeof(msg_s2.signature));

    ErrCode_t check_sign2 = msgSkycoinCheckMessageSignatureImpl(
        &msg_s2, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign2, ErrOk);

    SkycoinCheckMessageSignature msg_s3 = SkycoinCheckMessageSignature_init_zero;
    memcpy(msg_s3.address, raw_addr, sizeof(raw_addr));
    char raw_msg3[] = {
        "63f955205ceb159415268bad68acaae6ac8be0a9f33ef998a84d1c09a8b52798"};
    memcpy(msg_s3.message, raw_msg3, sizeof(raw_msg3));
    memcpy(msg_s3.signature, resp.signatures[2], sizeof(msg_s3.signature));

    ErrCode_t check_sign3 = msgSkycoinCheckMessageSignatureImpl(
        &msg_s3, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign3, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign8)
{
    SkycoinTransactionInput transactionInputs[3] = {
        {.hashIn = "ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "3pXt9MSQJkwgPXLNePLQkjKq8tsRnFZGQA",
            .coin = 1000000,
            .hour = 1000}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 1;
    msg.nbOut = 1;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 1);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "47bfa37c79f7960df8e8a421250922c5165167f4c91ecca5682c1106f9010a7f"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign9)
{
    SkycoinTransactionInput transactionInputs[1] = {
        {.hashIn = "ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[2] = {
        {.address = "3pXt9MSQJkwgPXLNePLQkjKq8tsRnFZGQA",
            .coin = 300000,
            .hour = 500},
        {.address = "S6Dnv6gRTgsHCmZQxjN7cX5aRjJvDvqwp9",
            .coin = 700000,
            .hour = 500}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.transactionOut[1] = transactionOutputs[1];
    msg.nbIn = 1;
    msg.nbOut = 2;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 1);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "e0c6e4982b1b8c33c5be55ac115b69be68f209c5d9054954653e14874664b57d"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign10)
{
    SkycoinTransactionInput transactionInputs[1] = {
        {.hashIn = "ae6fcae589898d6003362aaf39c56852f65369d55bf0f2f672bcc268c15a32da",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[2] = {
        {.address = "S6Dnv6gRTgsHCmZQxjN7cX5aRjJvDvqwp9",
            .coin = 1000000,
            .hour = 1000}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 1;
    msg.nbOut = 1;

    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ErrCode_t errCode = msgTransactionSignImpl(&msg, funcConfirmTxn, &resp);
    ck_assert_int_eq(errCode, ErrOk);
    ck_assert_int_eq(resp.signatures_count, 1);

    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    char raw_addr[] = {"2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw"};
    memcpy(msg_s.address, raw_addr, sizeof(raw_addr));
    char raw_msg[] = {
        "457648543755580ad40ab461bbef2b0ffe19f2130f2f220cbb2f196b05d436b4"};
    memcpy(msg_s.message, raw_msg, sizeof(raw_msg));
    memcpy(msg_s.signature, resp.signatures[0], sizeof(msg_s.signature));

    Failure failure_resp = Failure_init_default;
    Success success_resp = Success_init_default;
    ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
        &msg_s, &success_resp, &failure_resp);
    ck_assert_int_eq(check_sign, ErrOk);
}
END_TEST

START_TEST(test_msgTransactionSign11)
{
    // Set mnemonic
    SetMnemonic mnemonic = SetMnemonic_init_zero;
    char mnemonic_str[] = { "network hurdle trash obvious soccer sunset side merit horn author horn you" };
    memcpy(mnemonic.mnemonic,mnemonic_str, sizeof(mnemonic_str));
    ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

    // Send SignTx message
    SignTx sign_tx = SignTx_init_default;
    sign_tx.outputs_count = 14;
    sign_tx.inputs_count = 14;
    sign_tx.has_coin_name = true;
    strcpy((char*)sign_tx.coin_name,"Skycoin");
    sign_tx.has_version = true;
    sign_tx.version = 1;
    sign_tx.has_lock_time = true;
    sign_tx.lock_time = 3;
    sign_tx.has_tx_hash = true;
    strcpy((char*)sign_tx.tx_hash,"8cbdfbc7aa9975904b805152a816a897d7f8b652806fd9ceec8822b096c6fc18");
    TxRequest response = TxRequest_init_default;
    ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 1);
    
    // Init TxAck message for inputs
    TxAck tx_ack = TxAck_init_default;
    tx_ack.has_tx = true;
    tx_ack.tx.has_version = true;
    tx_ack.tx.version = 1;
    tx_ack.tx.inputs_count = 7;
    tx_ack.tx.outputs_count = 0;
    tx_ack.tx.has_lock_time = true;
    tx_ack.tx.lock_time = 3;

    // Send inputs 0-6
    TxAck_TransactionType_TxInputType inputs1[] = {
        {.hashIn = "f61364da33ecd1f557cbbb4999b89baf14364d8934b2431cb1313a40695c435a",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "7dd4035d267a3f692a8060b487895cbab4b18ff6dac1e7763b6243dd7b90e269",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "5fcc3cea408c88371ece8ef0627cf6f5a91dc49085b1aa131137d3b72e7cc5fb",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "6c7eea5c7290381393cbbd0c6a8269fcddfc24f7846a210e8c15bf0321dfe9df",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "9d8dcf32ec69155fbbd42b64a277cc2cf41a7b7a07101c7772485255fa5b84cc",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "dfb13c86421c37f4a697433dbe5e0b6f33479596b14dc43bcf83f577881625d4",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "a6fd4cdb5de8aa8bedc1f5b6e69bc5273f1590784caa584f9d275afa294156e3",
         .address_n_count = 1,
         .address_n = {0} }
    };
    memcpy(tx_ack.tx.inputs,inputs1,sizeof(inputs1));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 2);

    // Send inputs 7-13
    TxAck_TransactionType_TxInputType inputs2[] = {
        {.hashIn = "06c69e519bbcd5e989f66211ffa6f33610b3de986989ee5a04b7144dcd6252b4",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "3d1f6c3e55034e113e7f6a3a69afbd3929b906f4bc834fba32a60f24a6bdb985",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "a15aa4069673995a09996f4c5cb7ee040ebf0afa8bb1593c39a96406e28228f0",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "d8f5573a56cb94561b4404b9d55cbc14cbd3ceb1f8e75223ae3ea3ff900be2bd",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "f16bcbda8477c7178120df5a597fa4326b71fbf3f8bc5dd4734a00f87bfef5c8",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "bed47fc5ad21ce1deab10bfe45a27bcae251224539fca8d618a3c86791cd3baf",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "f580c788067392c6cf0f25b5c1fe099c41132750aab0cde0cfab6d47e5c0fbe7",
         .address_n_count = 1,
         .address_n = {0} }
    };
    memcpy(tx_ack.tx.inputs, inputs2, sizeof(inputs2));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXOUTPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 3);

    // Init TxAck message for outputs
    tx_ack.has_tx = true;
    tx_ack.tx.has_version = true;
    tx_ack.tx.version = 1;
    tx_ack.tx.inputs_count = 0;
    tx_ack.tx.outputs_count = 7;
    tx_ack.tx.has_lock_time = true;
    tx_ack.tx.lock_time = 3;

    // Send outputs 0-6
    TxAck_TransactionType_TxOutputType outputs1[] = {
        {.address = "2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 149},
        {.address = "zC8GAQGQBfwk7vtTxVoRG7iMperHNuyYPs",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 149},
        {.address = "28L2fexvThTVz6e2dWUV4pSuCP8SAnCUVku",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 149},
        {.address = "2NckPkQRQFa5E7HtqDkZmV1TH4HCzR2N5J6",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 149},
        {.address = "2ARhYQsMmMZuw5LPmZQvyWoTm1VUH8kSZ14",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 149},
        {.address = "FjWaGnwGTswo7TegsB9KikqcxGHy8zHTS1",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "26GcGAkdrXYkPVKkHvy5FQWAeLVVVGSmz6V",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148}
    };
    memcpy(tx_ack.tx.outputs, outputs1, sizeof(outputs1));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXOUTPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 4);

    // Send outputs 7-13
    TxAck_TransactionType_TxOutputType outputs2[] = {
        {.address = "obaHadRxLaz8Laoxi8TA799ycHXNK2hgdz",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "26jybLrsXXWjwBdmR2eo4c25hYGMipLEjTr",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "2CgDFkD43CUpQot3e76iuoB2BxCGXZ6xn38",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "cMdZRECEGhrBqtKvuB9XW2EK9tqi4znNhN",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "ouE9prS4XMhVwQa5gwW4hQuiAGamMcJmK5",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "ZyLHjEdTbxnYHZC2U4ZNqSuZBUh74Sjh9v",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148},
        {.address = "2eZCcsBQVooxUStrCKEZ4TLZzbGa7tx7Cwa",
         .address_n_count = 0,
         .coins = 2000000,
         .hours = 148}
    };
    memcpy(tx_ack.tx.outputs, outputs2, sizeof(outputs2));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 5);

    // Init TxAck message for inputs
    tx_ack.has_tx = true;
    tx_ack.tx.has_version = true;
    tx_ack.tx.version = 1;
    tx_ack.tx.inputs_count = 7;
    tx_ack.tx.outputs_count = 0;
    tx_ack.tx.has_lock_time = true;
    tx_ack.tx.lock_time = 3;

    // Send inputs 0-6
    memcpy(tx_ack.tx.inputs, inputs1, sizeof(inputs1));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 6);
    ck_assert_int_eq(response.sign_result_count, 7);

    char messages1[7][64] = {"24cb998dbaf43e6ae56896b116b5fd9bc13dc07a6ae05a04be48e404cb26260a",
                            "69f07537857f5e79784e0d827f2111f0f50aeb3c990a0abe26629d6992ee619c",
                            "be38e73857ba9d5a1af7f80050fc483f8452b8e993a35c01f9cc5fc8e401e907",
                            "91f6382d053ba621d97485ff74abc4e79908dfbf7647b59721b00074b27189c2",
                            "7d81509d42118a88561d4cd9eddd1e315e3fdf650199cc030bf0021582ff46cf",
                            "0f04c62b3685668369a5e1bf1a3e7e539c9cd202efde7cd5730210b01c10bd10",
                            "d2afbc1c9516cb344901b947283b62d69866fd653b273b14da66779e142f69d9"};
    SkycoinCheckMessageSignature msg_s = SkycoinCheckMessageSignature_init_zero;
    for (uint8_t i = 0; i < 7; i++){
        memcpy(msg_s.address, "zF2bJcm1VunARAJ26HmYVQE2SEudQmK9DJ", 34);
        memcpy(msg_s.message, messages1[i], sizeof(messages1[i]));
        memcpy(msg_s.signature, response.sign_result[i].signature, sizeof(response.sign_result[i].signature));
        Failure failure_resp = Failure_init_default;
        Success success_resp = Success_init_default;
        ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
            &msg_s, &success_resp, &failure_resp);
        ck_assert_int_eq(check_sign, ErrOk);
    }

    // Send inputs 7-13
    memcpy(tx_ack.tx.inputs, inputs2, sizeof(inputs2));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXFINISHED);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 7);
    ck_assert_int_eq(response.sign_result_count, 7);

    char messages[7][64] = {    "adbae6d00a6567c5f8e473b6960ba4268d066ffdcb318eb36ef014a2c074460c",
                                "d9525e1876e759e2ca504b1c177cf8d21ea3e2bbec27bea79261479a8edfe84b",
                                "4dfe14d44b23316cfeda041597291a15afd75a2b8a89e3d2b7f2b736c7cfa28d",
                                "30d672b384783ae5ca09af711d756d809d37469e68589d3a5941ed80128a7685",
                                "d221d769c6e9914c030c7dcea794a990623b3505ff32b90f5f65d14a25d5fc0d",
                                "efb0c7d702ac4d9677fcd45785a5ff73a324bd787adbc17b3116a85fd38d1841",
                                "be0c55f354fa94deb0ccbc62f29a8fa43068f8053c70eddc2e62d724659ff877"};
    for (uint8_t i = 0; i < 7; i++){
        memcpy(msg_s.address, "zF2bJcm1VunARAJ26HmYVQE2SEudQmK9DJ", 34);
        memcpy(msg_s.message, messages[i], sizeof(messages[i]));
        memcpy(msg_s.signature, response.sign_result[i].signature, sizeof(response.sign_result[i].signature));
        Failure failure_resp = Failure_init_default;
        Success success_resp = Success_init_default;
        ErrCode_t check_sign = msgSkycoinCheckMessageSignatureImpl(
            &msg_s, &success_resp, &failure_resp);
        ck_assert_int_eq(check_sign, ErrOk);
    }
}
END_TEST

START_TEST(test_msgTransactionSign12)
{
    SetMnemonic mnemonic = SetMnemonic_init_zero;
    char mnemonic_str[] = { "network hurdle trash obvious soccer sunset side merit horn author horn you" };
    memcpy(mnemonic.mnemonic,mnemonic_str, sizeof(mnemonic_str));
    ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

    SignTx sign_tx = SignTx_init_default;
    sign_tx.outputs_count = 14;
    sign_tx.inputs_count = 14;
    sign_tx.has_coin_name = true;
    strcpy(sign_tx.coin_name,"Skycoin");
    sign_tx.has_version = true;
    sign_tx.version = 1;
    sign_tx.has_lock_time = true;
    sign_tx.lock_time = 3;
    sign_tx.has_tx_hash = true;
    strcpy(sign_tx.tx_hash,"8cbdfbc7aa9975904b805152a816a897d7f8b652806fd9ceec8822b096c6fc18");
    TxRequest response = TxRequest_init_default;
    ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 1);
    
    TxAck tx_ack = TxAck_init_default;
    tx_ack.has_tx = true;
    tx_ack.tx.has_version = true;
    tx_ack.tx.version = 1;
    tx_ack.tx.inputs_count = 3;
    tx_ack.tx.outputs_count = 2;
    tx_ack.tx.has_lock_time = true;
    tx_ack.tx.lock_time = 3;

    TxAck_TransactionType_TxInputType inputs1[] = {
        {.hashIn = "941a422ed8b17ae9dcbf942ace143f77c26a9c02d2e6395b46d50d1079ba4b00",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1c7afa90dcd10063722c0cf8981c52bc715a6d522c4fcc92cd743e2120e866f2",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1e06ce57e449a3744a58d115da99f375926b30a4aaa62500f36400c479c86026",
         .address_n_count = 1,
         .address_n = {0} }
    };
    TxAck_TransactionType_TxOutputType outputs1[] = {
        {.address = "2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "zC8GAQGQBfwk7vtTxVoRG7iMperHNuyYPs",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
    };
    memcpy(tx_ack.tx.inputs, inputs1, sizeof(inputs1));
    memcpy(tx_ack.tx.outputs, outputs1, sizeof(outputs1));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrInvalidArg);
}
END_TEST

START_TEST(test_msgTransactionSign13)
{
    SetMnemonic mnemonic = SetMnemonic_init_zero;
    char mnemonic_str[] = { "network hurdle trash obvious soccer sunset side merit horn author horn you" };
    memcpy(mnemonic.mnemonic,mnemonic_str, sizeof(mnemonic_str));
    ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

    SignTx sign_tx = SignTx_init_default;
    sign_tx.outputs_count = 14;
    sign_tx.inputs_count = 14;
    sign_tx.has_coin_name = true;
    strcpy(sign_tx.coin_name, "Skycoin");
    sign_tx.has_version = true;
    sign_tx.version = 1;
    sign_tx.has_lock_time = true;
    sign_tx.lock_time = 3;
    sign_tx.has_tx_hash = true;
    strcpy(sign_tx.tx_hash, "8cbdfbc7aa9975904b805152a816a897d7f8b652806fd9ceec8822b096c6fc18");
    TxRequest response = TxRequest_init_default;
    ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 1);

    sign_tx.outputs_count = 14;
    sign_tx.inputs_count = 14;
    sign_tx.has_coin_name = true;
    strcpy(sign_tx.coin_name, "Skycoin");
    sign_tx.has_version = true;
    sign_tx.version = 1;
    sign_tx.has_lock_time = true;
    sign_tx.lock_time = 3;
    sign_tx.has_tx_hash = true;
    strcpy(sign_tx.tx_hash, "8cbdfbc7aa9975904b805152a816a897d7f8b652806fd9ceec8822b096c6fc18");    
    ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrFailed);
}
END_TEST

START_TEST(test_msgTransactionSign14)
{
    SetMnemonic mnemonic = SetMnemonic_init_zero;
    char mnemonic_str[] = { "network hurdle trash obvious soccer sunset side merit horn author horn you" };
    memcpy(mnemonic.mnemonic,mnemonic_str, sizeof(mnemonic_str));
    ck_assert_int_eq(msgSetMnemonicImpl(&mnemonic), ErrOk);

    SignTx sign_tx = SignTx_init_default;
    sign_tx.outputs_count = 14;
    sign_tx.inputs_count = 14;
    sign_tx.has_coin_name = true;
    strcpy(sign_tx.coin_name, "Skycoin");
    sign_tx.has_version = true;
    sign_tx.version = 1;
    sign_tx.has_lock_time = true;
    sign_tx.lock_time = 3;
    sign_tx.has_tx_hash = true;
    strcpy(sign_tx.tx_hash, "8cbdfbc7aa9975904b805152a816a897d7f8b652806fd9ceec8822b096c6fc18");
    TxRequest response = TxRequest_init_default;
    ck_assert_int_eq(msgSignTxImpl(&sign_tx, &response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 1);
    
    TxAck tx_ack = TxAck_init_default;
    tx_ack.has_tx = true;
    tx_ack.tx.has_version = true;
    tx_ack.tx.version = 1;
    tx_ack.tx.inputs_count = 7;
    tx_ack.tx.outputs_count = 0;
    tx_ack.tx.has_lock_time = true;
    tx_ack.tx.lock_time = 3;

    TxAck_TransactionType_TxInputType inputs1[] = {
        {.hashIn = "941a422ed8b17ae9dcbf942ace143f77c26a9c02d2e6395b46d50d1079ba4b00",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1c7afa90dcd10063722c0cf8981c52bc715a6d522c4fcc92cd743e2120e866f2",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1e06ce57e449a3744a58d115da99f375926b30a4aaa62500f36400c479c86026",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "c1dca5b6e34dbc8b8a87cae3074e1c24e555c8300043975982b3754c25fa31ef",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "516d5dd0465474b53520c2c7377f293823c36740b10a6cace58bcf53cabf91f2",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "69c010a4f512ef9a1ed73e8da5e57e7fdb11b9cadfa42babaf393c528d05b372",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "f7aeffdbfad94333c5198149bc1ad2a02acabeb3e67834f2f4c8aa2cac20248d",
         .address_n_count = 1,
         .address_n = {0} }
    };
    memcpy(tx_ack.tx.inputs,inputs1,sizeof(inputs1));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXINPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 2);

    TxAck_TransactionType_TxInputType inputs2[] = {
        {.hashIn = "6e99ca948cb8d50dc8708d77498fccc65ca2e6e8d6192c4b178999a6ed403752",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "6bb7c8ec3654b5f4718988606e15947ac45fd8ac255a6838c08c926a199c412d",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "19c3f8ef155b363cfc9e508de5930aad477e3ffd974ac90fd53b5eb0853cf29a",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "0516f33e59a97587135ee4350c8edff3a196415f31e3233579c29c505d6efa2c",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1d6a5a6fa9af1acf4ad8bf4348369adcaf61bab84b82697db5f733f60f91337b",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "d7a958d8e7edbab356b68f257e3b57d44d35e22f1fcfbee70116d502fa48e390",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "fc8542d202ee8c57a8f91058aaaf852a3db695248f94302f3f76f29e42d284c1",
         .address_n_count = 1,
         .address_n = {0} }
    };
    memcpy(tx_ack.tx.inputs, inputs2, sizeof(inputs2));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrOk);
    ck_assert_int_eq(response.request_type,TxRequest_RequestType_TXOUTPUT);
    ck_assert_int_eq(response.has_details, true);
    ck_assert_int_eq(response.details.request_index, 3);

    tx_ack.has_tx = true;
    tx_ack.tx.has_version = true;
    tx_ack.tx.version = 1;
    tx_ack.tx.inputs_count = 3;
    tx_ack.tx.outputs_count = 7;
    tx_ack.tx.has_lock_time = true;
    tx_ack.tx.lock_time = 3;

    TxAck_TransactionType_TxInputType inputs3[] = {
        {.hashIn = "941a422ed8b17ae9dcbf942ace143f77c26a9c02d2e6395b46d50d1079ba4b00",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1c7afa90dcd10063722c0cf8981c52bc715a6d522c4fcc92cd743e2120e866f2",
         .address_n_count = 1,
         .address_n = {0} },
        {.hashIn = "1e06ce57e449a3744a58d115da99f375926b30a4aaa62500f36400c479c86026",
         .address_n_count = 1,
         .address_n = {0} }
    };

    TxAck_TransactionType_TxOutputType outputs1[] = {
        {.address = "2EU3JbveHdkxW6z5tdhbbB2kRAWvXC2pLzw",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "zC8GAQGQBfwk7vtTxVoRG7iMperHNuyYPs",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "28L2fexvThTVz6e2dWUV4pSuCP8SAnCUVku",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "2NckPkQRQFa5E7HtqDkZmV1TH4HCzR2N5J6",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "2ARhYQsMmMZuw5LPmZQvyWoTm1VUH8kSZ14",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "FjWaGnwGTswo7TegsB9KikqcxGHy8zHTS1",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255},
        {.address = "26GcGAkdrXYkPVKkHvy5FQWAeLVVVGSmz6V",
         .address_n_count = 0,
         .coins = 2,
         .hours = 255}
    };
    memcpy(tx_ack.tx.inputs, inputs3, sizeof(inputs3));
    memcpy(tx_ack.tx.outputs, outputs1, sizeof(outputs1));
    ck_assert_int_eq(msgTxAckImpl(&tx_ack,&response), ErrInvalidArg);
}
END_TEST

START_TEST(test_transactionSignCheckEdges)
{
    SkycoinTransactionInput transactionInputs[1] = {
        {.hashIn = "4c12fdd28bd580989892b0518f51de3add96b5efb0f54f0cd6115054c682e1f1",
            .has_index = true,
            .index = 0}};

    SkycoinTransactionOutput transactionOutputs[1] = {
        {.address = "2iNNt6fm9LszSWe51693BeyNUKX34pPaLx8",
            .coin = 1000000,
            .hour = 0}};

    SetMnemonic nemonic = SetMnemonic_init_zero;
    char raw_mnemonic[] = {
        "cloud flower upset remain green metal below cup stem infant art thank"};
    memcpy(nemonic.mnemonic, raw_mnemonic, sizeof(raw_mnemonic));
    ck_assert_int_eq(msgSetMnemonicImpl(&nemonic), ErrOk);

    TransactionSign msg = TransactionSign_init_zero;
    msg.transactionIn[0] = transactionInputs[0];
    msg.transactionOut[0] = transactionOutputs[0];
    msg.nbIn = 8;
    msg.nbOut = 8;
    ResponseTransactionSign resp = ResponseTransactionSign_init_default;
    ck_assert_int_eq(ErrOk, msgTransactionSignImpl(&msg, funcConfirmTxn, &resp));
    msg.nbIn = 9;
    ck_assert_int_eq(ErrInvalidArg, msgTransactionSignImpl(&msg, funcConfirmTxn, &resp));
    msg.nbIn = 8;
    msg.nbOut = 9;
    ck_assert_int_eq(ErrInvalidArg, msgTransactionSignImpl(&msg, funcConfirmTxn, &resp));
}
END_TEST

// define test cases
TCase* add_fsm_tests(TCase* tc)
{
    tcase_add_checked_fixture(tc, setup_tc_fsm, teardown_tc_fsm);
    tcase_add_test(tc, test_msgSkycoinSignMessageReturnIsInHex);
    tcase_add_test(tc, test_msgSkycoinSignMessageCheckMaxAddresses);
    tcase_add_test(tc, test_msgGenerateMnemonicImplOk);
    tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFailIfItWasDone);
    tcase_add_test(tc, test_msgSkycoinCheckMessageSignatureOk);
    tcase_add_test(tc, test_msgSkycoinCheckMessageSignatureCanNotGetPubKey);
    tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFailForWrongSeedCount);
    tcase_add_test(tc, test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidSignedMessage);
    tcase_add_test(tc, test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidMessage);
    tcase_add_test(tc, test_msgApplySettingsLabelSuccess);
    tcase_add_test(tc, test_msgFeaturesLabelDefaultsToDeviceId);
    tcase_add_test(tc, test_msgGetFeatures);
    tcase_add_test(tc, test_msgApplySettingsLabelSuccessCheck);
    tcase_add_test(tc, test_msgApplySettingsLabelShouldNotBeReset);
    tcase_add_test(tc, test_msgApplySettingsLabelGetFeaturesSuccess);
    tcase_add_test(tc, test_msgApplySettingsUnsupportedLanguage);
    tcase_add_test(tc, test_msgApplySettingsNoSettingsFailure);
    tcase_add_test(tc, test_msgFeaturesLabelDefaultsToDeviceId);
    tcase_add_test(tc, test_msgEntropyAckChgMixerNotInternal);
    tcase_add_test(tc, test_msgChangePinSuccess);
    tcase_add_test(tc, test_msgChangePinSecondRejected);
    tcase_add_test(tc, test_msgChangePinEditSuccess);
    tcase_add_test(tc, test_msgChangePinRemoveSuccess);
    tcase_add_test(tc, test_msgSkycoinAddressesAll);
    tcase_add_test(tc, test_msgSkycoinAddressesStartIndex);
    tcase_add_test(tc, test_msgSkycoinAddressesAllEmptyPassphrase);
    tcase_add_test(tc, test_msgSkycoinAddressesStartIndexEmptyPassphrase);
    tcase_add_test(tc, test_msgSkycoinAddressesTooMany);
    tcase_add_test(tc, test_msgSkycoinAddressesFailWithoutMnemonic);
    tcase_add_test(tc, test_msgTransactionSign1);
    tcase_add_test(tc, test_msgTransactionSign2);
    tcase_add_test(tc, test_msgTransactionSign3);
    tcase_add_test(tc, test_msgTransactionSign4);
    tcase_add_test(tc, test_msgTransactionSign5);
    tcase_add_test(tc, test_msgTransactionSign6);
    tcase_add_test(tc, test_msgTransactionSign7);
    tcase_add_test(tc, test_msgTransactionSign8);
    tcase_add_test(tc, test_msgTransactionSign9);
    tcase_add_test(tc, test_msgTransactionSign10);
    tcase_add_test(tc, test_msgTransactionSign11);
    tcase_add_test(tc, test_msgTransactionSign12);
    tcase_add_test(tc, test_msgTransactionSign13);
    tcase_add_test(tc, test_msgTransactionSign14);
    tcase_add_test(tc, test_isSha256DigestHex);
    tcase_add_test(tc, test_transactionSignCheckEdges);
    return tc;
}
