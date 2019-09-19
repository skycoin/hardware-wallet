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

#include "skycoin-crypto/tools/base58.h"
#include "skycoin-crypto/tools/bip32.h"
#include "skycoin-crypto/tools/bip39.h"
#include "skycoin-crypto/check_digest.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/firmware/error.h"
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
#include "skycoin-crypto/tools/rand.h"
#include "tiny-firmware/firmware/recovery.h"
#include "tiny-firmware/firmware/reset.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/setup.h"
#include "skycoin-crypto/skycoin_crypto.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/tests/test_fsm.h"
#include "tiny-firmware/tests/test_many_address_golden.h"
#include "tiny-firmware/usb.h"
#include "tiny-firmware/util.h"
#include <inttypes.h>
#include <stdio.h>
#include "tiny-firmware/firmware/fsm_skycoin_impl.h"

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

// define test cases
TCase* add_fsm_tests(TCase* tc)
{
    tcase_add_checked_fixture(tc, setup_tc_fsm, teardown_tc_fsm);
    tcase_add_test(tc, test_msgGenerateMnemonicImplOk);
    tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFailIfItWasDone);
    tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFailForWrongSeedCount);
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
    tcase_add_test(tc, test_isSha256DigestHex);
    return tc;
}
