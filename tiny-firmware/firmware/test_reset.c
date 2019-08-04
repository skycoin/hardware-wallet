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

#include <check.h>
#include <stdio.h>
#include <time.h>

#include "test_pin.h"
#include "test_reset.h"
#include "rand.h"
#include "reset.h"
#include "setup.h"
#include "storage.h"

#define TEST_SERIALNO "DC5E1023685C298CA8E27611"

void setup_tc_reset(void)
{
    srand(time(NULL));
    setup();
}

void teardown_tc_reset(void)
{
}

static struct {
    STORAGE_STRING(mnemonic, 241)
    bool passphrase_protection;
    STORAGE_STRING(pin, 10)
    STORAGE_STRING(language, 17)
    STORAGE_STRING(label, DEVICE_LABEL_SIZE)
} storage_snapshot;

void take_storage_snapshot(void)
{
    storage_snapshot.has_mnemonic = storage_hasMnemonic();
    if (storage_snapshot.has_mnemonic) {
        strncpy(storage_snapshot.mnemonic, storage_getMnemonic(), 241);
    }
    storage_snapshot.has_label = storage_hasLabel();
    if (storage_snapshot.has_label) {
        strncpy(storage_snapshot.label, storage_getLabel(), DEVICE_LABEL_SIZE);
    }
    storage_snapshot.has_language = storage_getLanguage() != 0;
    if (storage_snapshot.has_language) {
        strncpy(storage_snapshot.language, storage_getLanguage(), 17);
    }
    storage_snapshot.has_pin = storage_hasPin();
    if (storage_snapshot.has_pin) {
        strncpy(storage_snapshot.pin, storage_getPin(), 10);
    }
    // Ignore has_passphrase since storage_* methods not get it
    storage_snapshot.passphrase_protection = storage_hasPassphraseProtection();
}

void assert_storage_snapshot_eq(char* msg)
{
    ck_assert_msg(storage_snapshot.has_mnemonic == storage_hasMnemonic(), msg);
    if (storage_snapshot.has_mnemonic) {
        ck_assert_msg(strcmp(storage_snapshot.mnemonic, storage_getMnemonic()) == 0, msg);
    }
    ck_assert_msg(storage_snapshot.has_label == storage_hasLabel(), msg);
    if (storage_snapshot.has_label) {
        ck_assert_msg(strcmp(storage_snapshot.label, storage_getLabel()) == 0, msg);
    }
    ck_assert_msg(storage_snapshot.has_language == (storage_getLanguage() != 0), msg);
    if (storage_snapshot.has_language) {
        ck_assert_msg(strcmp(storage_snapshot.language, storage_getLanguage()) == 0, msg);
    }
    ck_assert_msg(storage_snapshot.has_pin == storage_hasPin(), msg);
    if (storage_snapshot.has_pin) {
        ck_assert_msg(strcmp(storage_snapshot.pin, storage_getPin()) == 0, msg);
    }
    // Ignore has_passphrase since storage_* methods not get it
    ck_assert_msg(storage_snapshot.passphrase_protection == storage_hasPassphraseProtection(), msg);
}

START_TEST(test_reset_initWithInvalidStrength)
{
    storage_wipe();
    take_storage_snapshot();

    bool display_random;
    bool passphrase_protection;
    bool pin_protection;
    bool skip_backup;

    // Test all combinations
    int display_random_count = 0;
    int cnt = 0;
    for (display_random = true; display_random_count < 2; ++display_random_count, display_random = false) {
        int passphrase_protection_count = 0;
        for (passphrase_protection = true; passphrase_protection_count < 2; ++passphrase_protection_count, passphrase_protection = false) {
            int pin_protection_count = 0;
            for (pin_protection = true; pin_protection_count < 2; ++pin_protection_count, pin_protection = false) {
                int skip_backup_count = 0;
                for (skip_backup = true; skip_backup_count < 2; ++skip_backup_count, skip_backup = false) {
                    fprintf(stderr, "Loop %d", ++cnt);
                    reset_init(display_random, 160, passphrase_protection, pin_protection, "english", "lbl", skip_backup);
                    char testMsg[256];
                    sprintf(testMsg, "Invoke reset_init with display_random=%d strength=%d passphrase=%d pin=%d lang=%s label=%s skip_backup=%d",
                            display_random, 160, passphrase_protection, pin_protection, "english", "lbl", skip_backup);
                    assert_storage_snapshot_eq(testMsg);
                }
            }
        }
    }
}
END_TEST

START_TEST(test_reset_initNoPin)
{
    storage_wipe();
    take_storage_snapshot();

    reset_init_ex(false, 128, true, false, "english", "L", true, NULL);
    ck_assert_str_eq(storage_getLanguage(), "english");
    ck_assert_msg(storage_hasPassphraseProtection(), "Passphrase protection should be active");
    ck_assert_str_eq(storage_getLabel(), "L");
}
END_TEST

START_TEST(test_reset_initNoLabel)
{
    storage_wipe();
    ck_assert_ptr_null(storage_getLabel());

    reset_init_ex(false, 128, true, false, "english", "Label", true, NULL);
    ck_assert_str_eq("Label", storage_getLabel());
    reset_init_ex(false, 128, true, false, "english", "", true, NULL);
    ck_assert_str_eq("Label", storage_getLabel());
}
END_TEST

START_TEST(test_reset_initWrongPin)
{
    storage_wipe();
    ck_assert_ptr_null(storage_getLabel());
    take_storage_snapshot();
    ck_assert_str_eq("", storage_snapshot.label);

    reset_init_ex(false, 128, true, true, "english", "Label1", true, pin_reader_ok);
    ck_assert_str_eq("Label1", storage_getLabel());
    take_storage_snapshot();
    ck_assert_str_eq("Label1", storage_snapshot.label);
    reset_init_ex(false, 128, true, true, "english", NULL, true, pin_reader_wrong);
    assert_storage_snapshot_eq("Invoking reset_init wih wrong PIN changed storage");
}
END_TEST

START_TEST(test_reset_initCorrectPin)
{
    storage_wipe();
    ck_assert_ptr_null(storage_getLabel());

    reset_init_ex(false, 128, true, true, "english", "Label1", true, pin_reader_ok);
    ck_assert_str_eq("Label1", storage_getLabel());
    reset_init_ex(false, 128, true, true, "english", "Label2", true, pin_reader_ok);
    ck_assert_str_eq("Label2", storage_getLabel());
}
END_TEST

TCase *add_reset_tests(TCase *tc) {
    // FIXME: test cases for reset_init_ex with display_random=true (needs mocking of button ACK)
    tcase_add_checked_fixture(tc, setup_tc_reset, teardown_tc_reset);
    tcase_add_test(tc, test_reset_initWithInvalidStrength);
    tcase_add_test(tc, test_reset_initNoPin);
    tcase_add_test(tc, test_reset_initNoLabel);
    tcase_add_test(tc, test_reset_initWrongPin);
    tcase_add_test(tc, test_reset_initCorrectPin);
    return tc;
}

