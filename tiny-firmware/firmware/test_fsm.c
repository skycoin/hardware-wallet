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
#include <stdlib.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include <check.h>

#include "fsm_impl.h"
#include "messages.pb.h"
#include "messages.h"
#include "setup.h"
#include "storage.h"

#include "test_fsm.h"

static uint8_t msg_resp[MSG_OUT_SIZE] __attribute__ ((aligned));

#define setup_tc_fsm setup

void teardown_tc_fsm(void)
{
}

void forceGenerateMnemonic(void) {
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	msg.word_count = 12;
	msgGenerateMnemonicImpl(&msg);
}

bool is_a_base16_caharacter(char c) {
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
		return true;
	}
	return false;
}

START_TEST(test_msgGenerateMnemonicImplOk)
{
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	msg.word_count = 12;
	ErrCode_t ret = msgGenerateMnemonicImpl(&msg);
	ck_assert_int_eq(ErrOk, ret);
}
END_TEST

START_TEST(test_msgGenerateMnemonicImplShouldFaildIfItWasDone)
{
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	msgGenerateMnemonicImpl(&msg);
	ErrCode_t ret = msgGenerateMnemonicImpl(&msg);
	ck_assert_int_eq(ErrFailed, ret);
}
END_TEST

START_TEST(test_msgSkycoinSignMessageReturnIsInHex)
{
	forceGenerateMnemonic();
	char raw_msg[] = {
		"32018964c1ac8c2a536b59dd830a80b9d4ce3bb1ad6a182c13b36240ebf4ec11"};
	SkycoinSignMessage msg = SkycoinSignMessage_init_zero;
	strncpy(msg.message, raw_msg, sizeof(msg.message));
	RESP_INIT(ResponseSkycoinSignMessage);
	msgSkycoinSignMessageImpl(&msg, resp);
	// NOTE(denisacostaq@gmail.com): ecdsa signature have 65 bytes,
	// 2 for each one in hex = 130
	// TODO(denisacostaq@gmail.com): this kind of "dependency" is not maintainable.
	for (size_t i = 0; i < sizeof(resp->signed_message); ++i) {
		ck_assert(is_a_base16_caharacter(resp->signed_message[i]));
	}
}
END_TEST

START_TEST(test_msgSkycoinCheckMessageSignature)
{
    // NOTE(denisacostaq@gmail.com): Given
    forceGenerateMnemonic();
    SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
    msgSkyAddress.address_n = 1;
    uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
    ResponseSkycoinAddress *respAddress = (ResponseSkycoinAddress *) (void *) msg_resp_addr;
    ErrCode_t err = msgSkycoinAddress(&msgSkyAddress, respAddress);
    ck_assert_int_eq(ErrOk, err);
    ck_assert_int_eq(respAddress->addresses_count, 1);
    // NOTE(denisacostaq@gmail.com): `raw_msg` hash become from:
    // https://github.com/skycoin/skycoin/blob/develop/src/cipher/testsuite/testdata/input-hashes.golden
    char raw_msg[] = {
    "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"};
    SkycoinSignMessage msgSign = SkycoinSignMessage_init_zero;
    strncpy(msgSign.message, raw_msg, sizeof(msgSign.message));
    msgSign.address_n = 0;
    
    // NOTE(denisacostaq@gmail.com): When
    uint8_t msg_resp_sign[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
    ResponseSkycoinSignMessage *respSign = (ResponseSkycoinSignMessage *) (void *) msg_resp_sign;
    msgSkycoinSignMessageImpl(&msgSign, respSign);
    SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
    strncpy(checkMsg.message, msgSign.message, sizeof(checkMsg.message));
    memcpy(checkMsg.address, respAddress->addresses[0], sizeof(checkMsg.address));
    memcpy(checkMsg.signature, respSign->signed_message, sizeof(checkMsg.signature));
    uint8_t msg_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
    Success *respCheck = (Success *) (void *) msg_resp_check;
    msgSkycoinCheckMessageSignature(&checkMsg, respCheck);
    
    // NOTE(denisacostaq@gmail.com): Then
    ck_assert(respCheck->has_message);
    int address_diff = strncmp(respAddress->addresses[0], respCheck->message,
	        sizeof(respAddress->addresses[0]));
    if (address_diff) {
        fprintf(stderr, "\nrespAddress->addresses[0]: ");
        for (size_t i = 0; i < sizeof(respAddress->addresses[0]); ++i) {
			fprintf(stderr, "%c", respAddress->addresses[0][i]);
		}
		fprintf(stderr, "\nrespCheck->message: ");
		for (size_t i = 0; i < sizeof(respCheck->message); ++i) {
			fprintf(stderr, "%c", respCheck->message[i]);
		}
		fprintf(stderr, "\n");
    }
    ck_assert_int_eq(0, address_diff);
}
END_TEST

START_TEST(test_msgGetFeatures)
{
	RESP_INIT(Features);
	msgGetFeaturesImpl(resp);
	ck_assert_int_eq(resp->has_fw_major, 1);
	ck_assert_int_eq(resp->has_fw_minor, 1);
	ck_assert_int_eq(resp->has_fw_patch, 1);
	ck_assert_int_eq(VERSION_MAJOR, resp->fw_major);
	ck_assert_int_eq(VERSION_MINOR, resp->fw_minor);
	ck_assert_int_eq(VERSION_PATCH, resp->fw_patch);
}
END_TEST

// define test cases
TCase *add_fsm_tests(TCase *tc)
{
	tcase_add_checked_fixture(tc, setup_tc_fsm, teardown_tc_fsm);
	tcase_add_test(tc, test_msgSkycoinSignMessageReturnIsInHex);
	tcase_add_test(tc, test_msgGenerateMnemonicImplOk);
	tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFaildIfItWasDone);
	tcase_add_test(tc, test_msgSkycoinCheckMessageSignature);
	tcase_add_test(tc, test_msgGetFeatures);
	return tc;
}
