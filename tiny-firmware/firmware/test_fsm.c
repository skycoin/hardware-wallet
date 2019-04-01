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
#include <time.h>

#include <pb_encode.h>
#include <pb_decode.h>
#include <check.h>

#include "fsm_impl.h"
#include "messages.pb.h"
#include "messages.h"
#include "setup.h"
#include "storage.h"
#include "rng.h"

#include "test_fsm.h"

static uint8_t msg_resp[MSG_OUT_SIZE] __attribute__ ((aligned));

void setup_tc_fsm(void) {
	srand(time(NULL));
	setup();
}

void teardown_tc_fsm(void) {
}

void forceGenerateMnemonic(void) {
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	msg.word_count = MNEMONIC_WORD_COUNT_12;
	msg.has_word_count = true;
	ck_assert_int_eq(ErrOk, msgGenerateMnemonicImpl(&msg, &random_buffer));
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
	msg.word_count = MNEMONIC_WORD_COUNT_12;
	msg.has_word_count = true;
	ErrCode_t ret = msgGenerateMnemonicImpl(&msg, &random_buffer);
	ck_assert_int_eq(ErrOk, ret);
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
	ck_assert_int_eq(ErrFailed, ret);
}
END_TEST

START_TEST(test_msgGenerateMnemonicImplShouldFailForWrongSeedCount)
{
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	msg.has_word_count = true;
	msg.word_count = MNEMONIC_WORD_COUNT_12 + 1;
	ErrCode_t ret = msgGenerateMnemonicImpl(&msg, &random_buffer);
	ck_assert_int_eq(ErrInvalidArg, ret);
}
END_TEST

START_TEST(test_msgEntropyAckImplFailAsExpectedForSyncProblemInProtocol)
{
	storage_wipe();
	EntropyAck msg = EntropyAck_init_zero;
	msg.has_entropy = true;
	char entropy[EXTERNAL_ENTROPY_MAX_SIZE] = {0};
	memcpy(msg.entropy.bytes, entropy, sizeof (entropy));
	ErrCode_t ret = msgEntropyAckImpl(&msg/*, &random_buffer*/);
	ck_assert_int_eq(ErrUnexpectedMessage, ret);
}
END_TEST

static void random_buffer_with_low_entropy(uint8_t *buf, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		buf[i] = i % 5;
	}
}

START_TEST(test_msgGenerateMnemonicEntropyAckSequenceShouldBeOk)
{
	storage_wipe();
	GenerateMnemonic gnMsg = GenerateMnemonic_init_zero;
	ck_assert_int_eq(
		ErrLowEntropy, 
		msgGenerateMnemonicImpl(&gnMsg, &random_buffer_with_low_entropy));
	EntropyAck eaMsg = EntropyAck_init_zero;
	eaMsg.has_entropy = true;
	random_buffer(eaMsg.entropy.bytes, 32);
	ck_assert_int_eq(ErrOk, msgEntropyAckImpl(&eaMsg));
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

START_TEST(test_msgSkycoinCheckMessageSignatureOk)
{
	// NOTE(denisacostaq@gmail.com): Given
	forceGenerateMnemonic();
	SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
	msgSkyAddress.address_n = 1;
	uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	ResponseSkycoinAddress *respAddress = (ResponseSkycoinAddress *) (void *) msg_resp_addr;
	ErrCode_t err = msgSkycoinAddressImpl(&msgSkyAddress, respAddress);
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
	uint8_t msg_success_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	uint8_t msg_fail_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	Success *successRespCheck = (Success *) (void *) msg_success_resp_check;
	Failure *failRespCheck = (Failure *) (void *) msg_fail_resp_check;
	err = msgSkycoinCheckMessageSignatureImpl(&checkMsg, successRespCheck, failRespCheck);

	// NOTE(denisacostaq@gmail.com): Then
	ck_assert_int_eq(ErrOk, err);
	ck_assert(successRespCheck->has_message);
	int address_diff = strncmp(
		respAddress->addresses[0],
		successRespCheck->message,
		sizeof(respAddress->addresses[0]));
	if (address_diff) {
		fprintf(stderr, "\nrespAddress->addresses[0]: ");
		for (size_t i = 0; i < sizeof(respAddress->addresses[0]); ++i) {
			fprintf(stderr, "%c", respAddress->addresses[0][i]);
		}
		fprintf(stderr, "\nrespCheck->message: ");
		for (size_t i = 0; i < sizeof(successRespCheck->message); ++i) {
			fprintf(stderr, "%c", successRespCheck->message[i]);
		}
		fprintf(stderr, "\n");
	}
	ck_assert_int_eq(0, address_diff);
}
END_TEST

static void swap_char(char *ch1, char *ch2) {
	char tmp;
	memcpy((void*)&tmp, (void*)ch1, sizeof (tmp));
	memcpy((void*)ch1, (void*)ch2, sizeof (*ch1));
	memcpy((void*)ch2, (void*)&tmp, sizeof (tmp));
}

static void random_shuffle(char *buffer, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		size_t rIndex = (size_t)rand() % len;
		swap_char(&buffer[i], &buffer[rIndex]);
	}
}

START_TEST(test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidSignedMessage)
{
	// NOTE(denisacostaq@gmail.com): Given
	forceGenerateMnemonic();
	SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
	msgSkyAddress.address_n = 1;
	uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	ResponseSkycoinAddress *respAddress = (ResponseSkycoinAddress *) (void *) msg_resp_addr;
	ErrCode_t err = msgSkycoinAddressImpl(&msgSkyAddress, respAddress);
	ck_assert_int_eq(ErrOk, err);
	ck_assert_int_eq(respAddress->addresses_count, 1);
	// NOTE(denisacostaq@gmail.com): `raw_msg` hash become from:
	// https://github.com/skycoin/skycoin/blob/develop/src/cipher/testsuite/testdata/input-hashes.golden
	char raw_msg[] = {"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"};
	SkycoinSignMessage msgSign = SkycoinSignMessage_init_zero;
	strncpy(msgSign.message, raw_msg, sizeof(msgSign.message));
	msgSign.address_n = 0;

	// NOTE(denisacostaq@gmail.com): When
	uint8_t msg_resp_sign[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	ResponseSkycoinSignMessage *respSign = (ResponseSkycoinSignMessage *) (void *) msg_resp_sign;
	msgSkycoinSignMessageImpl(&msgSign, respSign);
	// NOTE(denisaostaq@gmail.com): An attacker change our msg signature.
	random_shuffle(respSign->signed_message, sizeof (respSign->signed_message));
	SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
	strncpy(checkMsg.message, msgSign.message, sizeof(checkMsg.message));
	memcpy(checkMsg.address, respAddress->addresses[0], sizeof(checkMsg.address));
	memcpy(checkMsg.signature, respSign->signed_message, sizeof(checkMsg.signature));
	uint8_t msg_success_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	uint8_t msg_fail_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	Success *successRespCheck = (Success *) (void *) msg_success_resp_check;
	Failure *failRespCheck = (Failure *) (void *) msg_fail_resp_check;
	err = msgSkycoinCheckMessageSignatureImpl(&checkMsg, successRespCheck, failRespCheck);

	// NOTE(denisacostaq@gmail.com): Then
	ck_assert_int_ne(ErrOk, err);
	ck_assert(failRespCheck->has_message);
	int address_diff = strncmp(
		respAddress->addresses[0], 
		successRespCheck->message,
		sizeof(respAddress->addresses[0]));
	ck_assert_int_ne(0, address_diff);
}
END_TEST

START_TEST(test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidMessage)
{
	// NOTE(denisacostaq@gmail.com): Given
	forceGenerateMnemonic();
	SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
	msgSkyAddress.address_n = 1;
	uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	ResponseSkycoinAddress *respAddress = (ResponseSkycoinAddress *) (void *) msg_resp_addr;
	ErrCode_t err = msgSkycoinAddressImpl(&msgSkyAddress, respAddress);
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
	// NOTE(denisaostaq@gmail.com): An attacker change our msg(hash).
	random_shuffle(msgSign.message, sizeof (msgSign.message));
	SkycoinCheckMessageSignature checkMsg = SkycoinCheckMessageSignature_init_zero;
	strncpy(checkMsg.message, msgSign.message, sizeof(checkMsg.message));
	memcpy(checkMsg.address, respAddress->addresses[0], sizeof(checkMsg.address));
	memcpy(checkMsg.signature, respSign->signed_message, sizeof(checkMsg.signature));
	uint8_t msg_success_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	uint8_t msg_fail_resp_check[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	Success *successRespCheck = (Success *) (void *) msg_success_resp_check;
	Failure *failRespCheck = (Failure *) (void *) msg_fail_resp_check;
	err = msgSkycoinCheckMessageSignatureImpl(&checkMsg, successRespCheck, failRespCheck);

	// NOTE(denisacostaq@gmail.com): Then
	ck_assert_int_ne(ErrOk, err);
	ck_assert(failRespCheck->has_message);
	int address_diff = strncmp(
		respAddress->addresses[0], 
		successRespCheck->message,
		sizeof(respAddress->addresses[0]));
	ck_assert_int_ne(0, address_diff);
}
END_TEST

START_TEST(test_msgApplySettingsLabelSuccess)
{
	storage_wipe();
	char raw_label[] = {
		"my custom device label"};
	ApplySettings msg = ApplySettings_init_zero;
	msg.has_label = true;
	strncpy(msg.label, raw_label, sizeof(msg.label));
	msgApplySettingsImpl(&msg);
	ck_assert_int_eq(storage_hasLabel(), true);
	ck_assert_str_eq(storage_getLabel(), raw_label);
}
END_TEST

START_TEST(test_msgApplySettingsLabelShouldNotBeRemovable)
{
	storage_wipe();
	char raw_label[] = {
		"my custom device label"};
	ApplySettings msg = ApplySettings_init_zero;
	msg.has_use_passphrase = true;
	msg.use_passphrase = false;
	msg.has_label = true;
	strncpy(msg.label, raw_label, sizeof(msg.label));
	msgApplySettingsImpl(&msg);
	ck_assert(!storage_hasPassphraseProtection());
	ck_assert_int_eq(storage_hasLabel(), true);
	ck_assert_str_eq(storage_getLabel(), raw_label);
	msg.has_label = false;
	memset(msg.label, 0, sizeof(msg.label));
	msg.has_use_passphrase = true;
	msg.use_passphrase = true;
	msgApplySettingsImpl(&msg);
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
	msgApplySettingsImpl(&msg);
	ck_assert_int_eq(storage_hasLabel(), true);
}
END_TEST

START_TEST(test_msgFeaturesLabelDefaultsToDeviceId)
{
	storage_wipe();
	const char *label = storage_getLabelOrDeviceId();
	ck_assert_str_eq(storage_uuid_str, label);
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
	tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFailIfItWasDone);
	tcase_add_test(tc, test_msgSkycoinCheckMessageSignatureOk);
	tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFailForWrongSeedCount);
	tcase_add_test(
		tc,
		test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidSignedMessage);
	tcase_add_test(
		tc, 
		test_msgSkycoinCheckMessageSignatureFailedAsExpectedForInvalidMessage);
	tcase_add_test(tc, test_msgApplySettingsLabelSuccess);
	tcase_add_test(tc, test_msgFeaturesLabelDefaultsToDeviceId);
	tcase_add_test(tc, test_msgGetFeatures);
	tcase_add_test(tc, test_msgApplySettingsLabelSuccessCheck);
	tcase_add_test(tc, test_msgApplySettingsLabelShouldNotBeRemovable);
	tcase_add_test(tc, test_msgFeaturesLabelDefaultsToDeviceId);
	tcase_add_test(
		tc, 
		test_msgEntropyAckImplFailAsExpectedForSyncProblemInProtocol);
	tcase_add_test(tc, test_msgGenerateMnemonicEntropyAckSequenceShouldBeOk);
	return tc;
}
