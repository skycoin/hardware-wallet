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

static uint8_t msg_resp[MSG_OUT_SIZE] __attribute__ ((aligned));

#define setup_tc_fsm setup

void teardown_tc_fsm(void)
{
}

void forceGenerateMnemonic(void) {
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
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
	// TODO(denisacostaq@gmail.com): this kind of "dependency" is maintainable.
	for (int i = 0; i < 130; ++i) {
		ck_assert(is_a_base16_caharacter(resp->signed_message[i]));
	}
}
END_TEST

START_TEST(test_msgSkycoinCheckMessageSignature)
{
	const uint32_t address_n = 1;
	forceGenerateMnemonic();
	SkycoinAddress msgSkyAddress = SkycoinAddress_init_zero;
	msgSkyAddress.address_n = address_n;
	uint8_t msg_resp_addr[MSG_OUT_SIZE] __attribute__ ((aligned)) = {0};
	ResponseSkycoinAddress *respAddress = (ResponseSkycoinAddress *) (void *) msg_resp_addr;
	ErrCode_t err = msgSkycoinAddress(&msgSkyAddress, respAddress);
	ck_assert_int_eq(ErrOk, err);
	ck_assert_int_eq(respAddress->addresses_count, 1);

	char raw_msg[] = {
		"32018964c1ac8c2a536b59dd830a80b9d4ce3bb1ad6a182c13b36240ebf4ec11"};
	SkycoinSignMessage msgSign = SkycoinSignMessage_init_zero;
	strncpy(msgSign.message, raw_msg, sizeof(msgSign.message));
	msgSign.address_n = address_n;
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
	ck_assert(respCheck->has_message);
	// FIXME(denisacostaq@gmail.com): Enable this test.
	// 	int address_diff = strncmp(respAddress->addresses[0], respCheck->message, sizeof(respAddress->addresses[0]));
	// 	ck_assert_int_eq(0, address_diff);
}
END_TEST

// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("firmware");
	TCase *tc = tcase_create("fsm");
	tcase_add_checked_fixture(tc, setup_tc_fsm, teardown_tc_fsm);
	tcase_add_test(tc, test_msgSkycoinSignMessageReturnIsInHex);
	tcase_add_test(tc, test_msgGenerateMnemonicImplOk);
	tcase_add_test(tc, test_msgGenerateMnemonicImplShouldFaildIfItWasDone);
	tcase_add_test(tc, test_msgSkycoinCheckMessageSignature);
	suite_add_tcase(s, tc);
	return s;
}

// run suite
int main(void)
{
	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	if (number_failed == 0) {
		printf("PASSED ALL TESTS\n");
	}
	return number_failed;
}
