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
	fsm_msgGenerateMnemonicImpl(&msg);
}

bool is_a_base16_caharacter(char c) {
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
		return true;
	}
	return false;
}

START_TEST(test_fsm_msgGenerateMnemonicImplOk)
{
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	ErrCode_t ret = fsm_msgGenerateMnemonicImpl(&msg);
	ck_assert_int_eq(ret, ErrOk);
}
END_TEST

START_TEST(test_fsm_msgGenerateMnemonicImplShouldFaildIfItWasDone)
{
	storage_wipe();
	GenerateMnemonic msg = GenerateMnemonic_init_zero;
	fsm_msgGenerateMnemonicImpl(&msg);
	ErrCode_t ret = fsm_msgGenerateMnemonicImpl(&msg);
	ck_assert_int_eq(ret, ErrFailed);
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
	fsm_msgSkycoinSignMessageImpl(&msg, resp);
	// NOTE(denisacostaq@gmail.com): ecdsa signature have 65 bytes,
	// 2 for each one in hex = 130
	// TODO(denisacostaq@gmail.com): this kind of "dependency" is maintainable.
	for (int i = 0; i < 130; ++i) {
		ck_assert(is_a_base16_caharacter(resp->signed_message[i]));
	}
}
END_TEST

// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("firmware");
	TCase *tc = tcase_create("fsm");
	tcase_add_checked_fixture(tc, setup_tc_fsm, teardown_tc_fsm);
	tcase_add_test(tc, test_msgSkycoinSignMessageReturnIsInHex);
	tcase_add_test(tc, test_fsm_msgGenerateMnemonicImplOk);
	tcase_add_test(tc, test_fsm_msgGenerateMnemonicImplShouldFaildIfItWasDone);
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
