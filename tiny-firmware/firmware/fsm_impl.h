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

#ifndef __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
#define __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__

#include "messages.pb.h"

// message methods

#define RESP_INIT(TYPE) \
			TYPE *resp = (TYPE *) (void *) msg_resp; \
			_Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
			memset(resp, 0, sizeof(TYPE));

#define CHECK_INITIALIZED \
	if (!storage_isInitialized()) { \
		fsm_sendFailure(FailureType_Failure_NotInitialized, NULL); \
		return; \
	}

#define CHECK_NOT_INITIALIZED \
	if (storage_isInitialized()) { \
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first.")); \
		return; \
	}

#define CHECK_NOT_INITIALIZED_RET_ERR_CODE \
	if (storage_isInitialized()) { \
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first.")); \
		return ErrFailed; \
	}

#define CHECK_PIN \
	if (!protectPin(true)) { \
		layoutHome(); \
		return; \
	}

#define CHECK_PIN_RET_ERR_CODE \
	if (!protectPin(true)) { \
		layoutHome(); \
		return ErrFailed; \
	}

#define CHECK_PIN_UNCACHED \
	if (!protectPin(false)) { \
		layoutHome(); \
		return; \
	}

#define CHECK_PARAM(cond, errormsg) \
	if (!(cond)) { \
		fsm_sendFailure(FailureType_Failure_DataError, (errormsg)); \
		layoutHome(); \
		return; \
	}

enum ErrCode{ErrOk = 0, ErrFailed};
typedef enum ErrCode ErrCode_t;

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic* msg);
void msgSkycoinSignMessageImpl(SkycoinSignMessage* msg,
							ResponseSkycoinSignMessage *msg_resp);
ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, 
										char* signed_message);
ErrCode_t msgSkycoinAddress(SkycoinAddress* msg, ResponseSkycoinAddress *resp);
void msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature* msg, Success *resp);
void msgApplySettings(ApplySettings *msg);
void msgGetFeaturesImpl(Features *resp);

#endif  // __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
