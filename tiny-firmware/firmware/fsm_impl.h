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
#include "firmware/error.h"

#define EXTERNAL_ENTROPY_MAX_SIZE 128
#define MNEMONIC_WORD_COUNT_12 12
#define MNEMONIC_WORD_COUNT_24 24

// message methods

#define GET_MSG_POINTER(TYPE, VarName) \
			TYPE *VarName = (TYPE *) (void *) msg_resp; \
			_Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
			memset(VarName, 0, sizeof(TYPE));

#define RESP_INIT(TYPE) GET_MSG_POINTER(TYPE, resp);

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

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic* msg);
ErrCode_t msgEntropyAckImpl(EntropyAck* msg);
void msgSkycoinSignMessageImpl(SkycoinSignMessage* msg,
							ResponseSkycoinSignMessage *msg_resp);
ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, 
										char* signed_message);
ErrCode_t msgSkycoinAddress(SkycoinAddress* msg, ResponseSkycoinAddress *resp);
ErrCode_t msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature* msg, 
										Success *resp);
void msgApplySettings(ApplySettings *msg);
void msgGetFeaturesImpl(Features *resp);

#endif  // __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
