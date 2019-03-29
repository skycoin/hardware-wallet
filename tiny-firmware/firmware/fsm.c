/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <libopencm3/stm32/flash.h>

#include <stdio.h>
#include <inttypes.h>
#include "trezor.h"
#include "fsm.h"
#include "messages.h"
#include "bip32.h"
#include "storage.h"
#include "rng.h"
#include "oled.h"
#include "protect.h"
#include "pinmatrix.h"
#include "layout2.h"
#include "reset.h"
#include "recovery.h"
#include "bip39.h"
#include "memory.h"
#include "usb.h"
#include "util.h"
#include "base58.h"
#include "gettext.h"
#include "skycoin_crypto.h"
#include "skycoin_check_signature.h"
#include "check_digest.h"
#include "fsm_impl.h"
#include "droplet.h"
#include "skyparams.h"

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__ ((aligned));

void fsm_sendSuccess(const char *text)
{
	RESP_INIT(Success);
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char *text)
{
	if (protectAbortedByInitialize) {
		fsm_msgInitialize((Initialize *)0);
		protectAbortedByInitialize = false;
		return;
	}
	RESP_INIT(Failure);
	resp->has_code = true;
	resp->code = code;
	if (!text) {
		switch (code) {
			case FailureType_Failure_UnexpectedMessage:
				text = _("Unexpected message");
				break;
			case FailureType_Failure_ButtonExpected:
				text = _("Button expected");
				break;
			case FailureType_Failure_DataError:
				text = _("Data error");
				break;
			case FailureType_Failure_ActionCancelled:
				text = _("Action cancelled by user");
				break;
			case FailureType_Failure_PinExpected:
				text = _("PIN expected");
				break;
			case FailureType_Failure_PinCancelled:
				text = _("PIN cancelled");
				break;
			case FailureType_Failure_PinInvalid:
				text = _("PIN invalid");
				break;
			case FailureType_Failure_InvalidSignature:
				text = _("Invalid signature");
				break;
			case FailureType_Failure_ProcessError:
				text = _("Process error");
				break;
			case FailureType_Failure_NotEnoughFunds:
				text = _("Not enough funds");
				break;
			case FailureType_Failure_NotInitialized:
				text = _("Device not initialized");
				break;
			case FailureType_Failure_PinMismatch:
				text = _("PIN mismatch");
				break;
			case FailureType_Failure_FirmwareError:
				text = _("Firmware error");
				break;
			case FailureType_Failure_AddressGeneration:
				text = _("Failed to generate address");
				break;
		}
	}
	if (text) {
		resp->has_message = true;
		strlcpy(resp->message, text, sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Failure, resp);
}

void fsm_msgInitialize(Initialize *msg)
{
    recovery_abort();
	if (msg && msg->has_state && msg->state.size == 64) {
		uint8_t i_state[64];
		if (!session_getState(msg->state.bytes, i_state, NULL)) {
			session_clear(false); // do not clear PIN
		} else {
			if (0 != memcmp(msg->state.bytes, i_state, 64)) {
				session_clear(false); // do not clear PIN
			}
		}
	} else {
		session_clear(false); // do not clear PIN
	}
	layoutHome();
	fsm_msgGetFeatures(0);
}

void fsm_msgApplySettings(ApplySettings *msg)
{
	CHECK_PIN
	if (msgApplySettings(msg) != ErrOk) {
		fsm_sendFailure(FailureType_Failure_DataError, _("Action cancelled by user"));
	} else {
		fsm_sendSuccess(_("Settings applied"));
	}
	layoutHome();
}

void fsm_msgGetFeatures(GetFeatures *msg)
{
	(void)msg;
	RESP_INIT(Features);
	msgGetFeaturesImpl(resp);
	msg_write(MessageType_MessageType_Features, resp);
}

void fsm_msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature* msg)
{
	GET_MSG_POINTER(Success, successResp);
	if ( msgSkycoinCheckMessageSignature(msg, successResp) == ErrOk) {
		msg_write(MessageType_MessageType_Success, successResp);
	} else {
		fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Invalid signature"));
	}
	layoutHome();
}

int fsm_getKeyPairAtIndex(uint32_t nbAddress, uint8_t* pubkey, uint8_t* seckey, ResponseSkycoinAddress* respSkycoinAddress, uint32_t start_index)
{
    const char* mnemo = storage_getFullSeed();
    uint8_t seed[33] = {0};
    uint8_t nextSeed[SHA256_DIGEST_LENGTH] = {0};
	size_t size_address = 36;
    if (mnemo == NULL || nbAddress == 0)
    {
        return -1;
    }
	generate_deterministic_key_pair_iterator((const uint8_t *)mnemo, strlen(mnemo), nextSeed, seckey, pubkey);
	if (respSkycoinAddress != NULL && start_index == 0) {
		generate_base58_address_from_pubkey(pubkey, respSkycoinAddress->addresses[0], &size_address);
		respSkycoinAddress->addresses_count++;
	}
	memcpy(seed, nextSeed, 32);
	for (uint32_t i = 0; i < nbAddress + start_index - 1; ++i)
	{
		generate_deterministic_key_pair_iterator(seed, 32, nextSeed, seckey, pubkey);
		memcpy(seed, nextSeed, 32);
		seed[32] = 0;
		if (respSkycoinAddress != NULL && ((i + 1) >= start_index)) {
			size_address = 36;
			generate_base58_address_from_pubkey(pubkey, respSkycoinAddress->addresses[respSkycoinAddress->addresses_count], &size_address);
			respSkycoinAddress->addresses_count++;
		}
	}
    return 0;
}

void fsm_msgTransactionSign(TransactionSign* msg) {

	CHECK_MNEMONIC
	CHECK_INPUTS(msg)
	CHECK_OUTPUTS(msg)

	if ( msgTransactionSign(msg) == ErrPinRequired ) {
		fsm_sendFailure(FailureType_Failure_PinExpected, _("Expected pin"));
		layoutHome();
	}

}

void fsm_msgSkycoinSignMessage(SkycoinSignMessage *msg)
{
	RESP_INIT(ResponseSkycoinSignMessage);
	msgSkycoinSignMessageImpl(msg, resp);
	layoutHome();
}

void fsm_msgSkycoinAddress(SkycoinAddress* msg)
{
	RESP_INIT(ResponseSkycoinAddress);
	if (msgSkycoinAddress(msg, resp) == ErrOk) {
		msg_write(MessageType_MessageType_ResponseSkycoinAddress, resp);
	}
	layoutHome();
}

void fsm_msgPing(Ping *msg)
{
	msgPing(msg);
	layoutHome();
}

void fsm_msgChangePin(ChangePin *msg)
{
	msgChangePinImpl(msg);
	layoutHome();
}

void fsm_msgWipeDevice(WipeDevice *msg)
{
	msgWipeDeviceImpl(msg);
	layoutHome();
}

void fsm_msgGenerateMnemonic(GenerateMnemonic* msg) {
	GET_MSG_POINTER(EntropyRequest, entropy_request);
	switch (msgGenerateMnemonicImpl(msg, &random_buffer)) {
		case ErrOk:
			fsm_sendSuccess(_("Mnemonic successfully configured"));
			break;
		case ErrInvalidArg:
			fsm_sendFailure(
						FailureType_Failure_DataError,
						_("Invalid word count expecified, the valid options are"
						" 12 or 24."));
			break;
		case ErrLowEntropy:
			msg_write(MessageType_MessageType_EntropyRequest, entropy_request);
			break;
		case ErrInvalidValue:
			fsm_sendFailure(
						FailureType_Failure_ProcessError,
						_("Device could not generate a valid Mnemonic"));
			break;
		default:
			fsm_sendFailure(FailureType_Failure_FirmwareError,
							_("Mnemonic generation failed"));
			break;
	}
	layoutHome();
}

void fsm_msgSetMnemonic(SetMnemonic* msg)
{
	CHECK_NOT_INITIALIZED
	msgSetMnemonicImpl(msg);
	layoutHome();
}

void fsm_msgGetEntropy(GetEntropy *msg)
{
	msgGetEntropyImpl(msg);
	layoutHome();
}

void fsm_msgLoadDevice(LoadDevice *msg)
{
	CHECK_NOT_INITIALIZED
	msgLoadDeviceImpl(msg);
	layoutHome();
}

void fsm_msgResetDevice(ResetDevice *msg)
{
	CHECK_NOT_INITIALIZED

	CHECK_PARAM(!msg->has_strength || msg->strength == 128 || msg->strength == 192 || msg->strength == 256, _("Invalid seed strength"));

	reset_init(
		msg->has_display_random && msg->display_random,
		msg->has_strength ? msg->strength : 128,
		msg->has_passphrase_protection && msg->passphrase_protection,
		msg->has_pin_protection && msg->pin_protection,
		msg->has_language ? msg->language : 0,
		msg->has_label ? msg->label : 0,
		msg->has_skip_backup ? msg->skip_backup : false
	);
}

void fsm_msgBackupDevice(BackupDevice *msg)
{
	CHECK_INITIALIZED
	CHECK_PIN_UNCACHED
	msgBackupDeviceImpl(msg);
	layoutHome();
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg)
{
	msgRecoveryDeviceImpl(msg);
	layoutHome();
}

void fsm_msgWordAck(WordAck *msg)
{
	recovery_word(msg->word);
}

void fsm_msgCancel(Cancel *msg)
{
	(void)msg;
	recovery_abort();
	fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
}

void fsm_msgEntropyAck(EntropyAck *msg)
{
	switch (msgEntropyAckImpl(msg)) {
		case ErrOk:
			fsm_sendSuccess(_("Recived entropy"));
			break;
		case ErrInvalidValue:
			fsm_sendFailure(
						FailureType_Failure_ProcessError,
						_("Device could not generate a valid Mnemonic"));
			break;
		case ErrUnexpectedMessage:
			fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
							_("Unexpected entropy ack msg."));
			break;
		default:
			fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
							_("Entropy ack failed."));
	}
	layoutHome();
}
