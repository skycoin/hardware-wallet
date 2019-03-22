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
	if (msg->has_label && strlen(msg->label)) {
		layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change name to"), msg->label, "?", NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
	} else {
		msg->has_label = false;
	}
	if (msg->has_language && strlen(msg->language)) {
		layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change language to"), msg->language, "?", NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
	} else {
		msg->has_language = false;
	}
	if (msg->has_use_passphrase) {
		layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), msg->use_passphrase ? _("enable passphrase") : _("disable passphrase"), _("protection?"), NULL, NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
	}
	if (msg->has_homescreen) {
		layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change the home"), _("screen?"), NULL, NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
	}
	msgApplySettings(msg);
	fsm_sendSuccess(_("Settings applied"));
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
	GET_MSG_POINTER(Failure, failureResp);
	if (msgSkycoinCheckMessageSignatureImpl(msg, successResp, failureResp)
			== ErrOk) {
		msg_write(MessageType_MessageType_Success, successResp);
	} else {
		failureResp->code = FailureType_Failure_InvalidSignature;
		msg_write(MessageType_MessageType_Failure, failureResp);
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

	if (storage_hasMnemonic() == false) {
		fsm_sendFailure(FailureType_Failure_AddressGeneration, "Mnemonic not set");
		return;
	}

	if (msg->nbIn > 8) {
		fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Cannot have more than 8 inputs"));
		return;
	}
	if (msg->nbOut > 8) {
		fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Cannot have more than 8 outputs"));
		return;
	}
#if EMULATOR
	printf("%s: %d. nbOut: %d\n",
		_("Transaction signed nbIn"),
		msg->nbIn, msg->nbOut);

	for (uint32_t i = 0; i < msg->nbIn; ++i) {
		printf("Input: addressIn: %s, index: %d\n",
			msg->transactionIn[i].hashIn, msg->transactionIn[i].index);
	}
	for (uint32_t i = 0; i < msg->nbOut; ++i) {
		printf("Output: coin: %" PRIu64 ", hour: %" PRIu64 " address: %s address_index: %d\n",
			msg->transactionOut[i].coin, msg->transactionOut[i].hour,
			msg->transactionOut[i].address, msg->transactionOut[i].address_index);
	}
#endif
	Transaction transaction;
	transaction_initZeroTransaction(&transaction);
	for (uint32_t i = 0; i < msg->nbIn; ++i) {
		uint8_t hashIn[32];
		writebuf_fromhexstr(msg->transactionIn[i].hashIn, hashIn);
		transaction_addInput(&transaction, hashIn);
	}
	for (uint32_t i = 0; i < msg->nbOut; ++i) {
		char strHour[30];
		char strCoin[30];
		char strValue[20];
		char *coinString = msg->transactionOut[i].coin == 1000000 ? _("coin") : _("coins");
		char *hourString = (msg->transactionOut[i].hour == 1 || msg->transactionOut[i].hour == 0) ? _("hour") : _("hours");
		char *strValueMsg = sprint_coins(msg->transactionOut[i].coin, SKYPARAM_DROPLET_PRECISION_EXP, sizeof(strValue), strValue);
		if (strValueMsg == NULL) {
			// FIXME: For Skycoin coin supply and precision buffer size should be enough
			strcpy(strCoin, "too many coins");
		}
		sprintf(strCoin, "%s %s %s", _("send"), strValueMsg, coinString);
		sprintf(strHour, "%" PRIu64 " %s", msg->transactionOut[i].hour, hourString);

		if (msg->transactionOut[i].has_address_index) {
			uint8_t pubkey[33] = {0};
			uint8_t seckey[32] = {0};
			size_t size_address = 36;
			char address[36] = {0};
			fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, msg->transactionOut[i].address_index);
			generate_base58_address_from_pubkey(pubkey, address, &size_address);
			if (strcmp(msg->transactionOut[i].address, address) != 0)
			{
					fsm_sendFailure(FailureType_Failure_AddressGeneration, _("Wrong return address"));
					#if EMULATOR
					printf("Internal address: %s, message address: %s\n", address, msg->transactionOut[i].address);
					printf("Comparaison size %ld\n", size_address);
					#endif
					return;
			}
		} else {
			layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Next"), NULL, _("Do you really want to"), strCoin, strHour, _("to address"), _("..."), NULL);
			if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				layoutHome();
				return;
			}
			layoutAddress(msg->transactionOut[i].address);
			if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
				fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
				layoutHome();
				return;
			}
		}
		transaction_addOutput(&transaction, msg->transactionOut[i].coin, msg->transactionOut[i].hour, msg->transactionOut[i].address);
	}

	CHECK_PIN_UNCACHED
	RESP_INIT(ResponseTransactionSign);
	for (uint32_t i = 0; i < msg->nbIn; ++i) {
		uint8_t digest[32];
    	transaction_msgToSign(&transaction, i, digest);
    	if (msgSignTransactionMessageImpl(digest, msg->transactionIn[i].index, resp->signatures[resp->signatures_count]) != ErrOk) {
			fsm_sendFailure(FailureType_Failure_InvalidSignature, NULL);
    		return;
    	}
		resp->signatures_count++;
#if EMULATOR
		char str[64];
		tohex(str, (uint8_t*)digest, 32);
		printf("Signing message:  %s\n", str);
		printf("Signed message:  %s\n", resp->signatures[i]);
		printf("Nb signatures: %d\n", resp->signatures_count);
#endif
	}
#if EMULATOR
	char str[64];
	tohex(str, transaction.innerHash, 32);
	printf("InnerHash %s\n", str);
	printf("Signed message:  %s\n", resp->signatures[0]);
	printf("Nb signatures: %d\n", resp->signatures_count);
#endif
    msg_write(MessageType_MessageType_ResponseTransactionSign, resp);
	layoutHome();
}

void fsm_msgSkycoinSignMessage(SkycoinSignMessage *msg)
{
	RESP_INIT(ResponseSkycoinSignMessage);
	msgSkycoinSignMessageImpl(msg, resp);
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
	RESP_INIT(Success);

	if (msg->has_button_protection && msg->button_protection) {
		layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("answer to ping?"), NULL, NULL, NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
	}

	if (msg->has_pin_protection && msg->pin_protection) {
		CHECK_PIN
	}

	if (msg->has_passphrase_protection && msg->passphrase_protection) {
		if (!protectPassphrase()) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			return;
		}
	}

	if (msg->has_message) {
		resp->has_message = true;
		memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
	layoutHome();
}

void fsm_msgChangePin(ChangePin *msg)
{
	bool removal = msg->has_remove && msg->remove;
	if (removal) {
		if (storage_hasPin()) {
			layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("remove current PIN?"), NULL, NULL, NULL, NULL);
		} else {
			fsm_sendSuccess(_("PIN removed"));
			return;
		}
	} else {
		if (storage_hasPin()) {
			layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("change current PIN?"), NULL, NULL, NULL, NULL);
		} else {
			layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("set new PIN?"), NULL, NULL, NULL, NULL);
		}
	}
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}

	CHECK_PIN_UNCACHED

	if (removal) {
		storage_setPin("");
		storage_update();
		fsm_sendSuccess(_("PIN removed"));
	} else {
		if (protectChangePin()) {
			fsm_sendSuccess(_("PIN changed"));
		} else {
			fsm_sendFailure(FailureType_Failure_PinMismatch, NULL);
		}
	}
	layoutHome();
}

void fsm_msgWipeDevice(WipeDevice *msg)
{
	(void)msg;
	layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("wipe the device?"), NULL, _("All data will be lost."), NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}
	storage_wipe();
	// the following does not work on Mac anyway :-/ Linux/Windows are fine, so it is not needed
	// usbReconnect(); // force re-enumeration because of the serial number change
	fsm_sendSuccess(_("Device wiped"));
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

	RESP_INIT(Success);
	layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL, _("Writing seed"), _("is not recommended."), _("Continue only if you"), _("know what you are"), _("doing!"), NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}
	if (!mnemonic_check(msg->mnemonic)) {
		fsm_sendFailure(FailureType_Failure_DataError, _("Mnemonic with wrong checksum provided"));
		layoutHome();
		return;
	}
	storage_setMnemonic(msg->mnemonic);
	storage_setNeedsBackup(true);
	storage_update();
	fsm_sendSuccess(_(msg->mnemonic));
	layoutHome();
}

void fsm_msgGetEntropy(GetEntropy *msg)
{
	layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("send entropy?"), NULL, NULL, NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}

	RESP_INIT(Entropy);
	uint32_t len = msg->size;
	if (len > 1024) {
		len = 1024;
	}
	resp->entropy.size = len;
	random_buffer(resp->entropy.bytes, len);
	msg_write(MessageType_MessageType_Entropy, resp);
	layoutHome();
}

void fsm_msgLoadDevice(LoadDevice *msg)
{
	CHECK_NOT_INITIALIZED

	layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL, _("Loading private seed"), _("is not recommended."), _("Continue only if you"), _("know what you are"), _("doing!"), NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}

	if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum) ) {
		if (!mnemonic_check(msg->mnemonic)) {
			fsm_sendFailure(FailureType_Failure_DataError, _("Mnemonic with wrong checksum provided"));
			layoutHome();
			return;
		}
	}

	storage_loadDevice(msg);
	fsm_sendSuccess(_("Device loaded"));
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

	(void)msg;
	if (!storage_needsBackup()) {
		fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Seed already backed up"));
		return;
	}
	reset_backup(true);

	layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you confirm you"), _("backed up your seed."), _("This will never be"), _("possible again."), NULL, NULL);
	if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
		layoutHome();
		return;
	}
	if (storage_unfinishedBackup()) {
		fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Backup operation did not finish properly."));
		layoutHome();
		return;
	}
	storage_setNeedsBackup(false);
	storage_update();
	fsm_sendSuccess(_("Device backed up!"));
	layoutHome();
}

void fsm_msgRecoveryDevice(RecoveryDevice *msg)
{
	const bool dry_run = msg->has_dry_run ? msg->dry_run : false;
	if (dry_run) {
		CHECK_PIN
	} else {
		CHECK_NOT_INITIALIZED
	}

	CHECK_PARAM(!msg->has_word_count || msg->word_count == 12
			|| msg->word_count == 24, _("Invalid word count"));

	if (!dry_run) {
		layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"), _("recover the device?"), NULL, NULL, NULL, NULL);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return;
		}
	}
	recovery_init(
		msg->has_word_count ? msg->word_count : 12,
		msg->has_passphrase_protection && msg->passphrase_protection,
		msg->has_pin_protection && msg->pin_protection,
		msg->has_language ? msg->language : 0,
		msg->has_label ? msg->label : 0,
		dry_run
	);
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
