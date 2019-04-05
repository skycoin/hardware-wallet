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

#include "fsm_impl.h"

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
#include "entropy.h"

#define MNEMONIC_STRENGTH_12 128
#define MNEMONIC_STRENGTH_24 256
#define INTERNAL_ENTROPY_SIZE 32

uint8_t msg_resp[MSG_OUT_SIZE] __attribute__ ((aligned));

extern bool awaiting_entropy;
extern uint32_t strength;
extern bool     skip_backup;
extern uint8_t  int_entropy[INTERNAL_ENTROPY_SIZE];
static bool has_passphrase_protection;
static bool passphrase_protection;

ErrCode_t msgEntropyAckImpl(EntropyAck* msg) {
	_Static_assert(EXTERNAL_ENTROPY_MAX_SIZE == sizeof(msg->entropy.bytes),
					"External entropy size does not match.");
	const bool skip_backup_saved = skip_backup;
	skip_backup = true;
	ErrCode_t ret;
	if (msg->has_entropy) {
		ret = reset_entropy(msg->entropy.bytes, msg->entropy.size);
	} else {
		ret = reset_entropy(0, 0);
	}
	if (has_passphrase_protection) {
		storage_setPassphraseProtection(passphrase_protection);
		storage_update();
	}
	skip_backup = skip_backup_saved;
	has_passphrase_protection = false;
	return ret;
}

ErrCode_t msgGenerateMnemonicImpl(
		GenerateMnemonic* msg,
		void (*random_buffer_func)(uint8_t *buf, size_t len)) {
	CHECK_NOT_INITIALIZED_RET_ERR_CODE
	strength = MNEMONIC_STRENGTH_12;
	if (msg->has_word_count) {
		switch (msg->word_count) {
			case MNEMONIC_WORD_COUNT_12:
				strength = MNEMONIC_STRENGTH_12;
				break;
			case MNEMONIC_WORD_COUNT_24:
				strength = MNEMONIC_STRENGTH_24;
				break;
			default:
				return ErrInvalidArg;
		}
	}
	random_buffer_func(int_entropy, sizeof(int_entropy));
	if (verify_entropy(int_entropy, sizeof(int_entropy)) != ErrOk) {
		awaiting_entropy = true;
		if (msg->has_passphrase_protection) {
			has_passphrase_protection = msg->has_passphrase_protection;
			passphrase_protection = msg->passphrase_protection;
		}
		return ErrLowEntropy;
	}
	const char* mnemonic = mnemonic_from_data(int_entropy, strength / 8);
	if (mnemonic && mnemonic_check(mnemonic)) {
		storage_setMnemonic(mnemonic);
		storage_setNeedsBackup(true);
		storage_setPassphraseProtection(
					msg->has_passphrase_protection
					&& msg->passphrase_protection);
		memset(int_entropy, 0, sizeof(int_entropy));
		storage_update();
		return ErrOk;
	}
	return ErrInvalidValue;
}


ErrCode_t msgSkycoinSignMessageImpl(SkycoinSignMessage* msg,
								   ResponseSkycoinSignMessage *resp)
{
	CHECK_MNEMONIC_RET_ERR_CODE
	CHECK_PIN_UNCACHED_RET_ERR_CODE
	uint8_t pubkey[33] = {0};
	uint8_t seckey[32] = {0};
	fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, msg->address_n);
	uint8_t digest[32] = {0};
	if (is_digest(msg->message) == false) {
		compute_sha256sum((const uint8_t *)msg->message, digest, strlen(msg->message));
	} else {
		writebuf_fromhexstr(msg->message, digest);
	}
	uint8_t signature[65];
	int res = ecdsa_skycoin_sign(random32(), seckey, digest, signature);
	if (res == 0) {
		layoutRawMessage("Signature success");
	} else {
		layoutRawMessage("Signature failed");
	}
	const size_t hex_len = 2 * sizeof(signature);
	char signature_in_hex[hex_len];
	tohex(signature_in_hex, signature, sizeof(signature));
	memcpy(resp->signed_message, signature_in_hex, hex_len);
	msg_write(MessageType_MessageType_ResponseSkycoinSignMessage, resp);
	return ErrOk;
}

ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, char* signed_message) {
	uint8_t pubkey[33] = {0};
	uint8_t seckey[32] = {0};
	uint8_t signature[65];
	int res = ErrOk;
	fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, index);
	if (ecdsa_skycoin_sign(random32(), seckey, message_digest, signature)) {
		res = ErrFailed;
	}
	tohex(signed_message, signature, sizeof(signature));
#if EMULATOR
	printf("Size_sign: %ld, sign58: %s\n", sizeof(signature) * 2, signed_message);
#endif
	return res;
}

ErrCode_t msgSkycoinAddressImpl(SkycoinAddress* msg, ResponseSkycoinAddress *resp)
{
	uint8_t seckey[32] = {0};
	uint8_t pubkey[33] = {0};
	uint32_t start_index = !msg->has_start_index ? 0 : msg->start_index;
	CHECK_PIN_RET_ERR_CODE
	if (msg->address_n > 99) {
		return ErrTooManyAddresses;
	}

	CHECK_MNEMONIC_RET_ERR_CODE

	if (fsm_getKeyPairAtIndex(msg->address_n, pubkey, seckey, resp, start_index) != 0)
	{
		return ErrAddressGeneration;
	}
	if (msg->address_n == 1 && msg->has_confirm_address && msg->confirm_address) {
		return ErrUserConfirmation;
	}
	return ErrOk;
}

ErrCode_t msgSkycoinCheckMessageSignatureImpl(SkycoinCheckMessageSignature* msg, Success *successResp, Failure *failureResp)
{
	// NOTE(denisacostaq@gmail.com): -1 because the end of string ('\0')
	// /2 because the hex to buff conversion.
	uint8_t sign[(sizeof(msg->signature) - 1)/2];
	// NOTE(denisacostaq@gmail.com): -1 because the end of string ('\0')
	char pubkeybase58[sizeof(msg->address) - 1];
	uint8_t pubkey[33] = {0};
	// NOTE(denisacostaq@gmail.com): -1 because the end of string ('\0')
	// /2 because the hex to buff conversion.
	uint8_t digest[(sizeof(msg->message) - 1) / 2] = {0};
	//     RESP_INIT(Success);
	if (is_digest(msg->message) == false) {
		compute_sha256sum((const uint8_t *)msg->message, digest, strlen(msg->message));
	} else {
		tobuff(msg->message, digest, MIN(sizeof(digest), sizeof(msg->message)));
	}
	tobuff(msg->signature, sign, sizeof(sign));

	ErrCode_t ret = recover_pubkey_from_signed_message((char*)digest, sign, pubkey) == 0 ? ErrOk : ErrFailed;

	if (ret == ErrOk) {
		size_t pubkeybase58_size = sizeof(pubkeybase58);
		generate_base58_address_from_pubkey(pubkey, pubkeybase58, &pubkeybase58_size);
		if (memcmp(pubkeybase58, msg->address, pubkeybase58_size)) {
			strncpy(failureResp->message, _("Address does not match"), sizeof (failureResp->message));
			failureResp->has_message = true;
			layoutRawMessage("Wrong signature");
			ret = ErrInvalidSignature;
		} else {
			layoutRawMessage("Verification success");
			memcpy(successResp->message, pubkeybase58, pubkeybase58_size);
			successResp->has_message = true;
		}
	} else {
		strncpy(failureResp->message, _("Unable to get pub key from signed message"), sizeof (failureResp->message));
		failureResp->has_message = true;
	}
	return ret;
}

ErrCode_t msgApplySettingsImpl(ApplySettings *msg)
{
	_Static_assert(
		sizeof(msg->label) == DEVICE_LABEL_SIZE,
		"device label size inconsitent betwen protocol and final storage");
	CHECK_PARAM_RET_ERR_CODE(msg->has_label || msg->has_language || msg->has_use_passphrase || msg->has_homescreen,
				_("No setting provided"));
	if (msg->has_label) {
		storage_setLabel(msg->label);
	}
	if (msg->has_language) {
		storage_setLanguage(msg->language);
	}
	if (msg->has_use_passphrase) {
		storage_setPassphraseProtection(msg->use_passphrase);
	}
	if (msg->has_homescreen) {
		storage_setHomescreen(msg->homescreen.bytes, msg->homescreen.size);
	}
	storage_update();
	return ErrOk;
}

ErrCode_t msgGetFeaturesImpl(Features *resp)
{
	resp->has_vendor = true;         strlcpy(resp->vendor, "Skycoin Foundation", sizeof(resp->vendor));
	resp->has_fw_major = true;       resp->fw_major = VERSION_MAJOR;
	resp->has_fw_minor = true;       resp->fw_minor = VERSION_MINOR;
	resp->has_fw_patch = true;       resp->fw_patch = VERSION_PATCH;
	resp->has_device_id = true;      strlcpy(resp->device_id, storage_uuid_str, sizeof(resp->device_id));
	resp->has_pin_protection = true; resp->pin_protection = storage_hasPin();
	resp->has_passphrase_protection = true; resp->passphrase_protection = storage_hasPassphraseProtection();
	resp->has_bootloader_hash = true; resp->bootloader_hash.size = memory_bootloader_hash(resp->bootloader_hash.bytes);
	if (storage_getLanguage()) {
		resp->has_language = true;
		strlcpy(resp->language, storage_getLanguage(), sizeof(resp->language));
	}
	if (storage_getLabel()) {
		resp->has_label = true;
		strlcpy(resp->label, storage_getLabel(), sizeof(resp->label));
	}
	resp->has_initialized = true; resp->initialized = storage_isInitialized();
	resp->has_pin_cached = true; resp->pin_cached = session_isPinCached();
	resp->has_passphrase_cached = true; resp->passphrase_cached = session_isPassphraseCached();
	resp->has_needs_backup = true; resp->needs_backup = storage_needsBackup();
	resp->has_model = true; strlcpy(resp->model, "1", sizeof(resp->model));
	return ErrOk;
}

ErrCode_t msgTransactionSignImpl(TransactionSign *msg, ErrCode_t (*funcConfirmTxn)(char*, char *, TransactionSign*, uint32_t)) {
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
			if (strcmp(msg->transactionOut[i].address, address) != 0) {
					// fsm_sendFailure(FailureType_Failure_AddressGeneration, _("Wrong return address"));
					#if EMULATOR
					printf("Internal address: %s, message address: %s\n", address, msg->transactionOut[i].address);
					printf("Comparaison size %ld\n", size_address);
					#endif
					return ErrAddressGeneration;
			}
		} else {
      ErrCode_t err = funcConfirmTxn(strCoin, strHour, msg, i);
      if (err != ErrOk)
        return err;
		}
		transaction_addOutput(&transaction, msg->transactionOut[i].coin, msg->transactionOut[i].hour, msg->transactionOut[i].address);
	}

	CHECK_PIN_UNCACHED_RET_ERR_CODE

	RESP_INIT(ResponseTransactionSign);
	for (uint32_t i = 0; i < msg->nbIn; ++i) {
		uint8_t digest[32];
		transaction_msgToSign(&transaction, i, digest);
		if (msgSignTransactionMessageImpl(digest, msg->transactionIn[i].index, resp->signatures[resp->signatures_count]) != ErrOk) {
			//fsm_sendFailure(FailureType_Failure_InvalidSignature, NULL);
			//layoutHome();
			return ErrInvalidSignature;
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
	//layoutHome();
	return ErrOk;
}

ErrCode_t msgPingImpl(Ping *msg) {
	RESP_INIT(Success);

	if (msg->has_pin_protection && msg->pin_protection) {
		CHECK_PIN_RET_ERR_CODE
	}

	if (msg->has_passphrase_protection && msg->passphrase_protection) {
		if (!protectPassphrase()) {
			return ErrActionCancelled;
		}
	}

	if (msg->has_message) {
		resp->has_message = true;
		memcpy(&(resp->message), &(msg->message), sizeof(resp->message));
	}
	msg_write(MessageType_MessageType_Success, resp);
	return ErrOk;

}

ErrCode_t msgChangePinImpl(ChangePin *msg, bool (*funcProtectChangePin)(void)) {
	bool removal = msg->has_remove && msg->remove;
	if (removal) {
		storage_setPin("");
		storage_update();
		//fsm_sendSuccess(_("PIN removed"));
	} else {
		if (!funcProtectChangePin()) {
			//fsm_sendSuccess(_("PIN changed"));
		} else {
			//fsm_sendFailure(FailureType_Failure_PinMismatch, NULL);
			return ErrPinMismatch;
		}
	}
	return ErrOk;
}

ErrCode_t msgWipeDeviceImpl(WipeDevice *msg) {
	(void)msg;
	storage_wipe();
	// the following does not work on Mac anyway :-/ Linux/Windows are fine, so it is not needed
	// usbReconnect(); // force re-enumeration because of the serial number change
	// fsm_sendSuccess(_("Device wiped"));
	return ErrOk;
}

ErrCode_t msgSetMnemonicImpl(SetMnemonic *msg) {
	RESP_INIT(Success);
	CHECK_MNEMONIC_CHECKSUM_RET_ERR_CODE
	storage_setMnemonic(msg->mnemonic);
	storage_setNeedsBackup(true);
	storage_update();
	//fsm_sendSuccess(_(msg->mnemonic));
	return ErrOk;
}

ErrCode_t msgGetEntropyImpl(GetEntropy *msg, Entropy *resp) {
#ifdef EMULATOR
#if EMULATOR
	return ErrNotImplemented;
#endif  // if EMULATOR
#endif  // ifdef EMULATOR
	uint32_t len = ( msg->size > 1024 ) ? 1024 : msg->size ;
	resp->entropy.size = len;
	random_buffer(resp->entropy.bytes, len);
	return ErrOk;
}

ErrCode_t msgLoadDeviceImpl(LoadDevice *msg) {
	if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum) ) {
		CHECK_MNEMONIC_CHECKSUM_RET_ERR_CODE
	}

	storage_loadDevice(msg);
	//fsm_sendSuccess(_("Device loaded"));
	return ErrOk;
}

ErrCode_t msgBackupDeviceImpl(BackupDevice *msg, ErrCode_t (*funcConfirmBackup)(void)) {
	(void)msg;
	if (!storage_needsBackup()) {
		//fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Seed already backed up"));
		return ErrUnexpectedMessage;
	}
	reset_backup(true);

  ErrCode_t err = funcConfirmBackup();
  if (err != ErrOk) {
    return err;
  }
	if (storage_unfinishedBackup()) {
		// fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Backup operation did not finish properly."));
		// layoutHome();
		return ErrUnfinishedBackup;
	}
	storage_setNeedsBackup(false);
	storage_update();
	// fsm_sendSuccess(_("Device backed up!"));
	return ErrOk;
}

ErrCode_t msgRecoveryDeviceImpl(RecoveryDevice *msg, ErrCode_t (*funcConfirmRecovery)(void)) {
	const bool dry_run = msg->has_dry_run ? msg->dry_run : false;
	if (dry_run) {
		CHECK_PIN_RET_ERR_CODE
	} else {
		CHECK_NOT_INITIALIZED_RET_ERR_CODE
	}

	CHECK_PARAM_RET_ERR_CODE(!msg->has_word_count || msg->word_count == 12
			|| msg->word_count == 24, _("Invalid word count"));

	if (!dry_run) {
    ErrCode_t err = funcConfirmRecovery();
    if (err != ErrOk) {
      return err;
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
	return ErrOk;
}
