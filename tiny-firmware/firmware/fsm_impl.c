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

#include <stdio.h>
#include <math.h>

#include <libopencm3/stm32/flash.h>


#include "trezor.h"
#include "fsm.h"
#include "messages.h"
#include "bip32.h"
#include "storage.h"
#include "rng.h"
#include "storage.h"
#include "oled.h"
#include "protect.h"
#include "pinmatrix.h"
#include "layout2.h"
#include "base58.h"
#include "reset.h"
#include "recovery.h"
#include "bip39.h"
#include "memory.h"
#include "usb.h"
#include "util.h"
#include "gettext.h"
#include "skycoin_crypto.h"
#include "skycoin_check_signature.h"
#include "check_digest.h"
#include "storage.h"

#define MNEMONIC_STRENGTH_12 128
#define MNEMONIC_STRENGTH_24 256
#define INTERNAL_ENTROPY_SIZE 32

/**
 * @brief make_histogram create a histogram in plce from bytes
 * @param bytes source to build the histogram
 * @param bytes_size size of source bites
 * @param hist output variable to fill with histogram values
 * @return the histogram length
 */
static uint8_t make_histogram(
	const uint8_t* const bytes, uint16_t bytes_size, uint8_t *hist) {
	// NOTE(denisacostaq@gmial.com): byte_posibilities = 2^sizeof(S[0])
	const uint16_t byte_posibilities = 256;
	int wherechar[byte_posibilities];
	for (uint16_t i = 0; i < byte_posibilities; ++i) {
		wherechar[i] = -1;
	}
	{GenerateMnemonic gmMsg;
		_Static_assert(
			sizeof(gmMsg.entropy.bytes) < 256, // 2^(size of uint8_t )
			"entropy.bytes can acumulate more than len, histlen and/or hist[i]");}
	uint8_t histlen = 0;
	for (uint8_t i = 0; i < bytes_size; ++i) {
		if (wherechar[bytes[i]] == -1) {
			wherechar[bytes[i]] = histlen++;
		}
		++hist[wherechar[bytes[i]]];
	}
	return histlen;
}

/**
 * @brief entropy return the entropy in a giving histogram
 * @param hist histogram to mesure the entropy from
 * @param histlen histogram length
 * @param len amount of symbols
 * @return the Shannon entropy (bits/symbol)
 * @sa https://rosettacode.org/wiki/Entropy
 */
static float entropy(
	const uint8_t *const hist, uint8_t histlen, uint16_t len) {
	float entr = .0f;
	for (uint8_t i = 0; i < histlen; ++i) {
		entr -= (float)hist[i]/len * (float)log2((double)hist[i]/len);
	}
	return entr;
}

/**
 * @brief engout_entropy says if a bytes distribution have engout entropy
 * @param bytes the bytes to mesur the entropy
 * @param size the size of bytes
 * @return an error if not fit minimal entropy required
 * @sa entropy, make_histogram
 */
ErrCode_t engout_entropy(const uint8_t* const bytes, uint16_t size) {
	uint8_t hist[size];
	memset(hist, 0, size);
	uint8_t histlen = make_histogram(bytes, size, hist);
	float entr = entropy(hist, histlen, size);
	return entr < 4.f ? ErrFailed : ErrOk;
}

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic* msg) {
	_Static_assert(
		EXTERNAL_ENTROPY_SIZE == sizeof(msg->entropy.bytes),
		"External entropy size not match.");
	CHECK_NOT_INITIALIZED_RET_ERR_CODE
	if (msg->entropy.size < EXTERNAL_ENTROPY_SIZE) {
		fsm_sendFailure(
			FailureType_Failure_DataError,
			_("Entropy buffer not have engouth size."));
		return ErrFailed;
	}
	if (engout_entropy(msg->entropy.bytes, msg->entropy.size) != ErrOk ) {
		fsm_sendFailure(
			FailureType_Failure_DataError,
			_("Not engouth entropy level recived."));
		return ErrFailed;
	}
	uint8_t int_entropy[INTERNAL_ENTROPY_SIZE];
	random_buffer(int_entropy, sizeof(int_entropy));
	SHA256_CTX ctx;
	sha256_Init(&ctx);
	sha256_Update(&ctx, int_entropy, sizeof(int_entropy));
	sha256_Update(&ctx, msg->entropy.bytes, msg->entropy.size);
	sha256_Final(&ctx, int_entropy);
	if (engout_entropy(int_entropy, sizeof(int_entropy)) != ErrOk ) {
		fsm_sendFailure(
			FailureType_Failure_ProcessError,
			_("Not engouth entropy level for combined entropy values."));
		return ErrFailed;
	}
	int strength = MNEMONIC_STRENGTH_12;
	if (msg->has_word_count) {
		switch (msg->word_count) {
			case MNEMONIC_WORD_COUNT_12:
				strength = MNEMONIC_STRENGTH_12;
				break;
			case MNEMONIC_WORD_COUNT_24:
				strength = MNEMONIC_STRENGTH_24;
				break;
			default:
				fsm_sendFailure(
					FailureType_Failure_DataError,
					_("Invalid word count expecified the valid options are 12 or 24."));
				return ErrFailed;
		}
	}
	const char* mnemonic = mnemonic_from_data(int_entropy, strength / 8);
	if (mnemonic) {
		if (!mnemonic_check(mnemonic)) {
			fsm_sendFailure(
				FailureType_Failure_DataError, 
				_("Mnemonic with wrong checksum provided"));
			return ErrFailed;
		}
		storage_setMnemonic(mnemonic);
		storage_setNeedsBackup(true);
		storage_setPassphraseProtection(
					msg->has_passphrase_protection
					&& msg->passphrase_protection);
		memset(int_entropy, 0, sizeof(int_entropy));
		storage_update();
		return ErrOk;
	} else {
		fsm_sendFailure(
					FailureType_Failure_ProcessError,
					_("Device could not generate a Mnemonic"));
		return ErrFailed;
	}
}


void msgSkycoinSignMessageImpl(SkycoinSignMessage* msg,
								   ResponseSkycoinSignMessage *resp)
{
	if (storage_hasMnemonic() == false) {
		fsm_sendFailure(FailureType_Failure_AddressGeneration, "Mnemonic not set");
		return;
	}
	CHECK_PIN_UNCACHED
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
	int res = ecdsa_skycoin_sign(rand(), seckey, digest, signature);
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
	layoutHome();
}

ErrCode_t msgSignTransactionMessageImpl(uint8_t* message_digest, uint32_t index, char* signed_message) {
	uint8_t pubkey[33] = {0};
	uint8_t seckey[32] = {0};
	uint8_t signature[65];
	int res = ErrOk;
	fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, index);
	if (ecdsa_skycoin_sign(rand(), seckey, message_digest, signature)) {
		res = ErrFailed;
	}
	tohex(signed_message, signature, sizeof(signature));
#if EMULATOR
	printf("Size_sign: %ld, sign58: %s\n", sizeof(signature) * 2, signed_message);
#endif
	return res;
}

ErrCode_t msgSkycoinAddress(SkycoinAddress* msg, ResponseSkycoinAddress *resp)
{
	uint8_t seckey[32] = {0};
	uint8_t pubkey[33] = {0};
	uint32_t start_index = !msg->has_start_index ? 0 : msg->start_index;
	CHECK_PIN_RET_ERR_CODE
	if (msg->address_n > 99) {
		fsm_sendFailure(FailureType_Failure_AddressGeneration, "Asking for too much addresses");
		return ErrFailed;
	}

	if (storage_hasMnemonic() == false) {
		fsm_sendFailure(FailureType_Failure_AddressGeneration, "Mnemonic not set");
		return ErrFailed;
	}

	if (fsm_getKeyPairAtIndex(msg->address_n, pubkey, seckey, resp, start_index) != 0)
	{
		fsm_sendFailure(FailureType_Failure_AddressGeneration, "Key pair generation failed");
		return ErrFailed;
	}
	if (msg->address_n == 1 && msg->has_confirm_address && msg->confirm_address) {
		char * addr = resp->addresses[0];
		layoutAddress(addr);
		if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
			fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
			layoutHome();
			return ErrFailed;
		}
	}
	return ErrOk;
}

void msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature* msg, Success *resp)
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
	recover_pubkey_from_signed_message((char*)digest, sign, pubkey);
	size_t pubkeybase58_size = sizeof(pubkeybase58);
	generate_base58_address_from_pubkey(pubkey, pubkeybase58, &pubkeybase58_size);
	if (memcmp(pubkeybase58, msg->address, pubkeybase58_size) == 0) {
		layoutRawMessage("Verification success");
	} else {
		layoutRawMessage("Wrong signature");
	}
	memcpy(resp->message, pubkeybase58, pubkeybase58_size);
	resp->has_message = true;
	msg_write(MessageType_MessageType_Success, resp);
}

void msgApplySettings(ApplySettings *msg)
{
	_Static_assert(
		sizeof(msg->label) == DEVICE_LABEL_SIZE, 
		"device label size inconsitent betwen protocol and final storage");
	CHECK_PARAM(msg->has_label || msg->has_language || msg->has_use_passphrase || msg->has_homescreen,
				_("No setting provided"));
	if (msg->has_label) {
		storage_setLabel(msg->label);
	} else {
		char label[DEVICE_LABEL_SIZE];
		_Static_assert(sizeof(label) >= sizeof(storage_uuid_str), 
						"Label can be truncated");
		strncpy(label, storage_uuid_str, 
				MIN(sizeof(storage_uuid_str), sizeof(label)));
		storage_setLabel(label);
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
}

void msgGetFeaturesImpl(Features *resp)
{
	resp->has_vendor = true;         strlcpy(resp->vendor, "Skycoin Foundation", sizeof(resp->vendor));
	resp->has_fw_major = true;  resp->fw_major = VERSION_MAJOR;
	resp->has_fw_minor = true;  resp->fw_minor = VERSION_MINOR;
	resp->has_fw_patch = true;  resp->fw_patch = VERSION_PATCH;
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
}
