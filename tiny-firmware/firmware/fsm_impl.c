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

#include "tiny-firmware/firmware/fsm_impl.h"

#include <libopencm3/stm32/flash.h>
#include <stdio.h>
#include <inttypes.h>
#include <ethereum_messages.pb.h>

#include "skycoin-crypto/tools/base58.h"
#include "skycoin-crypto/tools/bip32.h"
#include "skycoin-crypto/tools/bip39.h"
#include "skycoin-crypto/check_digest.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/gettext.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/firmware/messages.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/oled.h"
#include "tiny-firmware/firmware/protect.h"
#include "tiny-firmware/firmware/recovery.h"
#include "tiny-firmware/firmware/reset.h"
#include "tiny-firmware/memory.h"
#include "tiny-firmware/usb.h"
#include "tiny-firmware/util.h"
#include "skycoin-crypto/skycoin_constants.h"
#include "skycoin-crypto/eth_constants.h"
#include "skycoin-crypto/skycoin_crypto.h"
#include "skycoin-crypto/skycoin_signature.h"
#include "tiny-firmware/firmware/skyparams.h"

#define MNEMONIC_STRENGTH_12 128
#define MNEMONIC_STRENGTH_24 256
#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

#define UNUSED(x) (void)(x)

uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

extern uint32_t strength;
extern bool skip_backup;
extern uint8_t int_entropy[INTERNAL_ENTROPY_SIZE];

bool checkInitialized(void) {
    if (!storage_isInitialized()) {
        fsm_sendFailure(FailureType_Failure_NotInitialized, NULL, 0);
        return 1;
    }
    return 0;
}

bool checkNotInitialized(void) {
    if (storage_isInitialized()) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first."), 0);
        return 1;
    }
    return 0;
}

bool checkPin(void) {
    if (!protectPin(true)) {
        layoutHome();
        return 1;
    }
    return 0;
}

bool checkPinUncached(void) {
    if (!protectPin(false)) {
        layoutHome();
        return 1;
    }
    return 0;
}

bool checkInputs(TransactionSign *msg) {
    if ((msg)->nbIn > 8) {
        fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Cannot have more than 8 inputs"), 0);
        layoutHome();
        return 1;
    }
    return 0;
}

bool checkOutputs(TransactionSign *msg) {
    if ((msg)->nbOut > 8) {
        fsm_sendFailure(FailureType_Failure_InvalidSignature, _("Cannot have more than 8 outputs"), 0);
        layoutHome();
        return 1;
    }
    return 0;
}


bool checkParam(bool cond, const char *errormsg) {
    if (!(cond)) {
        fsm_sendFailure(FailureType_Failure_DataError, errormsg, 0);
        layoutHome();
        return 1;
    }
    return 0;
}

bool checkPrecondition(bool cond, const char *errormsg) {
    if (!(cond)) {
        fsm_sendFailure(FailureType_Failure_DataError, (errormsg), 0);
        layoutHome();
        return 1;
    }
    return 0;
}

bool checkButtonProtect(void) {
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, 0);
        layoutHome();
        return 1;
    }
    return 0;
}

ErrCode_t checkButtonProtectRetErrCode(void) {
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
        layoutHome();
        return ErrActionCancelled;
    }
    return ErrOk;
}

bool checkMnemonic(void) {
    if (storage_hasMnemonic() == false) {
        fsm_sendFailure(FailureType_Failure_AddressGeneration, "Mnemonic not set", 0);
        layoutHome();
        return 1;
    }
    return 0;
}

bool checkMnemonicChecksum(SetMnemonic *msg) {
    if (!mnemonic_check(msg->mnemonic)) {
        fsm_sendFailure(FailureType_Failure_DataError, _("Mnemonic with wrong checksum provided"), 0);
        layoutHome();
        return 1;
    }
    return 0;
}

ErrCode_t msgEntropyAckImpl(EntropyAck *msg) {
    _Static_assert(EXTERNAL_ENTROPY_MAX_SIZE == sizeof(msg->entropy.bytes),
                   "External entropy size does not match.");
    if (msg->entropy.size > sizeof(msg->entropy.bytes)) {
        return ErrInvalidArg;
    }
    if (!msg->has_entropy) {
        return ErrEntropyNotNeeded;
    }
    set_external_entropy(msg->entropy.bytes, msg->entropy.size);
    return ErrOk;
}

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic *msg, void (*random_buffer_func)(uint8_t *buf, size_t len)) {
    if (storage_isInitialized()) {
        return ErrNotInitialized;
    }
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
    // random buffer + entropy pool => mix256 => internal entropy
    uint8_t data[sizeof(int_entropy)];
    random_buffer_func(data, sizeof(data));
    entropy_salt_mix_256(data, sizeof(data), int_entropy);
    memset(data, 0, sizeof(data));
    const char *mnemonic = mnemonic_from_data(int_entropy, strength / 8);
    memset(int_entropy, 0, sizeof(int_entropy));
    if (!mnemonic) {
        return ErrInvalidValue;
    }
    if (!mnemonic_check(mnemonic)) {
        return ErrInvalidChecksum;
    }
    storage_setMnemonic(mnemonic);
    TxSignContext *ctx = TxSignCtx_Get();
    if (ctx != NULL) {
        ctx->mnemonic_change = true;
    }
    storage_setNeedsBackup(true);
    storage_setPassphraseProtection(
            msg->has_passphrase_protection && msg->passphrase_protection);
    storage_update();
    return ErrOk;
}

ErrCode_t msgSignTransactionMessageImpl(uint8_t *message_digest, uint32_t index, char *signed_message) {
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t signature[SKYCOIN_SIG_LEN];
    ErrCode_t res = fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, addSkycoinAddress,
                                          index, &skycoin_address_from_pubkey, true);
    if (res != ErrOk) {
        return res;
    }
    int signres = skycoin_ecdsa_sign_digest(seckey, message_digest, signature);
    if (signres == -2) {
        // Fail due to empty digest
        return ErrInvalidArg;
    } else if (res) {
        // Too many retries without a valid signature
        // -> fail with an error
        return ErrFailed;
    }
    tohex(signed_message, signature, SKYCOIN_SIG_LEN);
#if EMULATOR
    printf("Size_sign: %d, sig(hex): %s\n", SKYCOIN_SIG_LEN * 2, signed_message);
#endif
    return res;
}

ErrCode_t addSkycoinAddress(void *resp, char *address) {
    ResponseSkycoinAddress *skycoinResp = (ResponseSkycoinAddress *) (resp);

    static int max_addresses =
            sizeof(skycoinResp->addresses)
            / sizeof(skycoinResp->addresses[0]);
    if (skycoinResp->addresses_count + 1 > max_addresses)
        return ErrInvalidArg;

    memcpy(skycoinResp->addresses[skycoinResp->addresses_count], address, MAX_BIP58_ADDRESS_LEN);
    skycoinResp->addresses_count++;
    return ErrOk;
}

ErrCode_t addEthereumAddress(void *resp, char *address) {
    ResponseEthereumAddress *ethereumResp = (ResponseEthereumAddress *) (resp);

    static int max_addresses =
            sizeof(ethereumResp->addresses)
            / sizeof(ethereumResp->addresses[0]);
    if (ethereumResp->addresses_count + 1 > max_addresses)
        return ErrInvalidArg;

    memcpy(ethereumResp->addresses[ethereumResp->addresses_count].bytes, address, ETH_ADDR_LEN);
    ethereumResp->addresses_count++;
    return ErrOk;
}

ErrCode_t
fsm_getKeyPairAtIndex(uint32_t nbAddress,
                      uint8_t *pubkey, uint8_t *seckey,
                      void *resp,
                      ErrCode_t (*add_address_to_resp)(void *resp, char *address),
                      uint32_t start_index,
                      int (*address_from_pubkey)(const uint8_t *, char *, size_t *), bool is_compressed_pk) {
    const char *mnemo = storage_getFullSeed();
    uint8_t seed[33] = {0};
    uint8_t nextSeed[SHA256_DIGEST_LENGTH] = {0};
    if (mnemo == NULL || nbAddress == 0) {
        return ErrInvalidArg;
    }
    if (0 != deterministic_key_pair_iterator((const uint8_t *) mnemo, strlen(mnemo), nextSeed, seckey, pubkey,
                                             is_compressed_pk)) {
        return ErrFailed;
    }

    size_t max_size_address = MAX(MAX_BIP58_ADDRESS_LEN, ETH_ADDR_LEN);
    char buf[MAX(MAX_BIP58_ADDRESS_LEN, ETH_ADDR_LEN)];

    if (resp != NULL && start_index == 0) {
        if (!address_from_pubkey(pubkey, buf, &max_size_address)) {
            return ErrFailed;
        }
        if (add_address_to_resp(resp, buf) != ErrOk) {
            return ErrInvalidArg;
        }
    }
    memcpy(seed, nextSeed, 32);
    for (uint32_t i = 0; i < nbAddress + start_index - 1; ++i) {
        if (0 != deterministic_key_pair_iterator(seed, 32, nextSeed, seckey, pubkey, is_compressed_pk)) {
            return ErrFailed;
        }
        memcpy(seed, nextSeed, 32);
        seed[32] = 0;
        if (resp != NULL && ((i + 1) >= start_index)) {
            if (!address_from_pubkey(pubkey, buf, &max_size_address)) {
                return ErrFailed;
            }
            if (add_address_to_resp(resp, buf) != ErrOk) {
                return ErrInvalidArg;
            }
        }
    }
    return ErrOk;
}

ErrCode_t verifyLanguage(char *lang) {
    // FIXME: Check for supported language name. Only english atm.
    return (!strcmp(lang, "english")) ? ErrOk : ErrInvalidValue;
}

ErrCode_t msgApplySettingsImpl(ApplySettings *msg) {
    _Static_assert(
            sizeof(msg->label) == DEVICE_LABEL_SIZE,
            "device label size inconsitent betwen protocol and final storage");
    if (!(msg->has_label || msg->has_language || msg->has_use_passphrase || msg->has_homescreen)) {
        return ErrPreconditionFailed;
    }
    if (msg->has_label) {
        storage_setLabel(msg->label);
    }
    if (msg->has_language) {
        if (verifyLanguage(msg->language) != ErrOk) {
            return ErrInvalidArg;
        }
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

#if !defined(EMULATOR) || !EMULATOR

#include <tiny-firmware/memory.h>

#endif

ErrCode_t msgGetFeaturesImpl(Features *resp) {
    resp->has_vendor = true;
    strlcpy(resp->vendor, "Skycoin Foundation", sizeof(resp->vendor));
#if VERSION_IS_SEMANTIC_COMPLIANT == 1
#ifdef VERSION_MAJOR
    resp->has_fw_major = true;
    resp->fw_major = VERSION_MAJOR;
#endif // VERSION_MAJOR
#ifdef VERSION_MINOR
    resp->has_fw_minor = true;
    resp->fw_minor = VERSION_MINOR;
#endif // VERSION_MINOR
#ifdef VERSION_PATCH
    resp->has_fw_patch = true;
    resp->fw_patch = VERSION_PATCH;
#endif // VERSION_PATCH
#else  // VERSION_IS_SEMANTIC_COMPLIANT == 1
#ifdef APPVER
    resp->has_fw_version_head = true;
    sprintf(resp->fw_version_head, "%x", APPVER);
#endif // APPVER
#endif // VERSION_IS_SEMANTIC_COMPLIANT == 1
    resp->has_device_id = true;
    strlcpy(resp->device_id, storage_uuid_str, sizeof(resp->device_id));
    resp->has_pin_protection = true;
    resp->pin_protection = storage_hasPin();
    resp->has_passphrase_protection = true;
    resp->passphrase_protection = storage_hasPassphraseProtection();
    resp->has_bootloader_hash = true;
    resp->bootloader_hash.size = memory_bootloader_hash(resp->bootloader_hash.bytes);
    if (storage_getLanguage()) {
        resp->has_language = true;
        strlcpy(resp->language, storage_getLanguage(), sizeof(resp->language));
    }
    if (storage_getLabel()) {
        resp->has_label = true;
        strlcpy(resp->label, storage_getLabel(), sizeof(resp->label));
    }
    resp->has_initialized = true;
    resp->initialized = storage_isInitialized();
    resp->has_pin_cached = true;
    resp->pin_cached = session_isPinCached();
    resp->has_passphrase_cached = true;
    resp->passphrase_cached = session_isPassphraseCached();
    resp->has_needs_backup = true;
    resp->needs_backup = storage_needsBackup();
    resp->has_model = true;
    strlcpy(resp->model, "1", sizeof(resp->model));
    resp->has_firmware_features = true;
#if defined(EMULATOR) && EMULATOR
    resp->firmware_features |= FirmwareFeatures_IsEmulator;
#else
    resp->firmware_features |= (uint32_t) (memory_rdp_level() << FirmwareFeatures_IsEmulator);
#endif

#if DISABLE_GETENTROPY_CONFIRM
    resp->firmware_features |= FirmwareFeatures_RequireGetEntropyConfirm;
#endif
#if defined(ENABLE_GETENTROPY) && ENABLE_GETENTROPY
    resp->firmware_features |= FirmwareFeatures_IsGetEntropyEnabled;
#endif

    return ErrOk;
}

ErrCode_t msgPingImpl(Ping *msg) {
    RESP_INIT(Success);

    if (msg->has_pin_protection && msg->pin_protection) {
        if (!protectPin(true)) {
            return ErrPinRequired;
        }
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

ErrCode_t msgChangePinImpl(ChangePin *msg, const char *(*funcRequestPin)(PinMatrixRequestType, const char *)) {
    bool removal = msg->has_remove && msg->remove;
    if (removal) {
        storage_setPin("");
        storage_update();
    } else {
        if (!protectChangePinEx(funcRequestPin)) {
            return ErrPinMismatch;
        }
    }
    return ErrOk;
}

ErrCode_t msgWipeDeviceImpl(WipeDevice *msg) {
    (void) msg;
    storage_wipe();
    // the following does not work on Mac anyway :-/ Linux/Windows are fine, so it is not needed
    // usbReconnect(); // force re-enumeration because of the serial number change
    // fsm_sendSuccess(_("Device wiped"));
    return ErrOk;
}

ErrCode_t msgSetMnemonicImpl(SetMnemonic *msg) {

    // Removing multiple spaces from mnemonic
    uint32_t legitSpace, countSpaces = 0, i = 0;
    while (msg->mnemonic[i]) {
        if (msg->mnemonic[i] == ' ' && countSpaces == 0) {
            countSpaces++;
            legitSpace = i;
        } else if (msg->mnemonic[i] == ' ' && countSpaces > 0) {
            countSpaces++;
        } else if (msg->mnemonic[i] != ' ' && countSpaces > 1) {
            countSpaces = 0;
            memmove(&(msg->mnemonic[legitSpace + 1]), &(msg->mnemonic[i]), strlen(msg->mnemonic) - i + 1);
        } else if (msg->mnemonic[i] != ' ' && countSpaces <= 1)
            countSpaces = 0;

        i++;
    }
    // Handling first and last whitespace
    if (msg->mnemonic[0] == ' ')
        memmove(&(msg->mnemonic[0]), &(msg->mnemonic[1]), strlen(msg->mnemonic));
    if (msg->mnemonic[--i] == ' ')
        msg->mnemonic[i] = msg->mnemonic[i + 1];
    printf("%s\n", msg->mnemonic);
    if (!mnemonic_check(msg->mnemonic)) {
        return ErrInvalidValue;
    }
    storage_setMnemonic(msg->mnemonic);
    TxSignContext *ctx = TxSignCtx_Get();
    if (ctx != NULL) {
        ctx->mnemonic_change = true;
    }
    storage_setNeedsBackup(true);
    storage_update();
    //fsm_sendSuccess(_(msg->mnemonic));
    return ErrOk;
}

ErrCode_t msgGetEntropyImpl(GetRawEntropy *msg, Entropy *resp, void (*random_buffer_func)(uint8_t *buf, size_t len)) {
    (void) msg;
    (void) resp;
    (void) random_buffer_func;
#if defined(EMULATOR) && EMULATOR
    return ErrNotImplemented;
#else
#if !defined(ENABLE_GETENTROPY) || !ENABLE_GETENTROPY
    return ErrNotImplemented;
#endif // ENABLE_GETENTROPY
    uint32_t len = (msg->size > 1024) ? 1024 : msg->size;
    resp->entropy.size = len;
    random_buffer_func(resp->entropy.bytes, len);
    return ErrOk;
#endif // EMULATOR
}

ErrCode_t msgLoadDeviceImpl(LoadDevice *msg) {
    if (msg->has_mnemonic && !(msg->has_skip_checksum && msg->skip_checksum)) {
        if (!mnemonic_check(msg->mnemonic)) {
            return ErrInvalidValue;
        }
    }

    storage_loadDevice(msg);
    //fsm_sendSuccess(_("Device loaded"));
    return ErrOk;
}

ErrCode_t msgBackupDeviceImpl(BackupDevice *msg, ErrCode_t (*funcConfirmBackup)(void)) {
    (void) msg;
    if (!storage_needsBackup()) {
        //fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Seed already backed up"));
        return ErrUnexpectedMessage;
    }
    ErrCode_t err = reset_backup(true);
    if (err != ErrOk) {
        return err;
    }

    err = funcConfirmBackup();
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
        if (!protectPin(true)) {
            return ErrPinRequired;
        }
        if (!storage_isInitialized()) {
            return ErrInitialized;
        }
    } else {
        if (storage_isInitialized()) {
            return ErrNotInitialized;
        }
    }
    if (!(!msg->has_word_count || msg->word_count == 12 || msg->word_count == 24)) {
        return ErrInvalidArg;
    }

    if (!dry_run) {
        ErrCode_t err = funcConfirmRecovery();
        if (err != ErrOk) {
            return err;
        }
    }
    char current_label[DEVICE_LABEL_SIZE];
    strncpy(current_label, storage_getLabel(), sizeof(current_label));

    recovery_init(
            msg->has_word_count ? msg->word_count : 12,
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            (msg->has_label && strlen(msg->label) > 0) ? msg->label : current_label,
            dry_run);
    return ErrOk;
}

ErrCode_t msgSignTxImpl(SignTx *msg, TxRequest *resp) {
#if EMULATOR
    printf("%s: %d. nbOut: %d\n",
           _("Transaction signed nbIn"),
           msg->inputs_count, msg->outputs_count);
#endif
    TxSignContext *context = TxSignCtx_Get();
    if (context->state != Destroyed) {
        TxSignCtx_Destroy(context);
        return ErrFailed;
    }
    // Init TxSignContext
    context = TxSignCtx_Init();
    if (context->mnemonic_change) {
        TxSignCtx_Destroy(context);
        return ErrFailed;
    }
    memcpy(context->coin_name, msg->coin_name, 36 * sizeof(char));
    context->state = InnerHashInputs;
    context->current_nbIn = 0;
    context->current_nbOut = 0;
    context->lock_time = msg->lock_time;
    context->nbIn = msg->inputs_count;
    context->nbOut = msg->outputs_count;
    sha256_Init(&context->sha256_ctx);
    memcpy(context->tx_hash, msg->tx_hash, 65 * sizeof(char));
    context->version = msg->version;
    context->has_innerHash = false;
    context->requestIndex = 1;

    // Init Inputs head on sha256
    TxSignCtx_AddSizePrefix(context, msg->inputs_count);

    // Build response TxRequest
    resp->has_details = true;
    resp->details.has_request_index = true;
    resp->details.request_index = 1;
    memcpy(resp->details.tx_hash, msg->tx_hash, 65 * sizeof(char));
    resp->request_type = TxRequest_RequestType_TXINPUT;
    return ErrOk;
}

ErrCode_t reqConfirmTransaction(uint64_t coins, uint64_t hours, char *address) {
    char strCoins[32];
    char strHours[32];
    char strValue[20];
    char *coinString = coins == 1000000 ? _("coin") : _("coins");
    char *hourString = (hours == 1 || hours == 0) ? _("hour") : _("hours");
    char *strValueMsg = sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, sizeof(strValue), strValue);
    sprintf(strCoins, "%s %s %s", _("send"), strValueMsg, coinString);
    sprintf(strHours, "%"
                      PRIu64
                      "%s", hours, hourString);
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Next"), NULL, _("Do you really want to"), strCoins, strHours,
                      _("to address"), _("..."), NULL);
    ErrCode_t err = checkButtonProtectRetErrCode();
    if (err != ErrOk) {
        return err;
    }
    layoutAddress(address);
    err = checkButtonProtectRetErrCode();
    return err;
}

ErrCode_t msgTxAckImpl(TxAck *msg, TxRequest *resp) {
    TxSignContext *ctx = TxSignCtx_Get();
    if (ctx->state != Start && ctx->state != InnerHashInputs && ctx->state != InnerHashOutputs &&
        ctx->state != Signature) {
        TxSignCtx_Destroy(ctx);
        return ErrInvalidArg;
    }
#if EMULATOR
    switch (ctx->state) {
        case InnerHashInputs:
            printf("-> Inner Hash inputs\n");
            break;
        case InnerHashOutputs:
            printf("-> Inner Hash outputs\n");
            break;
        case Signature:
            printf("-> Signatures\n");
            break;
        default:
            printf("-> Unexpected\n");
            break;
    }
    for (uint32_t i = 0; i < msg->tx.inputs_count; ++i) {
        printf("   %d - Input: addressIn: %s, address_n: ", i + 1,
               msg->tx.inputs[i].hashIn);
        if (msg->tx.inputs[i].address_n_count != 0)
            printf("%d", msg->tx.inputs[i].address_n[0]);
        printf("\n");
    }
    for (uint32_t i = 0; i < msg->tx.outputs_count; ++i) {
        printf("   %d - Output: coins: %" PRIu64 ", hours: %" PRIu64 " address: %s address_n: ", i + 1,
               msg->tx.outputs[i].coins, msg->tx.outputs[i].hours, msg->tx.outputs[i].address);
        if (msg->tx.outputs[i].address_n_count != 0) {
            printf("%d", msg->tx.outputs[i].address_n[0]);
        }
        printf("\n");
    }
#endif
    if (ctx->mnemonic_change) {
        TxSignCtx_Destroy(ctx);
        return ErrFailed;
    }
    uint8_t inputs[7][32];
    for (uint8_t i = 0; i < msg->tx.inputs_count; ++i) {
        writebuf_fromhexstr(msg->tx.inputs[i].hashIn, inputs[i]);
    }
    switch (ctx->state) {
        case InnerHashInputs:
            if (!msg->tx.inputs_count || msg->tx.outputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            TxSignCtx_UpdateInputs(ctx, inputs, msg->tx.inputs_count);
            if (ctx->current_nbIn != ctx->nbIn)
                resp->request_type = TxRequest_RequestType_TXINPUT;
            else {
                TxSignCtx_AddSizePrefix(ctx, ctx->nbOut);
                resp->request_type = TxRequest_RequestType_TXOUTPUT;
                ctx->state = InnerHashOutputs;
            }
            break;
        case InnerHashOutputs:
            if (!msg->tx.outputs_count || msg->tx.inputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            TransactionOutput outputs[7];
            for (uint8_t i = 0; i < msg->tx.outputs_count; ++i) {
#if !EMULATOR
                if (!msg->tx.outputs[i].address_n_count) {
                    ErrCode_t err = reqConfirmTransaction(msg->tx.outputs[i].coins, msg->tx.outputs[i].hours,
                                                          msg->tx.outputs[i].address);
                    if (err != ErrOk)
                        return err;
                }
#endif
                outputs[i].coin = msg->tx.outputs[i].coins;
                outputs[i].hour = msg->tx.outputs[i].hours;
                size_t len = 37;
                uint8_t b58string[37];
                b58tobin(b58string, &len, msg->tx.outputs[i].address);
                memcpy(outputs[i].address, &b58string[37 - len], len);
            }
            TxSignCtx_UpdateOutputs(ctx, outputs, msg->tx.outputs_count);
            if (ctx->current_nbOut != ctx->nbOut) {
                resp->request_type = TxRequest_RequestType_TXOUTPUT;
            } else {
                TxSignCtx_finishInnerHash(ctx);
                ctx->state = Signature;
                ctx->current_nbIn = 0;
                resp->request_type = TxRequest_RequestType_TXINPUT;
            }
            break;
        case Signature:
            if (!msg->tx.inputs_count || msg->tx.outputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            if (!ctx->has_innerHash) {
                TxSignCtx_Destroy(ctx);
                return ErrFailed;
            }
            uint8_t signCount = 0;
            for (uint8_t i = 0; i < msg->tx.inputs_count; ++i) {
                if (msg->tx.inputs[i].address_n_count) {
                    uint8_t shaInput[64];
                    uint8_t msg_digest[32] = {0};
                    memcpy(shaInput, ctx->innerHash, 32);
                    memcpy(&shaInput[32], &inputs[i], 32);
                    SHA256_CTX sha256ctx;
                    sha256_Init(&sha256ctx);
                    sha256_Update(&sha256ctx, shaInput, 64);
                    sha256_Final(&sha256ctx, msg_digest);
                    resp->sign_result[signCount].has_signature = true;
                    msgSignTransactionMessageImpl(msg_digest, msg->tx.inputs[i].address_n[0],
                                                  resp->sign_result[signCount].signature);
                    resp->sign_result[signCount].has_signature_index = true;
                    resp->sign_result[signCount].signature_index = i;
                    signCount++;
                }
                ctx->current_nbIn++;
            }
            resp->sign_result_count = signCount;
            if (ctx->current_nbIn != ctx->nbIn)
                resp->request_type = TxRequest_RequestType_TXINPUT;
            else {
                resp->request_type = TxRequest_RequestType_TXFINISHED;
            }
            break;
        default:
            break;
    }
    resp->has_details = true;
    resp->details.has_request_index = true;
    ctx->requestIndex++;
    resp->details.request_index = ctx->requestIndex;
    resp->details.has_tx_hash = true;
    memcpy(resp->details.tx_hash, ctx->tx_hash, strlen(ctx->tx_hash) * sizeof(char));
    if (resp->request_type == TxRequest_RequestType_TXFINISHED)
        TxSignCtx_Destroy(ctx);
    return ErrOk;
}

ErrCode_t msgBitcoinTxAckImpl(BitcoinTxAck *msg, TxRequest *resp) {
    UNUSED(msg);
    UNUSED(resp);
    return ErrOk;
}
