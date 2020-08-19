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

#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/skywallet.h"
#include "tiny-firmware/firmware/messages.h"
#include "skycoin-crypto/tools/bip32.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/oled.h"
#include "tiny-firmware/util.h"
#include "tiny-firmware/memory.h"
#include "tiny-firmware/firmware/protect.h"
#include "tiny-firmware/firmware/recovery.h"
#include "tiny-firmware/firmware/reset.h"
#include "skycoin-crypto/tools/bip39.h"
#include "tiny-firmware/usb.h"
#include "skycoin-crypto/tools/base58.h"
#include "tiny-firmware/firmware/gettext.h"
#include "skycoin-crypto/skycoin_crypto.h"
#include "skycoin-crypto/check_digest.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "tiny-firmware/firmware/entropy.h"
#include "fsm_bitcoin_impl.h"

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void fsm_sendResponseFromErrCode(ErrCode_t err, const char *successMsg, const char *failMsg, MessageType *msgtype) {
    FailureType failure;
    switch (err) {
        case ErrOk:
            if (successMsg == NULL) {
                successMsg = _("Success");
            }
            fsm_sendSuccess(successMsg, msgtype);
            return;
        case ErrFailed:
            failure = FailureType_Failure_FirmwareError;
            break;
        case ErrInvalidArg:
            failure = FailureType_Failure_DataError;
            if (failMsg == NULL) {
                failMsg = _("Invalid argument");
            }
            break;
        case ErrPreconditionFailed:
            failure = FailureType_Failure_DataError;
            if (failMsg == NULL) {
                failMsg = _("Precondition failed");
            }
            break;
        case ErrIndexValue:
            failure = FailureType_Failure_DataError;
            if (failMsg == NULL) {
                failMsg = _("Index out of bounds");
            }
            break;
        case ErrInvalidValue:
            failure = FailureType_Failure_ProcessError;
            break;
        case ErrNotImplemented:
            failure = FailureType_Failure_FirmwareError;
            if (failMsg == NULL) {
                failMsg = _("Not Implemented");
            }
            break;
        case ErrInvalidChecksum:
            failure = FailureType_Failure_DataError;
            if (failMsg == NULL) {
                failMsg = _("Invalid checksum");
            }
            break;
        case ErrPinRequired:
            failure = FailureType_Failure_PinExpected;
            break;
        case ErrPinMismatch:
            failure = FailureType_Failure_PinMismatch;
            break;
        case ErrPinCancelled:
            failure = FailureType_Failure_PinCancelled;
            break;
        case ErrActionCancelled:
            failure = FailureType_Failure_ActionCancelled;
            break;
        case ErrNotInitialized:
            failure = FailureType_Failure_NotInitialized;
            break;
        case ErrMnemonicRequired:
            failure = FailureType_Failure_AddressGeneration;
            if (failMsg == NULL) {
                failMsg = _("Mnemonic required");
            }
            break;
        case ErrAddressGeneration:
            failure = FailureType_Failure_AddressGeneration;
            break;
        case ErrTooManyAddresses:
            failure = FailureType_Failure_AddressGeneration;
            if (failMsg == NULL) {
                failMsg = _("Too many addresses requested");
            }
            break;
        case ErrUnfinishedBackup:
            // FIXME: FailureType_Failure_ProcessError ?
            failure = FailureType_Failure_ActionCancelled;
            if (failMsg == NULL) {
                failMsg = _("Backup operation did not finish properly.");
            }
            break;
        case ErrUnexpectedMessage:
            failure = FailureType_Failure_UnexpectedMessage;
            break;
        case ErrSignPreconditionFailed:
            failure = FailureType_Failure_InvalidSignature;
            break;
        case ErrInvalidSignature:
            if (failMsg == NULL) {
                failMsg = _("Invalid signature.");
            }
            failure = FailureType_Failure_InvalidSignature;
            break;
        default:
            failure = FailureType_Failure_FirmwareError;
            failMsg = _("Unexpected firmware error");
            break;
    }
    fsm_sendFailure(failure, failMsg, msgtype);
}

void fsm_sendSuccess(const char *text, MessageType *msgtype) {
    RESP_INIT(Success);
    if (text) {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }
    if (msgtype) {
        resp->has_msg_type = true;
        resp->msg_type = *msgtype;
    } else {
        resp->has_msg_type = false;
    }
    msg_write(MessageType_MessageType_Success, resp);
}

void fsm_sendFailure(FailureType code, const char *text, MessageType *msgtype) {
    if (protectAbortedByInitialize) {
        fsm_msgInitialize((Initialize *) 0);
        protectAbortedByInitialize = false;
        return;
    }
    RESP_INIT(Failure);
    resp->has_code = true;
    resp->code = code;
    if (msgtype) {
        resp->has_msg_type = true;
        resp->msg_type = *msgtype;
    } else {
        resp->has_msg_type = false;
    }
    if (text == NULL) {
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
            case FailureType_Failure_FirmwarePanic:
                text = _("Firmware panic");
                break;
            default:
                text = _("Unknown failure error");
                break;
        }
    }
    if (text) {
        resp->has_message = true;
        strlcpy(resp->message, text, sizeof(resp->message));
    }
    msg_write(MessageType_MessageType_Failure, resp);
}

void fsm_msgInitialize(Initialize *msg) {
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

void fsm_msgApplySettings(ApplySettings *msg) {
    if (checkPin()) {
        return;
    }
    MessageType msgtype = MessageType_MessageType_ApplySettings;
    msg->has_label = msg->has_label && strlen(msg->label);
    msg->has_language = msg->has_language && strlen(msg->language);
    if (msg->has_label) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                          _("change name to"), msg->label, "?", NULL, NULL);
        if (checkButtonProtect()) { return; }
    }
    if (msg->has_language) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                          _("change language to"), msg->language, "?", NULL, NULL);
        if (checkButtonProtect()) { return; }
    }
    if (msg->has_use_passphrase) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                          msg->use_passphrase ? _("enable passphrase") : _("disable passphrase"), _("protection?"),
                          NULL, NULL, NULL);
        if (checkButtonProtect()) { return; }
    }
    if (msg->has_homescreen) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                          _("change the home"), _("screen?"), NULL, NULL, NULL);
        if (checkButtonProtect()) { return; }
    }

    ErrCode_t err = msgApplySettingsImpl(msg);
    char *failMsg = NULL;
    switch (err) {
        case ErrPreconditionFailed:
            failMsg = _("No setting provided");
            break;
        default:
            break;
    }
    fsm_sendResponseFromErrCode(err, _("Settings applied"), failMsg, &msgtype);
    layoutHome();
}

void fsm_msgGetFeatures(GetFeatures *msg) {
    (void) msg;
    RESP_INIT(Features);
    msgGetFeaturesImpl(resp);
    msg_write(MessageType_MessageType_Features, resp);
}

ErrCode_t requestConfirmTransaction(char *strCoin, char *strHour, TransactionSign *msg, uint32_t i) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Next"), NULL, _("Do you really want to"), strCoin, strHour,
                      _("to address"), _("..."), NULL);
    ErrCode_t err = checkButtonProtectRetErrCode();
    if (err != ErrOk) {
        return err;
    }
    layoutAddress(msg->transactionOut[i].address);
    err = checkButtonProtectRetErrCode();
    return err;
}

void fsm_msgPing(Ping *msg) {
    MessageType msgtype = MessageType_MessageType_Ping;
    if (msg->has_button_protection && msg->button_protection) {
        layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                          _("answer to ping?"), NULL, NULL, NULL, NULL);
        if (checkButtonProtect()) { return; }
    }

    ErrCode_t err = msgPingImpl(msg);
    if (err != ErrOk) {
        fsm_sendResponseFromErrCode(err, NULL, NULL, &msgtype);
    }
    layoutHome();
}

void fsm_msgChangePin(ChangePin *msg) {
    bool removal = msg->has_remove && msg->remove;
    MessageType msgtype = MessageType_MessageType_ChangePin;
    if (removal) {
        if (storage_hasPin()) {
            layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                              _("remove current PIN?"), NULL, NULL, NULL, NULL);
        } else {
            fsm_sendSuccess(_("PIN removed"), &msgtype);
            return;
        }
    } else {
        if (storage_hasPin()) {
            layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                              _("change current PIN?"), NULL, NULL, NULL, NULL);
        } else {
            layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                              _("set new PIN?"), NULL, NULL, NULL, NULL);
        }
    }

    if (checkButtonProtect()) { return; }
    if (checkPinUncached()) {
        return;
    }

    fsm_sendResponseFromErrCode(msgChangePinImpl(msg, &requestPin), (removal) ? _("PIN removed") : _("PIN changed"),
                                NULL, &msgtype);
    layoutHome();
}

void fsm_msgWipeDevice(WipeDevice *msg) {
    MessageType msgtype = MessageType_MessageType_WipeDevice;
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                      _("wipe the device?"), NULL, _("All data will be lost."), NULL, NULL);
    ErrCode_t err = protectButton(ButtonRequestType_ButtonRequest_WipeDevice, false) ? msgWipeDeviceImpl(msg)
                                                                                     : ErrActionCancelled;
    fsm_sendResponseFromErrCode(err, _("Device wiped"), NULL, &msgtype);
    layoutHome();
}

void fsm_msgGenerateMnemonic(GenerateMnemonic *msg) {
    MessageType msgtype = MessageType_MessageType_GenerateMnemonic;
    GET_MSG_POINTER(EntropyRequest, entropy_request);
    switch (msgGenerateMnemonicImpl(msg, &random_salted_buffer)) {
        case ErrNotInitialized:
            fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first."),
                            NULL);
            break;
        case ErrInvalidArg:
            fsm_sendFailure(FailureType_Failure_DataError,
                            _("Invalid word count expecified, the valid options are 12 or 24."), NULL);
            break;
        case ErrInvalidValue:
            fsm_sendFailure(FailureType_Failure_ProcessError, _("Device could not generate a valid Mnemonic"), NULL);
            break;
        case ErrInvalidChecksum:
            fsm_sendFailure(FailureType_Failure_DataError, _("Mnemonic with wrong checksum provided"), NULL);
            break;
        case ErrEntropyRequired:
            msg_write(MessageType_MessageType_EntropyRequest, entropy_request);
            break;
        case ErrOk:
            fsm_sendSuccess(_("Mnemonic successfully configured"), &msgtype);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_FirmwareError, _("Mnemonic generation failed"), &msgtype);
            break;
    }
    layoutHome();
}

void fsm_msgSetMnemonic(SetMnemonic *msg) {
    if (checkNotInitialized()) { return; }
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL, _("Writing seed"),
                      _("is not recommended."), _("Continue only if you"), _("know what you are"), _("doing!"), NULL);
    if (checkButtonProtect()) { return; }
    MessageType msgtype = MessageType_MessageType_GenerateMnemonic;
    ErrCode_t err = msgSetMnemonicImpl(msg);
    char *failMsg = (err == ErrInvalidValue) ? _("Mnemonic with wrong checksum provided") : NULL;
    fsm_sendResponseFromErrCode(err, msg->mnemonic, failMsg, &msgtype);
    layoutHome();
}

void fsm_msgGetRawEntropy(GetRawEntropy *msg) {
#if !DISABLE_GETENTROPY_CONFIRM
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                      _("send entropy?"), NULL, NULL, NULL, NULL);
    if (checkButtonProtect()) { return; }
#endif // DISABLE_GETENTROPY_CONFIRM
    MessageType msgtype = MessageType_MessageType_GetRawEntropy;
    RESP_INIT(Entropy);
    ErrCode_t ret = msgGetEntropyImpl(msg, resp, &_random_buffer);
    if (ret == ErrOk) {
        msg_write(MessageType_MessageType_Entropy, resp);
    } else {
        fsm_sendResponseFromErrCode(
                ret, NULL, _("Get raw entropy not implemented"), &msgtype);
    }
    layoutHome();
}

void fsm_msgGetMixedEntropy(GetMixedEntropy *_msg) {
#if !DISABLE_GETENTROPY_CONFIRM
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                      _("send entropy?"), NULL, NULL, NULL, NULL);
    if (checkButtonProtect()) { return; }
#endif // DISABLE_GETENTROPY_CONFIRM
    MessageType msgtype = MessageType_MessageType_GetMixedEntropy;
    RESP_INIT(Entropy);
    GetRawEntropy msg;
    msg.size = _msg->size;
    ErrCode_t ret = msgGetEntropyImpl(&msg, resp, &random_buffer);
    if (ret == ErrOk) {
        msg_write(MessageType_MessageType_Entropy, resp);
    } else {
        fsm_sendResponseFromErrCode(
                ret, NULL, _("Get mixed entropy not implemented"), &msgtype);
    }
    layoutHome();
}

void fsm_msgLoadDevice(LoadDevice *msg) {
    if (checkNotInitialized()) { return; }
    MessageType msgtype = MessageType_MessageType_LoadDevice;
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("I take the risk"), NULL, _("Loading private seed"),
                      _("is not recommended."), _("Continue only if you"), _("know what you are"), _("doing!"), NULL);
    if (checkButtonProtect()) { return; }

    ErrCode_t err = msgLoadDeviceImpl(msg);
    char *failMsg = (err == ErrInvalidValue) ? _("Mnemonic with wrong checksum provided") : NULL;
    fsm_sendResponseFromErrCode(err, _("Device loaded"), failMsg, &msgtype);
    layoutHome();
}

void fsm_msgResetDevice(ResetDevice *msg) {
    if (checkNotInitialized()) { return; }

    checkParam(!msg->has_strength || msg->strength == 128 || msg->strength == 192 || msg->strength == 256,
               _("Invalid seed strength"));

    reset_init(
            msg->has_display_random && msg->display_random,
            msg->has_strength ? msg->strength : 128,
            msg->has_passphrase_protection && msg->passphrase_protection,
            msg->has_pin_protection && msg->pin_protection,
            msg->has_language ? msg->language : 0,
            msg->has_label ? msg->label : 0,
            msg->has_skip_backup ? msg->skip_backup : false);
}

ErrCode_t confirmBackup(void) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you confirm you"),
                      _("backed up your seed."), _("This will never be"), _("possible again."), NULL, NULL);
    ErrCode_t err = checkButtonProtectRetErrCode();
    return err;
}

void fsm_msgBackupDevice(BackupDevice *msg) {
    if (checkInitialized() || checkPinUncached()) {
        return;
    }
    MessageType msgtype = MessageType_MessageType_BackupDevice;
    ErrCode_t err = msgBackupDeviceImpl(msg, &confirmBackup);
    switch (err) {
        case ErrOk:
            fsm_sendSuccess(_("Device backed up!"), &msgtype);
            break;
        case ErrUnexpectedMessage:
            fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Seed already backed up"), NULL);
            break;
        case ErrActionCancelled:
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, NULL);
            break;
        case ErrUnfinishedBackup:
            fsm_sendFailure(FailureType_Failure_ActionCancelled, _("Backup operation did not finish properly."), NULL);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_FirmwareError, _("Unexpected failure"), &msgtype);
            break;
    }
    if (err == ErrOk) {
        layoutHome();
    }
}

ErrCode_t confirmRecovery(void) {
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                      _("recover the device?"), NULL, NULL, NULL, NULL);
    ErrCode_t err = checkButtonProtectRetErrCode();
    return err;
}


void fsm_msgRecoveryDevice(RecoveryDevice *msg) {
    MessageType msgtype = MessageType_MessageType_RecoveryDevice;
    ErrCode_t err = msgRecoveryDeviceImpl(msg, &confirmRecovery);
    switch (err) {
        case ErrPinRequired:
            fsm_sendFailure(FailureType_Failure_PinExpected, _("Expected pin"), NULL);
            break;
        case ErrNotInitialized:
            fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device is already initialized. Use Wipe first."),
                            NULL);
            break;
        case ErrInitialized:
            fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Device it's not inizialized"), NULL);
            break;
        case ErrInvalidArg:
            fsm_sendFailure(FailureType_Failure_DataError, _("Invalid word count"), NULL);
            break;
        case ErrActionCancelled:
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, NULL);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_FirmwareError, _("Unexpected failure"), &msgtype);
            break;
    }
    if (err != ErrActionCancelled && err != ErrOk) {
        layoutHome();
    }
}

void fsm_msgWordAck(WordAck *msg) {
    recovery_word(msg->word);
}

void fsm_msgCancel(Cancel *msg) {
    MessageType msgtype = MessageType_MessageType_Cancel;
    (void) msg;
    recovery_abort();
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, &msgtype);
}

void fsm_msgEntropyAck(EntropyAck *msg) {
    MessageType msgtype = MessageType_MessageType_EntropyAck;
    switch (msgEntropyAckImpl(msg)) {
        case ErrUnexpectedMessage:
            fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Unexpected entropy ack msg."), &msgtype);
            break;
        case ErrOk:
            fsm_sendSuccess(_("Received entropy"), &msgtype);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_FirmwareError, _("Entropy ack failed."), &msgtype);
            break;
    }
}

void fsm_msgSignTx(SignTx *msg) {

    if (checkPin() || checkMnemonic()) {
        return;
    }


    MessageType msgtype = MessageType_MessageType_SignTx;
    RESP_INIT(TxRequest)
    ErrCode_t err = msgSignTxImpl(msg, resp);
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_TxRequest, resp);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_ProcessError, _("Signing transaction failed."), &msgtype);
            break;
    }
    return;
}

void fsm_msgTxAck(TxAck *msg) {

    if (checkPin() || checkMnemonic()) {
        return;
    }

    MessageType msgType = MessageType_MessageType_TxAck;
    RESP_INIT(TxRequest);
    ErrCode_t err = msgTxAckImpl(msg, resp);
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_TxRequest, resp);
            break;
        case ErrInvalidArg:
            fsm_sendFailure(FailureType_Failure_DataError, _("Invalid data on TxAck message."), &msgType);
            break;
        case ErrActionCancelled:
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, &msgType);
            break;
        case ErrFailed:
            fsm_sendFailure(FailureType_Failure_ProcessError, NULL, &msgType);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_ProcessError, _("Signing transaction failed."), &msgType);
            break;
    }
    layoutHome();
    return;
}

void fsm_msgBitcoinTxAck(BitcoinTxAck *msg) {

    if (checkPin() || checkMnemonic()) {
        return;
    }

    MessageType msgType = MessageType_MessageType_BitcoinTxAck;
    RESP_INIT(TxRequest);
    ErrCode_t err = msgBitcoinTxAckImpl(msg, resp);
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_TxRequest, resp);
            break;
        case ErrInvalidArg:
            fsm_sendFailure(FailureType_Failure_DataError, _("Invalid data on BitcoinTxAck message."), &msgType);
            break;
        case ErrActionCancelled:
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, &msgType);
            break;
        case ErrFailed:
            fsm_sendFailure(FailureType_Failure_ProcessError, NULL, &msgType);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_ProcessError, _("Signing transaction failed."), &msgType);
            break;
    }
    layoutHome();
    return;
}
