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

#include "tiny-firmware/firmware/fsm_skycoin.h"
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
#include "skycoin-crypto/skycoin_constants.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/firmware/fsm_skycoin_impl.h"
#include "tiny-firmware/buttons.h"

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void fsm_msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature *msg) {
    GET_MSG_POINTER(Success, successResp);
    GET_MSG_POINTER(Failure, failureResp);
    uint16_t msg_id = MessageType_MessageType_Failure;
    void *msg_ptr = failureResp;
    switch (msgSkycoinCheckMessageSignatureImpl(msg, successResp, failureResp)) {
        case ErrOk:
            msg_id = MessageType_MessageType_Success;
            msg_ptr = successResp;
            layoutRawMessage("Verification success");
            break;
        case ErrAddressGeneration:
        case ErrInvalidSignature:
            failureResp->code = FailureType_Failure_InvalidSignature;
            layoutRawMessage("Wrong signature");
            break;
        default:
            strncpy(failureResp->message, _("Firmware error."), sizeof(failureResp->message));
            layoutHome();
            break;
    }
    msg_write(msg_id, msg_ptr);
}

void fsm_msgSkycoinSignMessage(SkycoinSignMessage *msg) {
    if (checkMnemonic() || checkPinUncached()) {
        return;
    }
    RESP_INIT(ResponseSkycoinSignMessage);

    MessageType msgtype = MessageType_MessageType_SkycoinSignMessage;
    ResponseSkycoinAddress respAddr;
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    ErrCode_t err = fsm_getKeyPairAtIndex(1, pubkey, seckey, &respAddr, msg->address_n, &skycoin_address_from_pubkey,
                                          true);
    if (err != ErrOk) {
        fsm_sendResponseFromErrCode(err, NULL, _("Unable to get keys pair"), &msgtype);
        layoutHome();
        return;
    }
    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL, _("Do you really want to"),
                      _("sign message using"), _("this address?"), respAddr.addresses[0], NULL, NULL);
    if (checkButtonProtect()) { return; }

    err = msgSkycoinSignMessageImpl(msg, resp);
    if (err == ErrOk) {
        msg_write(MessageType_MessageType_ResponseSkycoinSignMessage, resp);
        layoutRawMessage("Signature success");
        do {
            delay(100000);
            buttonUpdate();
        } while (!button.YesUp && !button.NoUp);
    } else {
        char *failMsg = NULL;
        if (err == ErrMnemonicRequired) {
            failMsg = _("Mnemonic not set");
        }
        fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
    }
    layoutHome();
}

void fsm_msgSkycoinAddress(SkycoinAddress *msg) {
    MessageType msgtype = MessageType_MessageType_SkycoinAddress;
    RESP_INIT(ResponseSkycoinAddress);
    char *failMsg = NULL;
    ErrCode_t err = msgSkycoinAddressImpl(msg, resp);
    switch (err) {
        case ErrUserConfirmation:
            layoutAddress(resp->addresses[0]);
            if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
                err = ErrActionCancelled;
                break;
            }
            // fall through
        case ErrOk:
            msg_write(MessageType_MessageType_ResponseSkycoinAddress, resp);
            layoutHome();
            return;
        case ErrPinRequired:
            failMsg = _("Expected pin");
            break;
        case ErrTooManyAddresses:
            failMsg = _("Asking for too much addresses");
            break;
        case ErrMnemonicRequired:
            failMsg = _("Mnemonic required");
            break;
        case ErrAddressGeneration:
            failMsg = _("Key pair generation failed");
            break;
        default:
            break;
    }
    fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
    layoutHome();
}

void fsm_msgTransactionSign(TransactionSign *msg) {
    if (checkPin() || checkMnemonic() || checkInputs(msg) || checkOutputs(msg)) {
        return;
    }

    MessageType msgtype = MessageType_MessageType_TransactionSign;
    RESP_INIT(ResponseTransactionSign);
    ErrCode_t err = msgTransactionSignImpl(msg, &requestConfirmTransaction, resp);
    char *failMsg = NULL;
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_ResponseTransactionSign, resp);
            break;
        case ErrAddressGeneration:
            failMsg = _("Wrong return address");
            // fall through
        default:
            fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
            break;
    }
    layoutHome();
}
