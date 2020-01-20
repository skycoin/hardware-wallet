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

#include <libopencm3/stm32/flash.h>
#include <stdio.h>
#include <inttypes.h>

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
#include "skycoin-crypto/skycoin_crypto.h"
#include "skycoin-crypto/skycoin_signature.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "fsm_skycoin_impl.h"

ErrCode_t
msgSkycoinCheckMessageSignatureImpl(SkycoinCheckMessageSignature *msg, Success *successResp, Failure *failureResp) {
    // NOTE(): -1 because the end of string ('\0')
    // /2 because the hex to buff conversion.
    _Static_assert((sizeof(msg->message) - 1) / 2 == SHA256_DIGEST_LENGTH,
                   "Invalid buffer size for message");
    _Static_assert((sizeof(msg->signature) - 1) / 2 == SKYCOIN_SIG_LEN,
                   "Invalid buffer size for signature");
    uint8_t sig[SKYCOIN_SIG_LEN] = {0};
    // NOTE(): -1 because the end of string ('\0')
    char address[sizeof(msg->address) - 1];
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    if (is_sha256_digest_hex(msg->message)) {
        tobuff(msg->message, digest, MIN(sizeof(digest), sizeof(msg->message)));
    } else {
        sha256sum((const uint8_t *) msg->message, digest, strlen(msg->message));
    }
    tobuff(msg->signature, sig, sizeof(sig));
    ErrCode_t ret = (skycoin_ecdsa_verify_digest_recover(sig, digest, pubkey) == 0) ? ErrOk : ErrInvalidSignature;
    if (ret != ErrOk) {
        strncpy(failureResp->message, _("Address recovery failed"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrInvalidSignature;
    }
    if (!verify_pub_key(pubkey)) {
        strncpy(failureResp->message, _("Can not verify pub key"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrAddressGeneration;
    }
    size_t address_size = sizeof(address);
    if (!skycoin_address_from_pubkey(pubkey, address, &address_size)) {
        strncpy(failureResp->message, _("Can not verify pub key"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrAddressGeneration;
    }
    if (memcmp(address, msg->address, address_size)) {
        strncpy(failureResp->message, _("Address does not match"), sizeof(failureResp->message));
        failureResp->has_message = true;
        return ErrInvalidSignature;
    }
    memcpy(successResp->message, address, address_size);
    successResp->has_message = true;
    return ErrOk;
}

ErrCode_t msgSkycoinSignMessageImpl(SkycoinSignMessage *msg, ResponseSkycoinSignMessage *resp) {
    // NOTE: twise the SKYCOIN_SIG_LEN because the hex format
    _Static_assert(sizeof(resp->signed_message) >= 2 * SKYCOIN_SIG_LEN,
                   "hex SKYCOIN_SIG_LEN do not fit in the response");
    if (storage_hasMnemonic() == false) {
        return ErrMnemonicRequired;
    }
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    uint8_t signature[SKYCOIN_SIG_LEN];
    if (fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, msg->address_n, &skycoin_address_from_pubkey) != ErrOk) {
        return ErrInvalidValue;
    }
    if (is_sha256_digest_hex(msg->message)) {
        writebuf_fromhexstr(msg->message, digest);
    } else {
        sha256sum((const uint8_t *) msg->message, digest, strlen(msg->message));
    }
    int res = skycoin_ecdsa_sign_digest(seckey, digest, signature);
    if (res == -2) {
        // Fail due to empty digest
        return ErrInvalidArg;
    } else if (res) {
        // Too many retries without a valid signature
        // -> fail with an error
        return ErrFailed;
    }
    const size_t hex_len = 2 * SKYCOIN_SIG_LEN;
    char signature_in_hex[hex_len];
    tohex(signature_in_hex, signature, SKYCOIN_SIG_LEN);
    memcpy(resp->signed_message, signature_in_hex, hex_len);
    return ErrOk;
}

ErrCode_t msgSkycoinAddressImpl(SkycoinAddress *msg, ResponseSkycoinAddress *resp) {
    uint8_t seckey[32] = {0};
    uint8_t pubkey[33] = {0};
    uint32_t start_index = !msg->has_start_index ? 0 : msg->start_index;
    if (!protectPin(true)) {
        return ErrPinRequired;
    }
    if (msg->address_n > 99) {
        return ErrTooManyAddresses;
    }

    if (storage_hasMnemonic() == false) {
        return ErrMnemonicRequired;
    }

    if (fsm_getKeyPairAtIndex(msg->address_n, pubkey, seckey, resp, start_index, &skycoin_address_from_pubkey) != ErrOk) {
        return ErrAddressGeneration;
    }
    if (msg->address_n == 1 && msg->has_confirm_address && msg->confirm_address) {
        return ErrUserConfirmation;
    }
    return ErrOk;
}

ErrCode_t
msgTransactionSignImpl(TransactionSign *msg, ErrCode_t (*funcConfirmTxn)(char *, char *, TransactionSign *, uint32_t),
                       ResponseTransactionSign *resp) {
    if (msg->nbIn > sizeof(msg->transactionIn) / sizeof(*msg->transactionIn)) {
        return ErrInvalidArg;
    }
    if (msg->nbOut > sizeof(msg->transactionOut) / sizeof(*msg->transactionOut)) {
        return ErrInvalidArg;
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
        char *hourString = (msg->transactionOut[i].hour == 1 || msg->transactionOut[i].hour == 0) ? _("hour") : _(
                "hours");
        char *strValueMsg = sprint_coins(msg->transactionOut[i].coin, SKYPARAM_DROPLET_PRECISION_EXP, sizeof(strValue),
                                         strValue);
        if (strValueMsg == NULL) {
            // FIXME: For Skycoin coin supply and precision buffer size should be enough
            strcpy(strCoin, "too many coins");
        }
        sprintf(strCoin, "%s %s %s", _("send"), strValueMsg, coinString);
        sprintf(strHour, "%"
        PRIu64
        " %s", msg->transactionOut[i].hour, hourString);

        if (msg->transactionOut[i].has_address_index) {
            uint8_t pubkey[33] = {0};
            uint8_t seckey[32] = {0};
            size_t size_address = 36;
            char address[36] = {0};
            ErrCode_t ret = fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, msg->transactionOut[i].address_index, &skycoin_address_from_pubkey);
            if (ret != ErrOk) {
                return ret;
            }
            if (!skycoin_address_from_pubkey(pubkey, address, &size_address)) {
                return ErrAddressGeneration;
            }
            if (strcmp(msg->transactionOut[i].address, address) != 0) {
                // fsm_sendFailure(FailureType_Failure_AddressGeneration, _("Wrong return address"));
#if EMULATOR
                printf("Internal address: %s, message address: %s\n", address, msg->transactionOut[i].address);
                printf("Comparaison size %ld\n", size_address);
#endif
                return ErrAddressGeneration;
            }
        } else {
            // NOTICE: A single output per address is assumed
            ErrCode_t err = funcConfirmTxn(strCoin, strHour, msg, i);
            if (err != ErrOk)
                return err;
        }
        transaction_addOutput(&transaction, msg->transactionOut[i].coin, msg->transactionOut[i].hour,
                              msg->transactionOut[i].address);
    }

    if (!protectPin(false)) {
        return ErrPinRequired;
    }

    for (uint32_t i = 0; i < msg->nbIn; ++i) {
        uint8_t digest[32] = {0};
        transaction_msgToSign(&transaction, i, digest);
        // Only sign inputs owned by Skywallet device
        if (msg->transactionIn[i].has_index) {
            if (msgSignTransactionMessageImpl(digest, msg->transactionIn[i].index,
                                              resp->signatures[resp->signatures_count]) != ErrOk) {
                //fsm_sendFailure(FailureType_Failure_InvalidSignature, NULL);
                //layoutHome();
                return ErrInvalidSignature;
            }
        } else {
            // Null sig
            uint8_t signature[65];
            memset(signature, 0, sizeof(signature));
            tohex(resp->signatures[resp->signatures_count], signature, sizeof(signature));
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
    if (resp->signatures_count != msg->nbIn) {
        // Ensure number of sigs and inputs is the same. Mismatch should never happen.
        return ErrFailed;
    }
#if EMULATOR
    char str[64];
    tohex(str, transaction.innerHash, 32);
    printf("InnerHash %s\n", str);
    printf("Signed message:  %s\n", resp->signatures[0]);
    printf("Nb signatures: %d\n", resp->signatures_count);
#endif
    //layoutHome();
    return ErrOk;
}
