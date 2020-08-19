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

 #include <stdio.h>
 #include <inttypes.h>

 #include "tiny-firmware/firmware/droplet.h"
 #include "tiny-firmware/firmware/entropy.h"
 #include "tiny-firmware/firmware/fsm_impl.h"
 #include "tiny-firmware/firmware/gettext.h"
 #include "tiny-firmware/firmware/layout2.h"
 #include "tiny-firmware/firmware/storage.h"
 #include "tiny-firmware/firmware/protect.h"
 #include "tiny-firmware/firmware/recovery.h"
 #include "tiny-firmware/firmware/skyparams.h"

 #include "tiny-firmware/oled.h"

 #include "skycoin-crypto/tools/base58.h"
 #include "skycoin-crypto/tools/ecdsa.h"
 #include "skycoin-crypto/bitcoin_constants.h"
 #include "skycoin-crypto/bitcoin_crypto.h"
 #include "skycoin-crypto/skycoin_crypto.h"

 #include "fsm_bitcoin_impl.h"

ErrCode_t msgBitcoinAddressImpl(BitcoinAddress *msg, ResponseSkycoinAddress *resp) {
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

    if (fsm_getKeyPairAtIndex(msg->address_n, pubkey, seckey, resp, start_index, &bitcoin_address_from_pubkey) != ErrOk) {
        return ErrAddressGeneration;
    }
    if (msg->address_n == 1 && msg->has_confirm_address && msg->confirm_address) {
        return ErrUserConfirmation;
    }
    return ErrOk;
}

ErrCode_t reqConfirmBitcoinTransaction(uint64_t coins, char *address) {
    char strCoins[32];
    char strValue[20];
    char *coinString = coins == 1000000 ? _("coin") : _("coins");
    char *strValueMsg = sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, sizeof(strValue), strValue);
    sprintf(strCoins, "%s %s %s", _("send"), strValueMsg, coinString);

    layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Next"), NULL, _("Do you really want to"), strCoins,
                      _("to address"), _("..."), NULL, NULL);
    ErrCode_t err = checkButtonProtectRetErrCode();
    if (err != ErrOk) {
        return err;
    }
    layoutAddress(address);
    err = checkButtonProtectRetErrCode();
    return err;
}

ErrCode_t msgSignBitcoinTransactionMessageImpl(uint8_t *message_digest, uint32_t index, char *signed_message) {
    uint8_t pubkey[BITCOIN_PUBKEY_LEN] = {0};
    uint8_t seckey[BITCOIN_SECKEY_LEN] = {0};
    uint8_t signature_rs[BITCOIN_RS_SIG_LEN];
    uint8_t signature_der[BITCOIN_DER_SIG_LEN];
    ErrCode_t res = fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, index, &bitcoin_address_from_pubkey);
    if (res != ErrOk) {
        return res;
    }
    int signres = skycoin_ecdsa_sign_digest(seckey, message_digest, signature_rs);
    if (signres == -2) {
        // Fail due to empty digest
        return ErrInvalidArg;
    } else if (res) {
        // Too many retries without a valid signature
        // -> fail with an error
        return ErrFailed;
    }
    int len = ecdsa_sig_to_der(signature_rs, signature_der);
    tohex(signed_message, signature_der, len);
#if EMULATOR
    printf("Size_sign: %d, sig(hex): %s\n", len * 2, signed_message);
#endif
    return res;
}

ErrCode_t msgBitcoinTxAckImpl(BitcoinTxAck *msg, TxRequest *resp) {
    TxSignContext *ctx = TxSignCtx_Get();
    if (ctx->state != Start && ctx->state != BTC_Outputs && ctx->state != BTC_Signature) {
        TxSignCtx_Destroy(ctx);
        return ErrInvalidArg;
    }
#if EMULATOR
    switch (ctx->state) {
        case BTC_Outputs:
            printf("-> Outputs\n");
            break;
        case BTC_Signature:
            printf("-> Signatures\n");
            break;
        default:
            printf("-> Unexpected: %d\n", ctx->state);
            break;
    }
    for (uint32_t i = 0; i < msg->tx.inputs_cnt; ++i) {
        printf("   %d - Input: prev_hash: %s \n", i + 1,
               msg->tx.inputs[i].prev_hash.bytes);
        printf("\n");
    }
    for (uint32_t i = 0; i < msg->tx.outputs_count; ++i) {
        printf("   %d - Output: coins: %" PRIu64 ", address: %s\n", i + 1, msg->tx.outputs[i].coin,
               msg->tx.outputs[i].address);
    }
#endif
    if (ctx->mnemonic_change) {
        TxSignCtx_Destroy(ctx);
        return ErrFailed;
    }
    switch (ctx->state) {
        case BTC_Outputs:
            if (!msg->tx.outputs_count || msg->tx.inputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            TransactionOutput outputs[7];
            for (uint8_t i = 0; i < msg->tx.outputs_count; ++i) {
#if !EMULATOR
                ErrCode_t err = reqConfirmBitcoinTransaction(msg->tx.outputs[i].coin, msg->tx.outputs[i].address);
                if (err != ErrOk)
                    return err;
#endif
                outputs[i].coin = msg->tx.outputs[i].coin;
                size_t len = 36;
                uint8_t b58string[36];
                b58tobin(b58string, &len, msg->tx.outputs[i].address);
                memcpy(outputs[i].address, &b58string[36 - len], len);
                ctx->current_nbOut++;
            }
            if (ctx->current_nbOut != ctx->nbOut) {
                resp->request_type = TxRequest_RequestType_TXOUTPUT;
            } else {
                ctx->state = BTC_Signature;
                ctx->current_nbIn = 0;
                resp->request_type = TxRequest_RequestType_TXINPUT;
            }
            break;
        case BTC_Signature:
            if (!msg->tx.inputs_count || msg->tx.outputs_count) {
                TxSignCtx_Destroy(ctx);
                return ErrInvalidArg;
            }
            uint8_t signCount = 0;
            for (uint8_t i = 0; i < msg->tx.inputs_count; ++i) {
                ErrCode_t err = msgSignBitcoinTransactionMessageImpl(msg->tx.inputs->prev_hash.bytes,
                                                                     msg->tx.inputs[i].index,
                                                                     resp->sign_result[signCount].signature);
                if (err != ErrOk)
                    return err;
                resp->sign_result[signCount].has_signature = true;
                resp->sign_result[signCount].has_signature_index = true;
                resp->sign_result[signCount].signature_index = i;
                signCount++;
            }
            ctx->current_nbIn += signCount;
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
