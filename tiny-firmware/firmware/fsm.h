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

#ifndef __FSM_H__
#define __FSM_H__

#include "messages.pb.h"
#include "bitcoin_messages.pb.h"
#include "tiny-firmware/firmware/error.h"
#include "skycoin-crypto/tools/bip32.h"

// message functions

#define MAX_MNEMONIC_LEN 240

void fsm_sendSuccess(const char* text, MessageType* msgtype);

void fsm_sendFailure(FailureType code, const char* text, MessageType* msgtype);

void fsm_sendResponseFromErrCode(ErrCode_t err, const char *successMsg, const char *failMsg, MessageType *msgtype);

void fsm_msgInitialize(Initialize* msg);
void fsm_msgGetFeatures(GetFeatures* msg);
void fsm_msgApplySettings(ApplySettings* msg);
void fsm_msgGenerateMnemonic(GenerateMnemonic* msg);
void fsm_msgSetMnemonic(SetMnemonic* msg);
void fsm_msgPing(Ping* msg);
void fsm_msgChangePin(ChangePin* msg);
void fsm_msgWipeDevice(WipeDevice* msg);
void fsm_msgGetRawEntropy(GetRawEntropy* msg);
void fsm_msgGetMixedEntropy(GetMixedEntropy* msg);
void fsm_msgEntropyAck(EntropyAck* msg);
void fsm_msgLoadDevice(LoadDevice* msg);
void fsm_msgResetDevice(ResetDevice* msg);
void fsm_msgBackupDevice(BackupDevice* msg);
void fsm_msgPinMatrixAck(PinMatrixAck* msg);
void fsm_msgCancel(Cancel* msg);
void fsm_msgRecoveryDevice(RecoveryDevice* msg);
void fsm_msgWordAck(WordAck* msg);
void fsm_msgSignTx(SignTx* msg);
void fsm_msgTxAck(TxAck* msg);
void fsm_msgBitcoinTxAck(BitcoinTxAck* msg);
int fsm_getBitcoinBIP39_Seed(uint8_t seed[]);
HDNode* fsm_getDerivedNode(const char *curve, const int coinType);
ErrCode_t requestConfirmTransaction(char *strCoin, char *strHour, TransactionSign *msg, uint32_t i);

#endif
