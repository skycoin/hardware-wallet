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

#ifndef __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
#define __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__

#include "messages.pb.h"
#include "tiny-firmware/firmware/error.h"

#define MNEMONIC_WORD_COUNT_12 12
#define MNEMONIC_WORD_COUNT_24 24

// message methods
#define GET_MSG_POINTER(TYPE, VarName)                                       \
    TYPE* VarName = (TYPE*)(void*)msg_resp;                                  \
    _Static_assert(sizeof(msg_resp) >= sizeof(TYPE), #TYPE " is too large"); \
    memset(VarName, 0, sizeof(TYPE));

#define RESP_INIT(TYPE) GET_MSG_POINTER(TYPE, resp);

bool checkInitialized(void);

bool checkNotInitialized(void);

bool checkPin(void);

bool checkPinUncached(void);

bool checkParam(bool cond, const char *errormsg);

bool checkPrecondition(bool cond, const char *errormsg);

bool checkButtonProtect(void);

ErrCode_t checkButtonProtectRetErrCode(void);

bool checkMnemonic(void);

bool checkInputs(TransactionSign *msg);

bool checkOutputs(TransactionSign *msg);

bool checkMnemonicChecksum(SetMnemonic *msg);

ErrCode_t
fsm_getKeyPairAtIndex(uint32_t nbAddress, uint8_t *pubkey, uint8_t *seckey, ResponseSkycoinAddress *respSkycoinAddress,
                      uint32_t start_index);

ErrCode_t msgGenerateMnemonicImpl(GenerateMnemonic *msg, void (*random_buffer_func)(uint8_t *buf, size_t len));

ErrCode_t msgEntropyAckImpl(EntropyAck *msg);

ErrCode_t msgSignTransactionMessageImpl(uint8_t *message_digest, uint32_t index, char *signed_message);

ErrCode_t msgApplySettingsImpl(ApplySettings *msg);

ErrCode_t msgGetFeaturesImpl(Features *resp);

ErrCode_t msgPingImpl(Ping *msg);

ErrCode_t msgChangePinImpl(ChangePin *msg, const char *(*)(PinMatrixRequestType, const char *));

ErrCode_t msgWipeDeviceImpl(WipeDevice *msg);

ErrCode_t msgSetMnemonicImpl(SetMnemonic *msg);

ErrCode_t msgGetEntropyImpl(GetRawEntropy *msg, Entropy *resp, void (*random_buffer_func)(uint8_t *buf, size_t len));

ErrCode_t msgLoadDeviceImpl(LoadDevice *msg);

ErrCode_t msgBackupDeviceImpl(BackupDevice *msg, ErrCode_t (*)(void));

ErrCode_t msgRecoveryDeviceImpl(RecoveryDevice *msg, ErrCode_t (*)(void));

ErrCode_t msgSignTxImpl(SignTx *msg, TxRequest *resp);

ErrCode_t msgTxAckImpl(TxAck *msg, TxRequest *resp);

ErrCode_t reqConfirmTransaction(uint64_t coins, uint64_t hours, char *address);

#endif // __TINYFIRMWARE_FIRMWARE_FSMIMPL_H__
