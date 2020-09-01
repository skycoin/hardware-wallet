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

#ifndef __FSM_BITCOIN_IMPL_H__
#define __FSM_BITCOIN_IMPL_H__

#include "bitcoin_messages.pb.h"
#include "tiny-firmware/firmware/error.h"

typedef struct Script{
  uint32_t OP_DUP;
  uint32_t OP_HASH160;
  uint32_t PUSHDATA;
  uint32_t pubKeyHash;
  uint32_t OP_EQUALVERIFY;
  uint32_t OP_CHECKSIG;
}

typedef struct BTC_Tx_Output{
  uint32_t nbOut;
  uint32_t value;
  uint32_t lockScriptLen;
  Script lScript;
  uint32_t locktime;
}

typedef struct BTC_TxInput{
  uint32_t version;
  uint32_t nbIn;
  uint32_t txHash;
  uint32_t outputIndex;
  uint32_t unlockScriptLen;
  Script uScript;
  uint32_t sequence;
}

typedef struct BitcoinTX{
  BTC_TxInput input;
  BTC_Tx_Output output;
}

ErrCode_t msgBitcoinAddressImpl(BitcoinAddress *msg, ResponseSkycoinAddress *resp);
ErrCode_t reqConfirmBitcoinTransaction(uint64_t coins, char *address);
ErrCode_t msgSignBitcoinTransactionMessageImpl(uint8_t *message_digest, uint32_t index, char *signed_message);
ErrCode_t msgBitcoinTxAckImpl(BitcoinTxAck *msg, TxRequest *resp);

#endif
