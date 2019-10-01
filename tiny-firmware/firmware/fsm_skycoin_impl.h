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

#ifndef __FSM_SKYCOIN_IMPL_H__
#define __FSM_SKYCOIN_IMPL_H__

#include "messages.pb.h"
#include "tiny-firmware/firmware/error.h"

ErrCode_t
msgSkycoinCheckMessageSignatureImpl(SkycoinCheckMessageSignature *msg, Success *successResp, Failure *failureResp);

ErrCode_t msgSkycoinSignMessageImpl(SkycoinSignMessage *msg, ResponseSkycoinSignMessage *msg_resp);

ErrCode_t msgSkycoinAddressImpl(SkycoinAddress *msg, ResponseSkycoinAddress *resp);

ErrCode_t msgTransactionSignImpl(TransactionSign *msg, ErrCode_t (*)(char *, char *, TransactionSign *, uint32_t),
                                 ResponseTransactionSign *);

#endif
