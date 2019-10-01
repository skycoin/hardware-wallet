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

#ifndef __FSM_SKYCOIN_H__
#define __FSM_SKYCOIN_H__

#include "messages.pb.h"

void fsm_msgSkycoinCheckMessageSignature(SkycoinCheckMessageSignature *msg);
void fsm_msgSkycoinSignMessage(SkycoinSignMessage *msg);
void fsm_msgSkycoinAddress(SkycoinAddress* msg);
void fsm_msgTransactionSign(TransactionSign* msg);

#endif
