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
#include "skycoin-crypto/tools/bip44_coins.h"
#include "skycoin-crypto/check_digest.h"
#include "skycoin-crypto/tools/curves.h"
#include "tiny-firmware/firmware/droplet.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/hd_wallet.h"
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
#include "skycoin-crypto/bitcoin_constants.h"
#include "skycoin-crypto/bitcoin_crypto.h"
#include "skycoin-crypto/skycoin_signature.h"
#include "tiny-firmware/firmware/skyparams.h"
#include "fsm_bitcoin_impl.h"

ErrCode_t msgBitcoinAddressImpl(BitcoinAddress *msg, ResponseSkycoinAddress *resp) {

  if (msg->address_n > 99) {
      return ErrTooManyAddresses;
  }

  if (storage_hasMnemonic() == false) {
      return ErrMnemonicRequired;
  }

  HDNode* node = fsm_getDerivedNode(SECP256K1_NAME, BIP44_BITCOIN);
  HDNode addressNode;
  size_t size_address = 36;

  for(uint32_t i = msg->start_index; i < (msg->start_index + msg->address_n); i++){
    memcpy(&addressNode, node, sizeof(HDNode));
    hdnode_private_ckd(&addressNode, i);
    hdnode_fill_public_key(&addressNode);

    if(bitcoin_address_from_pubkey(addressNode.public_key, resp->addresses[resp->addresses_count], &size_address) != 1){
      return ErrAddressGeneration;
    }

    resp->addresses_count++;
  }

  return ErrOk;
}
