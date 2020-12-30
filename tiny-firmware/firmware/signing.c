#include "skycoin-crypto/skycoin_crypto.h"
#include "skycoin-crypto/bitcoin_constants.h"
#include "skycoin-crypto/tools/sha2.h"
#include "skycoin-crypto/tools/base58.h"
#include "skycoin-crypto/tools/hasher.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/signing.h"

#include <stdio.h>

/*
Computes PKH of input address
*/

ErrCode_t get_pubkeyhash(uint8_t* script, uint8_t address_n){

  uint8_t pubkey[BITCOIN_PUBKEY_LEN] = {0};
  uint8_t seckey[BITCOIN_SECKEY_LEN] = {0};

  char address[36] = {""};
  uint8_t addrhex[25] = {0};
  size_t sz = sizeof(addrhex);
  size_t addresslen = 36;

  //get private/public keypair
  ErrCode_t res = fsm_getKeyPairAtIndex(1, pubkey, seckey, NULL, address_n, &bitcoin_address_from_pubkey);

  if (res != ErrOk) {
      return res;
  }

  //compute pubkeyhash

  if (!bitcoin_address_from_pubkey(pubkey, address, &addresslen)) {
      return ErrFailed;
  }

  b58tobin(addrhex, &sz, address);

  compile_script(addrhex + 1, script);

  return ErrOk;
}

/*
Setting prefix if Tx in Hasher
*/
void BTC_TxAddPrefix(Hasher* hasher, uint32_t tx_version){

  uint8_t version[VERSION_LENGTH] = {0};

  //Version should be 4 bytes entry in little endian format
  for(size_t i = 0; i < VERSION_LENGTH; i++){

    version[i] = (tx_version >> i * 8);

  }
  hasher_Update(hasher, version, VERSION_LENGTH);
}

/*
Setting input of Tx to Hasher
*/
void BTC_TxUpdateInput(Hasher* hasher, BitcoinTransactionInput* inputs,
                        uint8_t* pubkeyhash, size_t i){

    uint8_t tx_id[TXID_LENGTH] = {0};
    uint8_t prev_output_index[VERSION_LENGTH] = {0};
    uint8_t script_len = SCRIPT_LENGTH;

    //set previous tx_id in little endian format (reverse)
    for(size_t k = 0; k < TXID_LENGTH; k++){

      tx_id[k] = inputs[i].prev_hash.bytes[TXID_LENGTH - 1 - k];

    }

    hasher_Update(hasher, tx_id, TXID_LENGTH);

    //set previous output index (4 byte entry in little endian format)
    for(size_t k = 0; k < VERSION_LENGTH; k++){

      prev_output_index[k] = (inputs[i].index >> k * 8);

    }

    hasher_Update(hasher, prev_output_index, VERSION_LENGTH);

    //set script length
    hasher_Update(hasher, &(script_len), 1);

    //set temporary unlocking script
    hasher_Update(hasher, pubkeyhash, SCRIPT_LENGTH);

}

/*
Setting outputs of Tx to Hasher
*/

void BTC_TxUpdateOutput(Hasher* hasher, BitcoinTransactionOutput* outputs, uint8_t* pubkeyhash, size_t i){

    uint8_t amount[8] = {0};
    uint8_t script_len = SCRIPT_LENGTH;

    //set amount of money (8 byte long entry in little endian format)
    for(size_t k = 0; k < 8; k++){

      amount[k] = (outputs[i].coin >> k * 8);

    }

    hasher_Update(hasher, amount, 8);

    //set script length
    hasher_Update(hasher, &(script_len), 1);

    //set script
    hasher_Update(hasher, pubkeyhash, SCRIPT_LENGTH);

}

ErrCode_t sign_tx(SignTx* msg, TxRequest* resp){
  TxSignContext *context = TxSignCtx_Get();
  if (context->state != Destroyed) {
      TxSignCtx_Destroy(context);
      return ErrFailed;
  }

  // Init TxSignContext
  context = TxSignCtx_Init();
  if (context->mnemonic_change) {
      TxSignCtx_Destroy(context);
      return ErrFailed;
  }
  memcpy(context->coin_name, msg->coin_name, 36 * sizeof(char));

  msg->coin_name[7] = '\0';
  context->state = InnerHashInputs;

  context->current_nbIn = 0;
  context->current_nbOut = 0;
  context->lock_time = msg->lock_time;
  context->nbIn = msg->inputs_count;
  context->nbOut = msg->outputs_count;
  sha256_Init(&context->sha256_ctx);
  memcpy(context->tx_hash, msg->tx_hash, 65 * sizeof(char));
  context->version = msg->version;
  context->has_innerHash = false;
  context->requestIndex = 1;

  // Init Inputs head on sha256
  TxSignCtx_AddSizePrefix(context, msg->inputs_count);

  // Build response TxRequest
  resp->has_details = true;
  resp->details.has_request_index = true;
  resp->details.request_index = 1;
  memcpy(resp->details.tx_hash, msg->tx_hash, 65 * sizeof(char));
  resp->request_type = TxRequest_RequestType_TXINPUT;

  return ErrOk;
}
