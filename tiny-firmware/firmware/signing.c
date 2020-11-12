#include "skycoin-crypto/skycoin_crypto.h"
#include "skycoin-crypto/bitcoin_constants.h"
#include "skycoin-crypto/tools/sha2.h"
#include "skycoin-crypto/tools/base58.h"
#include "skycoin-crypto/tools/hasher.h"

#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/signing.h"

#include <stdio.h>

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

ErrCode_t signBTC_tx(SignTx* msg, TxRequest* resp){
  BTC_Transaction *btc_tx = BTC_Transaction_Get();
  if(btc_tx->state != Destroyed){
    BTC_Transaction_Destroy(btc_tx);
    return ErrFailed;
  }

  // Init TxSignContext
  btc_tx = BTC_Transaction_Init();
  if (btc_tx->mnemonic_change) {
      BTC_Transaction_Destroy(btc_tx);
      return ErrFailed;
  }
  btc_tx->state = BTC_Outputs;

  btc_tx->current_nbIn = 0;
  btc_tx->current_nbOut = 0;
  btc_tx->lock_time = msg->lock_time;
  btc_tx->nbIn = msg->inputs_count;
  btc_tx->nbOut = msg->outputs_count;
  hasher_Init(&(btc_tx->hasher), HASHER_SHA2D);
  //memcpy(btc_tx->tx_hash, msg->tx_hash, 65 * sizeof(char));
  btc_tx->version = msg->version;
  btc_tx->sequence = SEQUENCE;
  btc_tx->sigHash = 1;
  btc_tx->requestIndex = 1;

  // Build response TxRequest
  resp->has_details = true;
  resp->details.has_request_index = true;
  resp->details.request_index = 1;
  memcpy(resp->details.tx_hash, msg->tx_hash, 65 * sizeof(char));

  resp->request_type = TxRequest_RequestType_TXOUTPUT;

  return ErrOk;
}

ErrCode_t getPubKey(uint8_t* seckey, uint8_t* pubkey, uint8_t address_n){
  ErrCode_t res = fsm_getKeyPairAtIndex(1, pubkey, seckey,
                                        NULL, address_n, &bitcoin_address_from_pubkey);

  if (res != ErrOk){
    return res;
  }

  return ErrOk;
}

ErrCode_t set_prev_outputs_script(BTC_Transaction* btc_tx){
  uint8_t seckey[BITCOIN_SECKEY_LEN] = {0};
  char address[36] = {""};
  uint8_t addrhex[25] = {0};
  size_t sz = sizeof(addrhex);
  size_t addresslen = 36;

  for(uint8_t i = 0; i < btc_tx->nbIn; ++i){

    ErrCode_t res = getPubKey(seckey, btc_tx->inputs[i].pubkey, btc_tx->inputs[i].address_n);
    if (res != ErrOk) {
        return res;
    }

    if (!bitcoin_address_from_pubkey(btc_tx->inputs[i].pubkey, address, &addresslen)) {
        return ErrFailed;
    }

    b58tobin(addrhex, &sz, address);

    compile_locking_script(addrhex, btc_tx->inputs[i].sigScript);

  }

  return ErrOk;
}

size_t compile_btc_tx_hash(BTC_Transaction* btc_tx, BitcoinTransactionInput* inputs, uint8_t* hash, bool final_hash){

  size_t cursor = 0;

  //set version
  for(size_t i = 0; i < VERSION_LENGTH; i++){
    hash[cursor] = (btc_tx->version >> i * 8);
    cursor = cursor + 1;
  }

  //set number of inputs
  hash[cursor] = btc_tx->nbIn;
  cursor = cursor + 1;

  //set each input
  for(uint32_t i = 0; i < btc_tx->nbIn; i++){

    //set previous tx_id in little endian format (reverse)
    for(size_t k = 0; k < TXID_LENGTH; k++){
      hash[cursor + k] = inputs[i].prev_hash.bytes[TXID_LENGTH - 1 - k];
    }
    cursor = cursor + TXID_LENGTH;

    //set input index
    for(size_t k = 0; k < VERSION_LENGTH; k++){
      hash[cursor] = (btc_tx->inputs[i].prev_index >> k * 8);
      cursor = cursor + 1;
    }

    //set script length
    hash[cursor] = SCRIPT_LENGTH;
    cursor = cursor + 1;

    //set temporary unlocking script
    if(final_hash == false){
      memcpy(hash + cursor, btc_tx->inputs[i].sigScript, SCRIPT_LENGTH);
      cursor = cursor + SCRIPT_LENGTH;
    }else{
      memcpy(hash + cursor, btc_tx->inputs[i].unlockScript, 109);
      cursor = cursor + 109;
    }

    //set sequence
    for(size_t k = 0; k < VERSION_LENGTH; k++){
      hash[cursor] = (btc_tx->sequence >> k * 8);
      cursor = cursor + 1;
    }

  }

  //set number of outputs
  hash[cursor] = btc_tx->nbOut;
  cursor = cursor + 1;

  //set each output
  for(uint32_t i = 0; i < btc_tx->nbOut; i++){

    //set value
    for(size_t k = 0; k < 8; k++){
      hash[cursor] = (btc_tx->outputs[i].amount >> k * 8);
      cursor = cursor + 1;
    }

    //set script length
    hash[cursor] = SCRIPT_LENGTH;
    cursor = cursor + 1;

    //set locking script
    memcpy(hash + cursor, btc_tx->outputs[i].lockScript, SCRIPT_LENGTH);
    for(size_t k = cursor; k < cursor + SCRIPT_LENGTH; k++){
    }
    cursor = cursor + SCRIPT_LENGTH;

  }

  //set locktime
  for(size_t k = 0; k < VERSION_LENGTH; k++){
    hash[cursor] = (btc_tx->lock_time >> k * 8);
    cursor = cursor + 1;
  }

  //set SIGHASH_ALL flag
  for(size_t k = 0; k < VERSION_LENGTH; k++){
  hash[cursor] = (btc_tx->sigHash >> k * 8);
    cursor = cursor + 1;
  }

  return cursor;
}
