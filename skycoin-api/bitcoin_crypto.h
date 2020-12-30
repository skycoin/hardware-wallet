#ifndef BITCOIN_CRYPTO_H
#define BITCOIN_CRYPTO_H

#include "tools/sha2.h"
#include "tools/hasher.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "skycoin_crypto.h"

typedef struct BTC_TxInput {
  uint32_t address_n;
  uint32_t prev_hash;
  uint32_t prev_index;
  uint8_t pubkey[33];
  uint8_t script_len;
  uint8_t unlockScript[109];
  uint8_t sigScript[25];
  uint32_t value;
} BTC_TxInput;

typedef struct BTC_TxOutput {
  uint8_t address[25];
  uint64_t amount;
  uint32_t fee;
  bool has_change_address;
  uint32_t change_address_n;
  uint8_t lockScript[25];
} BTC_TxOutput;

typedef struct BTC_Transaction {
  bool mnemonic_change;
  TxSignState state;
  Hasher hasher;

  uint32_t version;
  uint32_t current_nbIn;
  uint8_t nbIn;
  BTC_TxInput inputs[8];

  uint32_t sequence;
  uint8_t nbOut;
  uint32_t current_nbOut;

  BTC_TxOutput outputs[8];
  uint32_t lock_time;

  uint32_t sigHash;

  uint8_t tx_hash[256];
  uint64_t requestIndex;
} BTC_Transaction;

int bitcoin_address_from_pubkey(const uint8_t* pubkey, char* b58address, size_t* size_b58address);

int bitcoin_ecdsa_sign_digest(const uint8_t* priv_key, const uint8_t* digest, uint8_t* sig);

int compile_locking_script(uint8_t* b58_addr, uint8_t* pubkeyhash);

int compile_unlocking_script(const uint8_t* signature, int siglen, uint8_t* pubkey, uint8_t* script);

BTC_Transaction* BTC_Transaction_Init(void);

BTC_Transaction* BTC_Transaction_Get(void);

void BTC_Transaction_Destroy(BTC_Transaction*);

#endif
