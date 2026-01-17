#include "messages.pb.h"
#include "bitcoin_messages.pb.h"
#include "skycoin-crypto/bitcoin_crypto.h"
#include "tiny-firmware/firmware/error.h"

#define VERSION_LENGTH 4
#define TXID_LENGTH 32
#define SCRIPT_LENGTH 25
#define SEQUENCE_LENGTH 4
#define LOCKTIME_LENGTH 4
#define SEQUENCE 0xffffffff

ErrCode_t get_pubkeyhash(uint8_t* pubkeyhash, uint8_t address_n);

void BTC_TxAddPrefix(Hasher* hasher, uint32_t version);

void BTC_TxUpdateInput(Hasher* hasher, BitcoinTransactionInput* inputs,
                        uint8_t* pubkeyhash, size_t i);

void BTC_TxUpdateOutput(Hasher* hasher, BitcoinTransactionOutput* outputs,
                        uint8_t* pubkeyhash, size_t i);
