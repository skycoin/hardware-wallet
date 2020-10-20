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


ErrCode_t sign_tx(SignTx* msg, TxRequest* resp);

ErrCode_t signBTC_tx(SignTx* msg, TxRequest* resp);

ErrCode_t set_prev_outputs_script(BTC_Transaction* btc_tx);

size_t compile_btc_tx_hash(BTC_Transaction* btc_tx, BitcoinTransactionInput* inputs);
