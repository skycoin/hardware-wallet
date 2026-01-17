#include "skycoin-crypto/tools/bip32.h"

#define MAX_MNEMONIC_LEN 240

int fsm_getBitcoinBIP39_Seed(uint8_t seed[]);
HDNode* fsm_getDerivedNode(const char *curve, const int coinType);
