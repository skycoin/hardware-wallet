#ifndef HW_FSM_ETH_H
#define HW_FSM_ETH_H

#include "skycoin-crypto/eth_constants.h"
#include "skycoin-crypto/eth_crypto.h"

#include "tiny-firmware/protob/c/messages.pb.h"
#include "tiny-firmware/protob/c/ethereum_messages.pb.h"

void fsm_msgEthereumAddress(EthereumAddress *msg);

void fsm_msgEthereumTxAck(EthereumTxAck *ethereumTxAck);

#endif //HW_FSM_ETH_H
