#ifndef HW_FSM_ETH_IMPL_H
#define HW_FSM_ETH_IMPL_H

#include "tiny-firmware/firmware/error.h"
#include "tiny-firmware/protob/c/messages.pb.h"
#include "tiny-firmware/protob/c/ethereum_messages.pb.h"

ErrCode_t msgEthereumAddressImpl(EthereumAddress *msg, ResponseEthereumAddress *resp);

#endif //HW_FSM_ETH_IMPL_H
