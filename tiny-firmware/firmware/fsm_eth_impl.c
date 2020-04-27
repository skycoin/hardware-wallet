#include "fsm_eth_impl.h"

#include <inttypes.h>

#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/firmware/protect.h"

#include "skycoin-crypto/eth_crypto.h"
#include "skycoin-crypto/eth_constants.h"

ErrCode_t msgEthereumAddressImpl(EthereumAddress *msg, ResponseEthereumAddress *resp) {
    uint8_t seckey[ETH_PRIVKEY_LEN] = {0};
    uint8_t pubkey[ETH_PUBKEY_LEN] = {0};
    uint32_t start_index = !msg->has_start_index ? 0 : msg->start_index;
    if (!protectPin(true)) {
        return ErrPinRequired;
    }
    if (msg->address_n > 99) {
        return ErrTooManyAddresses;
    }

    if (storage_hasMnemonic() == false) {
        return ErrMnemonicRequired;
    }

    if (fsm_getKeyPairAtIndex(msg->address_n, pubkey, seckey, resp, addEthereumAddress,
                              start_index, &eth_address_from_pubkey, false) != ErrOk) {
        return ErrAddressGeneration;
    }
    if (msg->address_n == 1 && msg->has_confirm_address && msg->confirm_address) {
        return ErrUserConfirmation;
    }
    return ErrOk;
}

