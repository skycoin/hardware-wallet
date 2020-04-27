#include "fsm_eth.h"

#include <stdio.h>
#include <inttypes.h>

#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/firmware/messages.h"
#include "tiny-firmware/firmware/protect.h"
#include "tiny-firmware/firmware/gettext.h"

#include "tiny-firmware/firmware/fsm.h"
#include "tiny-firmware/firmware/fsm_impl.h"
#include "tiny-firmware/firmware/fsm_eth_impl.h"

#include "tiny-firmware/vendor/skycoin-crypto/skycoin_crypto.h"
#include "skycoin-crypto/eth_constants.h"

extern uint8_t msg_resp[MSG_OUT_SIZE] __attribute__((aligned));

void fsm_msgEthereumAddress(EthereumAddress *msg) {
    MessageType msgtype = MessageType_MessageType_SkycoinAddress;
    RESP_INIT(ResponseEthereumAddress);
    char *failMsg = NULL;
    ErrCode_t err = msgEthereumAddressImpl(msg, resp);
    switch (err) {
        case ErrUserConfirmation: {
            char address_hex[2 + ETH_ADDR_LEN * 2 + 1];
            tohex(address_hex, resp->addresses[0].bytes, ETH_ADDR_LEN);
            layoutAddress(address_hex);
            if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
                err = ErrActionCancelled;
                break;
            }
        } // fall through
        case ErrOk:
            msg_write(MessageType_MessageType_ResponseSkycoinAddress, resp);
            layoutHome();
            return;
        case ErrPinRequired:
            failMsg = _("Expected pin");
            break;
        case ErrTooManyAddresses:
            failMsg = _("Asking for too much addresses");
            break;
        case ErrMnemonicRequired:
            failMsg = _("Mnemonic required");
            break;
        case ErrAddressGeneration:
            failMsg = _("Key pair generation failed");
            break;
        default:
            break;
    }
    fsm_sendResponseFromErrCode(err, NULL, failMsg, &msgtype);
    layoutHome();
}

void fsm_msgEthereumTxAck(EthereumTxAck *msg) {
    if (checkPin() || checkMnemonic()) {
        return;
    }

    MessageType msgType = MessageType_MessageType_EthereumTxAck;
    RESP_INIT(TxRequest);
    ErrCode_t err = msgEthereumTxAckImpl(msg, resp);
    switch (err) {
        case ErrOk:
            msg_write(MessageType_MessageType_TxRequest, resp);
            break;
        case ErrInvalidArg:
            fsm_sendFailure(FailureType_Failure_DataError, _("Invalid data on TxAck message."), &msgType);
            break;
        case ErrActionCancelled:
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, &msgType);
            break;
        case ErrFailed:
            fsm_sendFailure(FailureType_Failure_ProcessError, NULL, &msgType);
            break;
        default:
            fsm_sendFailure(FailureType_Failure_ProcessError, _("Signing transaction failed."), &msgType);
            break;
    }
    layoutHome();
    return;
}
