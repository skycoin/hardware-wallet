

#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/usb.h"
#include "skycoin-crypto/tools/bip39.h"
#include "skycoin-crypto/tools/bip44_coins.h"
#include "skycoin-crypto/tools/memzero.h"
#include "tiny-firmware/firmware/hd_wallet.h"

static void get_root_node_callback(uint32_t iter, uint32_t total) {
  usbSleep(1);
  layoutProgress("Waking up", 1000 * iter / total);
}

int fsm_getBitcoinBIP39_Seed(uint8_t seed[]){

     char mnemonic[MAX_MNEMONIC_LEN + 1];
     const char *mnemo = storage_getFullSeed();

     strcpy(mnemonic, mnemo);

     if(!mnemonic_check(mnemonic)){
       return 1;
     }

     char oldTiny = usbTiny(1);
     mnemonic_to_seed(mnemonic, "", seed, get_root_node_callback);
     memzero(mnemonic, sizeof(mnemonic));
     usbTiny(oldTiny);

     return 0;
}

HDNode* fsm_getDerivedNode(const char *curve, const int coinType){

  static CONFIDENTIAL HDNode node;
  static uint8_t CONFIDENTIAL BIP39Seed[256];

  fsm_getBitcoinBIP39_Seed(BIP39Seed);

  // Chain m
  hdnode_from_seed(BIP39Seed, 64, curve, &node);

  // if (!address_n || address_n_count == 0) {
  //   return &node;
  // }

  // Chain m/44'
  if(hdnode_private_ckd_prime(&node, 44) == 0){
    return 0;
  }

  // Chain m/44'/0'
  if(hdnode_private_ckd_prime(&node, coinType) == 0){
    return 0;
  }

  // Chain m/44'/0'/0'
  if (hdnode_private_ckd_prime(&node, 0) == 0){

      return 0;
  }

  // Chain m/44'/0'/0'/0
  if (hdnode_private_ckd(&node, 0) == 0){

      return 0;
  }

  return &node;
}
