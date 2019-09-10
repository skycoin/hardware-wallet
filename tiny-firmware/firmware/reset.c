/*
 * This file is part of the Skycoin project, https://skycoin.net/ 
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "tiny-firmware/firmware/reset.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/rng.h"
#include "skycoin-crypto/tools/sha2.h"
#include "tiny-firmware/firmware/fsm.h"
#include "types.pb.h"
#include "tiny-firmware/firmware/protect.h"
#include "skycoin-crypto/tools/bip39.h"
#include "tiny-firmware/util.h"
#include "tiny-firmware/firmware/gettext.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/firmware/messages.h"

uint32_t strength;
uint8_t int_entropy[32] = {0};
bool skip_backup = false;

void reset_init(bool display_random, uint32_t _strength, bool passphrase_protection, bool pin_protection, const char* language, const char* label, bool _skip_backup)
{
    reset_init_ex(display_random, _strength, passphrase_protection, pin_protection, language, label, _skip_backup, NULL);
}

void reset_init_ex(bool display_random, uint32_t _strength, bool passphrase_protection, bool pin_protection, const char* language, const char* label, bool _skip_backup, const char* (*funcRequestPin)(PinMatrixRequestType, const char*))
{
    if (funcRequestPin == NULL) {
        funcRequestPin = requestPin;
    }

    if (_strength != 128 && _strength != 192 && _strength != 256) {
        return;
    }

    strength = _strength;
    skip_backup = _skip_backup;

    random_salted_buffer(int_entropy, 32);

    if (display_random) {
        char ent_str[4][17];
        data2hex(int_entropy, 8, ent_str[0]);
        data2hex(int_entropy + 8, 8, ent_str[1]);
        data2hex(int_entropy + 16, 8, ent_str[2]);
        data2hex(int_entropy + 24, 8, ent_str[3]);

        layoutDialogSwipe(&bmp_icon_info, _("Cancel"), _("Continue"), NULL, _("Internal entropy:"), ent_str[0], ent_str[1], ent_str[2], ent_str[3], NULL);
        if (!protectButton(ButtonRequestType_ButtonRequest_ResetDevice, false)) {
            fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, 0);
            layoutHome();
            return;
        }
    }

    if (pin_protection && !protectChangePinEx(funcRequestPin)) {
        fsm_sendFailure(FailureType_Failure_PinMismatch, NULL, 0);
        layoutHome();
        return;
    }

    storage_setPassphraseProtection(passphrase_protection);
    storage_setLanguage(language);
    if (label != NULL && strcmp("", label) != 0) {
        storage_setLabel(label);
    }
    storage_update();

    EntropyRequest resp;
    memset(&resp, 0, sizeof(EntropyRequest));
    msg_write(MessageType_MessageType_EntropyRequest, &resp);
}

ErrCode_t reset_entropy(void)
{
    storage_setNeedsBackup(true);
    const char* mnemonic = mnemonic_from_data(int_entropy, strength / 8);
    if (!mnemonic_check(mnemonic)) {
        return ErrInvalidValue;
    }
    storage_setMnemonic(mnemonic);
    memset(int_entropy, 0, sizeof(int_entropy));

    if (skip_backup) {
        storage_update();
    } else {
        reset_backup(false);
    }
    return ErrOk;
}

static char current_word[10];

ErrCode_t reset_backup(bool separated)
{
    if (!storage_needsBackup()) {
        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Seed already backed up"), 0);
        return ErrUnexpectedMessage;
    }

    storage_setUnfinishedBackup(true);

    if (separated) {
        storage_update();
    }

    const char* mnemonic = storage_getMnemonic();

    for (int pass = 0; pass < 2; pass++) {
        int i = 0, word_pos = 1;
        while (mnemonic[i] != 0) {
            // copy current_word
            int j = 0;
            while (mnemonic[i] != ' ' && mnemonic[i] != 0 && j + 1 < (int)sizeof(current_word)) {
                current_word[j] = mnemonic[i];
                i++;
                j++;
            }
            current_word[j] = 0;
            if (mnemonic[i] != 0) {
                i++;
            }
            layoutResetWord(current_word, pass, word_pos, mnemonic[i] == 0);
            if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmWord, true)) {
                if (!separated) {
                    storage_clear_update();
                    session_clear(true);
                }
                layoutHome();
                fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL, 0);
                return ErrActionCancelled;
            }
            word_pos++;
        }
    }

    storage_setUnfinishedBackup(false);

    if (!separated) {
        storage_update();
        fsm_sendSuccess(_("Device successfully initialized"), 0);
    }
    layoutHome();
    return ErrOk;
}

#if DEBUG_LINK

uint32_t reset_get_int_entropy(uint8_t* entropy)
{
    memcpy(entropy, int_entropy, 32);
    return 32;
}

const char* reset_get_word(void)
{
    return current_word;
}

#endif
