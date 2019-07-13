/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "entropy.h"

#include <string.h>

#if !EMULATOR

#include "gpio_noise.h"

#endif // EMULATOR

#include "firmware/storage.h"
#include "firmware/swtimer.h"
#include "messages.h"
#include "messages.pb.h"
#include "oled.h"
#include "protob/c/messages.pb.h"
#include "rng.h"
#include "skycoin_crypto.h"
#include "timer.h"
#include "vendor/skycoin-crypto/tools/entropypool.h"
#include "vendor/skycoin-crypto/tools/sha2.h"

#define EXTERNAL_ENTROPY_TIMEOUT 60000
#define ENTROPY_RANDOMSALT_SIZE 256

static SWTIMER entropy_timeout = INVALID_TIMER;

ErrCode_t is_external_entropy_needed(void)
{
    // Request for external entropy after 60000 clock ticks ellapsed
    if (stopwatch_counter(entropy_timeout)) {
        return ErrEntropyNotNeeded;
    }
    return ErrEntropyRequired;
}

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

/**
 * Salted entropy sources
 *
 * Type 0 - Constant values
 * - MCU core registers (PC, SP, LR)
 *
 * Type 1 - variable between devices
 * - device UUID
 *
 * Type 2 - variable between device runs (at init time)
 * - RTC
 * - stopwatch counter based on SysTick timer
 *
 * Type 3 - variable over time (after init, value continues to change)
 * - RTC
 * - random buffer (TRNG)
 * - stopwatch counter based on SysTick timer
 * - unconnected GPIO pin
 *
 */

void reset_entropy_mix_256(void)
{
    if (entropy_timeout == INVALID_TIMER) {
        entropy_timeout = stopwatch_start(EXTERNAL_ENTROPY_TIMEOUT);
    }
    // Salt source: 96-bits device UID
    // FIXME : Read STM32_UUID instead
    entropy_mix_256((uint8_t*)storage_uuid_str, sizeof(storage_uuid_str), NULL);
#if !EMULATOR
    // Salt source : MCU core registers
    uint32_t salt_mcu[3] = {0};
    uint32_t rval;
    // FIXME LR is not likely to change neither over time nor across MCU devices
    __asm__ __volatile__("mov %0, lr"
                         : "=r"(rval));
    salt_mcu[0] = rval;
    // FIXME PC is not likely to change neither over time nor across MCU devices
    __asm__ __volatile__("mov %0, pc"
                         : "=r"(rval));
    salt_mcu[1] = rval;
    // FIXME SP is not likely to change neither over time nor across MCU devices
    __asm__ __volatile__("mov %0, sp"
                         : "=r"(rval));
    salt_mcu[2] = rval;
    entropy_mix_256((uint8_t*)salt_mcu, sizeof(salt_mcu), NULL);
#endif
    // Salt source : Random buffer
    uint8_t rndbuf[ENTROPY_RANDOMSALT_SIZE];
    _random_buffer(rndbuf, sizeof(rndbuf));
    entropy_mix_256(rndbuf, sizeof(rndbuf), NULL);
    // Mix type 3 salt sources
    entropy_salt_mix_256(NULL, 0, NULL);
}

void entropy_salt_mix_256(uint8_t* in, size_t in_len, uint8_t* buf)
{
    if (entropy_timeout == INVALID_TIMER) {
        return;
    }
    // Salt source : System clock timer
    uint64_t salt_ticker = 0;
#if !EMULATOR
    // Salt source : disconnected gpio (current noise)
    uint16_t salt_gpio = read_gpio_noise(2, 2); /// Read from GPIOB : GPIO2
    entropy_mix_256((uint8_t*)&salt_gpio, sizeof(salt_gpio), NULL);

    // Salt source : Systick timer
    salt_ticker = timer_ms();
#else
    // Salt source : Simulate SysTick timer with random number
    _random_buffer((uint8_t*)&salt_ticker, sizeof(salt_ticker));
#endif // EMULATOR
    entropy_mix_256((uint8_t*)&salt_ticker, sizeof(salt_ticker), NULL);

    // Salt source : TRNG 32 bits
    uint32_t salt_trng = _random32();
    entropy_mix_256((uint8_t*)&salt_trng, sizeof(salt_trng), NULL);
    if (in != NULL) {
        entropy_mix_256(in, in_len, buf);
    }
}

void set_external_entropy(uint8_t* entropy, size_t len)
{
    stopwatch_reset(entropy_timeout);
    entropy_salt_mix_256(entropy, len, NULL);
}

void check_entropy(void)
{
#if !EMULATOR
    EntropyRequest entropy_request;

    if (is_external_entropy_needed() == ErrEntropyRequired) {
        memset((void*)&entropy_request, 0, sizeof(EntropyRequest));
        msg_write(MessageType_MessageType_EntropyRequest, &entropy_request);
        stopwatch_reset(entropy_timeout);
    }
#endif
}
