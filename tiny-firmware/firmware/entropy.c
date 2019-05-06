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

uint8_t entropy_mixer_prev_val[SHA256_DIGEST_LENGTH] = {0};

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
    random_buffer(rndbuf, sizeof(rndbuf));
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
    random_buffer((uint8_t*)&salt_ticker, sizeof(salt_ticker));
#endif // EMULATOR
    entropy_mix_256((uint8_t*)&salt_ticker, sizeof(salt_ticker), NULL);

    // Salt source : TRNG 32 bits
    uint32_t salt_trng = random32();
    entropy_mix_256((uint8_t*)&salt_trng, sizeof(salt_trng), NULL);
    if (in != NULL) {
        entropy_mix_256(in, in_len, buf);
    }
}

void entropy_mix_256(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy)
{
    uint8_t val1[SHA256_DIGEST_LENGTH] = {0};
    compute_sha256sum(in, val1, in_len);
    uint8_t val2[SHA256_DIGEST_LENGTH] = {0};
    add_sha256(
        val1, sizeof(val1),
        entropy_mixer_prev_val, sizeof(entropy_mixer_prev_val),
        val2);
    uint8_t val3[SHA256_DIGEST_LENGTH] = {0};
    add_sha256(val1, sizeof(val1), val2, sizeof(val2), val3);
    memset(val1, 0, sizeof(val1));
    memcpy(entropy_mixer_prev_val, val3, sizeof(entropy_mixer_prev_val));
    memset(val3, 0, sizeof(val1));
    if (out_mixed_entropy != NULL) {
        memcpy(out_mixed_entropy, val2, SHA256_DIGEST_LENGTH);
    }
    memset(val2, 0, sizeof(val1));
}

void entropy_mix_n(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy)
{
    uint8_t* iptr = (uint8_t*)in;
    uint8_t* optr;
    size_t i;
    for (i = in_len, optr = out_mixed_entropy;
         i >= SHA256_DIGEST_LENGTH;
         i -= SHA256_DIGEST_LENGTH, iptr += SHA256_DIGEST_LENGTH, optr += SHA256_DIGEST_LENGTH) {
        entropy_mix_256(iptr, SHA256_DIGEST_LENGTH, optr);
    }
    if (i > 0) {
        uint8_t tmp[SHA256_DIGEST_LENGTH] = {0};
        entropy_mix_256(iptr, i, tmp);
        memcpy(optr, &tmp, i);
        memset(&tmp, 0, sizeof(tmp));
    }
    iptr = optr = NULL;
}

void __attribute__((weak)) random_salted_buffer(uint8_t* buf, size_t len)
{
    random_buffer(buf, len);

    uint8_t tmp[SHA256_DIGEST_LENGTH] = {0};
    uint8_t *bptr, *tptr;
    size_t i, j;
    for (i = len, bptr = buf; i >= SHA256_DIGEST_LENGTH; i -= SHA256_DIGEST_LENGTH) {
        entropy_mix_256(bptr, SHA256_DIGEST_LENGTH, tmp);
        for (j = SHA256_DIGEST_LENGTH, tptr = tmp; j; --j, ++tptr, ++bptr) {
            // FIXME: XOR the whole architecture-specific word
            *bptr = *bptr ^ *tptr;
        }
    }
    if (i > 0) {
        entropy_mix_256(bptr, i, tmp);
        for (tptr = tmp; i; --i, ++tptr, ++bptr) {
            // FIXME: XOR the whole architecture-specific word
            *bptr = *bptr ^ *tptr;
        }
    }
    memset(&tmp, 0, sizeof(tmp));
    bptr = tptr = NULL;
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
