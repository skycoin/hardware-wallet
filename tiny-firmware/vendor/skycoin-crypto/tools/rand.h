/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c)      2019 Skycoin Developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __RAND_H__
#define __RAND_H__

#include <stdint.h>
#include <stdlib.h>

/**
 * @brief base (system) random number generator
 * @return unsigned 32-bits integer
 */
uint32_t _random32(void);

/**
 * @brief generate random buffer using base (system) random generator
 * @param len number of random bytes that need to be generated
 * @param buf pointer to memory buffer
 */
void _random_buffer(uint8_t* buf, size_t len);

/**
 * @brief salted random number generator
 * @return unsigned 32-bits integer
 * @attention values returned by this function are salted with the accumulated state of the entropy pool
 */
uint32_t random32(void);

/**
 * @brief random number generator with uniform distribution in [0 .. n) interval
 * @param n interval boundary
 * @return unsigned 32-bit integer
 * @attention values returned by this function are salted with the accumulated state of the entropy pool
 */
uint32_t random_uniform(uint32_t n);

/**
 * @brief populate buffer with random bytes
 * @param buf memory buffer pointer
 * @param len number of bytes in input buffer
 * @attention values returned by this function are salted with the accumulated state of the entropy pool
 */
void random_buffer(uint8_t* buf, size_t len);

/**
 * @brief inplace permutation of buffer (byte) items
 * @param buf memory buffer pointer
 * @param len number of bytes in input buffer
 * @attention values returned by this function are salted with the accumulated state of the entropy pool
 */
void random_permute(char* buf, size_t len);

#endif
